# Pester tests for the internal Read-LATLogFileShared helper.
#
# Purpose: prove the helper can read a file while a concurrent writer
# holds it open with FileShare.ReadWrite -- which is exactly what the
# MECM SMS Agent Host does for the logs under C:\Windows\CCM\Logs. The
# previous [System.IO.File]::ReadAllText path opened with FileShare.Read
# and failed against those live logs over an SMB UNC path with
# "The process cannot access the file ... because it is being used by
# another process."
#
# The helper is internal (not exported from LogAnalyzerCommon.psd1) so
# tests reach it via InModuleScope.

Describe 'Read-LATLogFileShared (internal helper)' {

    BeforeAll {
        $script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
        Import-Module (Join-Path $script:RepoRoot 'Module\LogAnalyzerCommon.psd1') -Force -DisableNameChecking
    }

    Context 'Plain file (no concurrent writer)' {

        It 'returns the file contents as a single string' {
            $tmp = Join-Path $TestDrive 'plain.log'
            [IO.File]::WriteAllText($tmp, "line one`r`nline two`r`n")
            $result = InModuleScope LogAnalyzerCommon -Parameters @{ Path = $tmp } {
                param($Path)
                Read-LATLogFileShared -Path $Path
            }
            $result | Should -Match 'line one'
            $result | Should -Match 'line two'
        }

        It 'returns empty string for an empty file' {
            $tmp = Join-Path $TestDrive 'empty.log'
            [IO.File]::WriteAllText($tmp, '')
            $result = InModuleScope LogAnalyzerCommon -Parameters @{ Path = $tmp } {
                param($Path)
                Read-LATLogFileShared -Path $Path
            }
            $result | Should -Be ''
        }

        It 'throws when the path does not exist' {
            $missing = Join-Path $TestDrive 'does-not-exist.log'
            {
                InModuleScope LogAnalyzerCommon -Parameters @{ Path = $missing } {
                    param($Path)
                    Read-LATLogFileShared -Path $Path
                }
            } | Should -Throw
        }
    }

    Context 'Concurrent writer holds file open with FileShare.ReadWrite (CCM-agent simulation)' {
        # The SMS Agent Host opens CCM logs with FileAccess.Write +
        # FileShare.ReadWrite so CMTrace and similar can read them live.
        # [IO.File]::ReadAllText opens with FileShare.Read, which does
        # NOT include the writer's already-granted Write access -- hence
        # the "used by another process" error. The helper opens with
        # FileShare.ReadWrite and succeeds.

        It 'succeeds where [System.IO.File]::ReadAllText would fail' {
            $tmp = Join-Path $TestDrive 'live.log'
            [IO.File]::WriteAllText($tmp, 'initial content line')

            $writerFs = [IO.FileStream]::new(
                $tmp,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Write,
                [IO.FileShare]::ReadWrite
            )
            try {
                # Baseline: plain ReadAllText should throw because its
                # FileShare.Read does not cover the writer's Write access.
                # The exact IOException message is localized/platform-specific
                # ("being used by another process"); we assert only that it
                # throws so the test is stable across locales.
                { [IO.File]::ReadAllText($tmp) } | Should -Throw

                # Helper: opens with FileShare.ReadWrite, reads cleanly.
                $result = InModuleScope LogAnalyzerCommon -Parameters @{ Path = $tmp } {
                    param($Path)
                    Read-LATLogFileShared -Path $Path
                }
                $result | Should -Be 'initial content line'
            } finally {
                $writerFs.Dispose()
            }
        }

        It 'releases its own handle so a second read can run immediately' {
            $tmp = Join-Path $TestDrive 'release.log'
            [IO.File]::WriteAllText($tmp, 'hello')

            # Invoke twice in succession; second call must not be blocked
            # by a leaked handle from the first.
            $r1 = InModuleScope LogAnalyzerCommon -Parameters @{ Path = $tmp } {
                param($Path)
                Read-LATLogFileShared -Path $Path
            }
            $r2 = InModuleScope LogAnalyzerCommon -Parameters @{ Path = $tmp } {
                param($Path)
                Read-LATLogFileShared -Path $Path
            }
            $r1 | Should -Be 'hello'
            $r2 | Should -Be 'hello'

            # And the file can be deleted immediately -- proves no dangling handle.
            { Remove-Item -LiteralPath $tmp -Force -ErrorAction Stop } | Should -Not -Throw
        }
    }
}
