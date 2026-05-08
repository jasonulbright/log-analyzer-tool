Describe 'Compress-LogEntries' {

    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..\Module\LogAnalyzerCommon.psd1') -Force

        function New-FakeEntry {
            param(
                [string]$Message,
                [datetime]$DateTime = (Get-Date '2026-03-04 14:10:00'),
                [string]$Component = 'LocationServices',
                [string]$Severity = 'Error',
                [int]$Type = 3,
                [string]$LogFile = 'LocationServices.log',
                $ErrorCode = $null,
                $ErrorTranslation = $null
            )
            [pscustomobject]@{
                Message          = $Message
                DateTime         = $DateTime
                Component        = $Component
                Context          = ''
                Type             = $Type
                Severity         = $Severity
                Thread           = '1'
                LogFile          = $LogFile
                LineNumber       = 1
                ErrorCode        = $ErrorCode
                ErrorTranslation = $ErrorTranslation
                AllErrorCodes    = @()
                AllTranslations  = @()
            }
        }
    }

    Context 'Pass-through cases' {

        It 'Returns empty array for empty input' {
            $result = @(Compress-LogEntries -Entries @())
            $result.Count | Should -Be 0
        }

        It 'Returns single entry unchanged with RepeatCount 1' {
            $entry = New-FakeEntry -Message 'Something broke'
            $result = @(Compress-LogEntries -Entries @($entry))
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 1
            $result[0].RepeatSpan | Should -BeNullOrEmpty
        }

        It 'Does not collapse entries with different messages' {
            $entries = @(
                New-FakeEntry -Message 'Error A' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Error B' -DateTime (Get-Date '2026-03-04 14:10:01')
                New-FakeEntry -Message 'Error C' -DateTime (Get-Date '2026-03-04 14:10:02')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 3
            $result | ForEach-Object { $_.RepeatCount | Should -Be 1 }
        }

        It 'Does not collapse entries with same message but different components' {
            $entries = @(
                New-FakeEntry -Message 'Failed to connect' -Component 'CAS'
                New-FakeEntry -Message 'Failed to connect' -Component 'LocationServices'
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 2
        }

        It 'Does not collapse entries with same message but different severity' {
            $entries = @(
                New-FakeEntry -Message 'Connection timeout' -Severity 'Warning' -Type 2
                New-FakeEntry -Message 'Connection timeout' -Severity 'Error' -Type 3
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 2
        }
    }

    Context 'Basic collapse' {

        It 'Collapses 3 identical consecutive messages into 1' {
            $entries = @(
                New-FakeEntry -Message 'Failed to get DP locations' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Failed to get DP locations' -DateTime (Get-Date '2026-03-04 14:10:05')
                New-FakeEntry -Message 'Failed to get DP locations' -DateTime (Get-Date '2026-03-04 14:10:10')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 3
            $result[0].RepeatSpan | Should -Be '14:10:00 - 14:10:10'
            $result[0].Message | Should -Be 'Failed to get DP locations'
        }

        It 'Sets RepeatSpan to single time when all timestamps identical' {
            $sameTime = Get-Date '2026-03-04 14:10:00'
            $entries = @(
                New-FakeEntry -Message 'Waiting for policy' -DateTime $sameTime
                New-FakeEntry -Message 'Waiting for policy' -DateTime $sameTime
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatSpan | Should -Be '14:10:00'
        }

        It 'Preserves first entry properties (DateTime, ErrorCode, etc.)' {
            $entries = @(
                New-FakeEntry -Message 'Error 0x80070005' -DateTime (Get-Date '2026-03-04 14:10:00') -ErrorCode '0x80070005'
                New-FakeEntry -Message 'Error 0x80070005' -DateTime (Get-Date '2026-03-04 14:10:30') -ErrorCode '0x80070005'
                New-FakeEntry -Message 'Error 0x80070005' -DateTime (Get-Date '2026-03-04 14:11:00') -ErrorCode '0x80070005'
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result[0].DateTime | Should -Be (Get-Date '2026-03-04 14:10:00')
            $result[0].ErrorCode | Should -Be '0x80070005'
        }
    }

    Context 'Normalization - messages differing only in variable data collapse together' {

        It 'Normalizes GUIDs' {
            $entries = @(
                New-FakeEntry -Message 'App {12345678-1234-1234-1234-123456789ABC} failed' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'App {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE} failed' -DateTime (Get-Date '2026-03-04 14:10:01')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 2
        }

        It 'Normalizes IP addresses' {
            $entries = @(
                New-FakeEntry -Message 'Failed to resolve DP 10.0.1.4' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Failed to resolve DP 10.0.1.9' -DateTime (Get-Date '2026-03-04 14:10:01')
                New-FakeEntry -Message 'Failed to resolve DP 192.168.1.100' -DateTime (Get-Date '2026-03-04 14:10:02')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 3
        }

        It 'Normalizes hex values' {
            $entries = @(
                New-FakeEntry -Message 'Error code 0x80070005 in handler' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Error code 0x80004005 in handler' -DateTime (Get-Date '2026-03-04 14:10:01')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 2
        }

        It 'Normalizes UNC paths' {
            $entries = @(
                New-FakeEntry -Message 'Cannot access \\SERVER01\SMSPKGD$\Package1' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Cannot access \\SERVER02\SMSPKGD$\Package2' -DateTime (Get-Date '2026-03-04 14:10:01')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 2
        }

        It 'Normalizes local paths' {
            $entries = @(
                New-FakeEntry -Message 'File not found: C:\Windows\CCM\Logs\foo.log' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'File not found: C:\Windows\CCM\Logs\bar.log' -DateTime (Get-Date '2026-03-04 14:10:01')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 2
        }

        It 'Normalizes standalone multi-digit numbers' {
            $entries = @(
                New-FakeEntry -Message 'Retry attempt 10 of 50' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Retry attempt 20 of 50' -DateTime (Get-Date '2026-03-04 14:10:01')
                New-FakeEntry -Message 'Retry attempt 30 of 50' -DateTime (Get-Date '2026-03-04 14:10:02')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 3
        }
    }

    Context 'Interleaved sequences stay separate' {

        It 'Creates separate collapsed groups when interrupted by a different message' {
            $entries = @(
                New-FakeEntry -Message 'Waiting for policy' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Waiting for policy' -DateTime (Get-Date '2026-03-04 14:10:01')
                New-FakeEntry -Message 'Waiting for policy' -DateTime (Get-Date '2026-03-04 14:10:02')
                New-FakeEntry -Message 'Connection reset'   -DateTime (Get-Date '2026-03-04 14:10:03')
                New-FakeEntry -Message 'Waiting for policy' -DateTime (Get-Date '2026-03-04 14:10:04')
                New-FakeEntry -Message 'Waiting for policy' -DateTime (Get-Date '2026-03-04 14:10:05')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 3
            $result[0].RepeatCount | Should -Be 3
            $result[0].Message | Should -Be 'Waiting for policy'
            $result[1].RepeatCount | Should -Be 1
            $result[1].Message | Should -Be 'Connection reset'
            $result[2].RepeatCount | Should -Be 2
            $result[2].Message | Should -Be 'Waiting for policy'
        }
    }

    Context 'MinRepeatCount threshold' {

        It 'Collapses when count meets MinRepeatCount (default 2)' {
            $entries = @(
                New-FakeEntry -Message 'Duplicate line' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Duplicate line' -DateTime (Get-Date '2026-03-04 14:10:01')
            )
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 2
        }

        It 'Respects custom MinRepeatCount of 5' {
            $entries = @(
                New-FakeEntry -Message 'Repeated line' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Repeated line' -DateTime (Get-Date '2026-03-04 14:10:01')
                New-FakeEntry -Message 'Repeated line' -DateTime (Get-Date '2026-03-04 14:10:02')
            )
            # 3 repeats, but threshold is 5 - should NOT collapse
            $result = @(Compress-LogEntries -Entries $entries -MinRepeatCount 5)
            $result.Count | Should -Be 3
            $result | ForEach-Object { $_.RepeatCount | Should -Be 1 }
        }
    }

    Context 'Large volume simulation' {

        It 'Collapses 200 identical entries into 1' {
            $entries = @(1..200 | ForEach-Object {
                New-FakeEntry -Message 'PolicyEvaluator: waiting for policy' `
                    -DateTime (Get-Date '2026-03-04 14:10:00').AddSeconds($_) `
                    -Component 'PolicyAgent' -Severity 'Warning' -Type 2
            })
            $result = @(Compress-LogEntries -Entries $entries)
            $result.Count | Should -Be 1
            $result[0].RepeatCount | Should -Be 200
        }
    }
}
