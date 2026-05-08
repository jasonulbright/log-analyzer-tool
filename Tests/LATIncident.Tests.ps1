Describe 'LATIncident (Session 7)' {

    BeforeAll {
        $script:RepoRoot     = Resolve-Path (Join-Path $PSScriptRoot '..')
        $script:EvaluatorPs  = Join-Path $script:RepoRoot 'Module\Invoke-RuleEvaluator.ps1'
        $script:IncidentPs   = Join-Path $script:RepoRoot 'Module\LATIncident.ps1'
        $script:ValidatorPs  = Join-Path $script:RepoRoot 'Module\Test-LATRule.ps1'
        . $script:ValidatorPs
        . $script:EvaluatorPs
        . $script:IncidentPs

        function New-FakeEntry {
            param(
                [string]   $Message,
                [datetime] $DateTime = (Get-Date '2026-04-24 09:00:00'),
                [string]   $Component = 'ccmsetup',
                [string]   $SignatureId = $null,
                [string]   $LogFile = 'ccmsetup.log',
                $ErrorCode = $null
            )
            [pscustomobject]@{
                Message     = $Message
                DateTime    = $DateTime
                Component   = $Component
                SignatureId = $SignatureId
                LogFile     = $LogFile
                ErrorCode   = $ErrorCode
                Severity    = 'Error'
            }
        }

        function New-Rule {
            param(
                [string]$Id,
                [string]$Scope = 'ClientInstall',
                [int]   $Confidence = 80,
                [object[]]$All,
                [string]$Verdict = 'Test verdict sentence for the incident suite.',
                [string]$Fix = 'Apply the fix and retry.'
            )
            [pscustomobject]@{
                id         = $Id
                scope      = $Scope
                confidence = $Confidence
                version    = '1.0'
                source     = 'baseline'
                when       = [pscustomobject]@{ all = $All; any = @(); none = @() }
                verdict    = $Verdict
                fix        = $Fix
                evidence   = @()
            }
        }

        function New-TempRoot {
            $p = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-incident-test-" + [guid]::NewGuid().ToString('N').Substring(0,10))
            $null = New-Item -ItemType Directory -Path $p -Force
            return $p
        }
    }

    Context 'New-LATIncident' {

        BeforeAll {
            $script:Root = New-TempRoot
            $script:Pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'ccmsetup started' -SignatureId 'CCM-001' -DateTime (Get-Date '2026-04-24 09:00:00')),
                (New-FakeEntry -Component 'ClientIDManagerStartup' -Message 'certificate validation failed' -SignatureId 'CERT-001' -DateTime (Get-Date '2026-04-24 09:00:10'))
            )
            $script:Rules = @(
                (New-Rule -Id 'smoke-rule' -All @([pscustomobject]@{ signature = 'CCM-001' }))
            )
            $script:Eval = Invoke-RuleEvaluator -ParseResult $script:Pr -Rules $script:Rules
        }

        AfterAll {
            Remove-Item -Path $script:Root -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'writes a zip with expected entries' {
            $path = New-LATIncident -ParseResult $script:Pr -EvalResult $script:Eval -IncidentRoot $script:Root
            Test-Path $path | Should -BeTrue
            (Get-Item $path).Length | Should -BeGreaterThan 0
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($path)
            try {
                $names = @($zip.Entries | ForEach-Object { $_.FullName })
                $names | Should -Contain 'manifest.json'
                $names | Should -Contain 'parse-result.json'
                $names | Should -Contain 'matches.json'
            } finally {
                $zip.Dispose()
            }
        }

        It 'records top verdict in the manifest' {
            $path = New-LATIncident -ParseResult $script:Pr -EvalResult $script:Eval -Label 'unit' -IncidentRoot $script:Root
            $bundle = Import-LATIncident -Path $path
            try {
                $bundle.Manifest.topVerdictRuleId | Should -Be 'smoke-rule'
                $bundle.Manifest.label            | Should -Be 'unit'
                $bundle.Manifest.schemaVersion    | Should -Be 1
            } finally {
                Remove-Item -Path $bundle.ExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'embeds requested log files' {
            $tempLog = Join-Path ([System.IO.Path]::GetTempPath()) "fake-$([guid]::NewGuid().ToString('N').Substring(0,8)).log"
            Set-Content -Path $tempLog -Value 'fake log content' -Encoding UTF8
            try {
                $path = New-LATIncident -ParseResult $script:Pr -EvalResult $script:Eval -LogFiles @($tempLog) -IncidentRoot $script:Root
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $zip = [System.IO.Compression.ZipFile]::OpenRead($path)
                try {
                    $names = @($zip.Entries | ForEach-Object { $_.FullName })
                    @($names | Where-Object { $_ -match '^logs[\\/]' }).Count | Should -BeGreaterThan 0
                } finally {
                    $zip.Dispose()
                }
            } finally {
                Remove-Item $tempLog -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Import-LATIncident round-trip' {

        BeforeAll {
            $script:Root2 = New-TempRoot
            $script:Pr2 = New-LATParseResult -Entries @(
                (New-FakeEntry -Message 'sig-event' -SignatureId 'CCM-001' -DateTime (Get-Date '2026-04-24 12:34:56'))
            ) -MatchedSignatures @('CCM-001')
            $script:Rules2 = @( (New-Rule -Id 'r1' -All @([pscustomobject]@{ signature = 'CCM-001' })) )
            $script:Eval2 = Invoke-RuleEvaluator -ParseResult $script:Pr2 -Rules $script:Rules2
            $script:IncidentPath = New-LATIncident -ParseResult $script:Pr2 -EvalResult $script:Eval2 -IncidentRoot $script:Root2
        }

        AfterAll {
            Remove-Item -Path $script:Root2 -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'preserves ParseResult shape and counts' {
            $bundle = Import-LATIncident -Path $script:IncidentPath
            try {
                @($bundle.ParseResult.Entries).Count | Should -Be 1
                @($bundle.ParseResult.MatchedSignatures) -contains 'CCM-001' | Should -BeTrue
            } finally {
                Remove-Item -Path $bundle.ExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'round-trips DateTime as [datetime]' {
            $bundle = Import-LATIncident -Path $script:IncidentPath
            try {
                $dt = $bundle.ParseResult.Entries[0].DateTime
                $dt | Should -BeOfType [datetime]
                $dt.Year | Should -Be 2026
                $dt.Month | Should -Be 4
                $dt.Day | Should -Be 24
            } finally {
                Remove-Item -Path $bundle.ExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'rejects unknown schemaVersion' {
            # Corrupt the manifest and re-zip under a test-only path
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $extract = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-badver-" + [guid]::NewGuid().ToString('N').Substring(0,8))
            $null = New-Item -ItemType Directory -Path $extract -Force
            Expand-Archive -Path $script:IncidentPath -DestinationPath $extract -Force
            $m = Get-Content (Join-Path $extract 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json
            $m.schemaVersion = 999
            $m | ConvertTo-Json -Depth 6 | Set-Content -Path (Join-Path $extract 'manifest.json') -Encoding UTF8
            $badZip = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-badver-" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".zip")
            Compress-Archive -Path (Join-Path $extract '*') -DestinationPath $badZip -Force
            try {
                { Import-LATIncident -Path $badZip } | Should -Throw -ExpectedMessage '*schemaVersion*'
            } finally {
                Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item $badZip -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Get-LATIncidentList + Trim-LATIncidents (FIFO retention)' {

        It 'returns newest first' {
            $root = New-TempRoot
            try {
                $pr  = New-LATParseResult
                $ev  = Invoke-RuleEvaluator -ParseResult $pr -Rules @()
                $p1 = New-LATIncident -ParseResult $pr -EvalResult $ev -Label 'first'  -IncidentRoot $root -Retention 0
                Start-Sleep -Milliseconds 1100
                $p2 = New-LATIncident -ParseResult $pr -EvalResult $ev -Label 'second' -IncidentRoot $root -Retention 0
                $list = @(Get-LATIncidentList -IncidentRoot $root)
                $list.Count | Should -Be 2
                $list[0].FullName | Should -Be $p2
                $list[1].FullName | Should -Be $p1
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'enforces FIFO retention on the Nth write' {
            $root = New-TempRoot
            try {
                $pr  = New-LATParseResult
                $ev  = Invoke-RuleEvaluator -ParseResult $pr -Rules @()
                for ($i = 0; $i -lt 4; $i++) {
                    $null = New-LATIncident -ParseResult $pr -EvalResult $ev -Label "x$i" -IncidentRoot $root -Retention 2
                    Start-Sleep -Milliseconds 1100
                }
                $list = @(Get-LATIncidentList -IncidentRoot $root)
                $list.Count | Should -Be 2
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Invoke-LATIncidentReplay' {

        It 'flags added + removed verdicts when the rulebase changes' {
            $root = New-TempRoot
            try {
                $pr = New-LATParseResult -Entries @(
                    (New-FakeEntry -Message 'x' -SignatureId 'CCM-001')
                ) -MatchedSignatures @('CCM-001')
                $originalRules = @( (New-Rule -Id 'old-rule' -All @([pscustomobject]@{ signature = 'CCM-001' })) )
                $ev = Invoke-RuleEvaluator -ParseResult $pr -Rules $originalRules
                $path = New-LATIncident -ParseResult $pr -EvalResult $ev -IncidentRoot $root -Retention 0

                # New rulebase: old rule dropped, new rule added that also fires
                $newRules = @(
                    (New-Rule -Id 'new-rule'    -All @([pscustomobject]@{ signature = 'CCM-001' })),
                    (New-Rule -Id 'other-rule'  -All @([pscustomobject]@{ signature = 'WMI-001' }))
                )
                $result = Invoke-LATIncidentReplay -Path $path -Rules $newRules
                @($result.Diff.AddedRuleIds)   | Should -Contain 'new-rule'
                @($result.Diff.RemovedRuleIds) | Should -Contain 'old-rule'
                @($result.Replay.Verdicts).Count | Should -BeGreaterThan 0
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'returns identical diff sets when rulebase is unchanged' {
            $root = New-TempRoot
            try {
                $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
                $rules = @( (New-Rule -Id 'r' -All @([pscustomobject]@{ signature = 'CCM-001' })) )
                $ev = Invoke-RuleEvaluator -ParseResult $pr -Rules $rules
                $path = New-LATIncident -ParseResult $pr -EvalResult $ev -IncidentRoot $root -Retention 0

                $result = Invoke-LATIncidentReplay -Path $path -Rules $rules
                @($result.Diff.AddedRuleIds).Count   | Should -Be 0
                @($result.Diff.RemovedRuleIds).Count | Should -Be 0
                @($result.Diff.RetainedRuleIds)      | Should -Contain 'r'
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
