Describe 'LAT rule schema (Session 2 smoke + structural)' {

    BeforeAll {
        $script:RepoRoot     = Resolve-Path (Join-Path $PSScriptRoot '..')
        $script:SchemaPath   = Join-Path $script:RepoRoot 'Rules\Schema\rule.schema.json'
        $script:BaselineRoot = Join-Path $script:RepoRoot 'Rules\Baseline'
        $script:ValidatorPath = Join-Path $script:RepoRoot 'Module\Test-LATRule.ps1'
        . $script:ValidatorPath

        function Read-RuleFile {
            param([string]$Path)
            $raw = Get-Content -Path $Path -Raw -Encoding UTF8
            return $raw | ConvertFrom-Json
        }

        function New-MinimalRule {
            [pscustomobject]@{
                id         = 'sample-rule'
                scope      = 'ClientInstall'
                confidence = 80
                version    = '1.0'
                when       = [pscustomobject]@{
                    all = @([pscustomobject]@{ signature = 'CCM-001' })
                }
                verdict    = 'A reasonable verdict sentence for a sample rule.'
                fix        = 'Apply the obvious fix. Then verify and move on.'
            }
        }
    }

    Context 'Schema file' {

        It 'rule.schema.json exists and is valid JSON' {
            Test-Path $script:SchemaPath | Should -BeTrue
            { Get-Content -Path $script:SchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json } | Should -Not -Throw
        }

        It 'declares draft-07 and the expected scope enum' {
            $schema = Get-Content -Path $script:SchemaPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $schema.'$schema' | Should -Be 'http://json-schema.org/draft-07/schema#'
            $expected = @('App', 'SoftwareUpdate', 'ClientInstall', 'CrossScope')
            ($schema.properties.scope.enum | Sort-Object) -join ',' | Should -Be (($expected | Sort-Object) -join ',')
        }
    }

    Context 'Test-LATRule validator' {

        It 'accepts a minimal valid rule' {
            $r = Test-LATRule -Rule (New-MinimalRule)
            if (-not $r.Valid) { Write-Host ($r.Errors -join "`n") }
            $r.Valid | Should -BeTrue
        }

        It 'rejects an empty object (missing required fields)' {
            $r = Test-LATRule -Rule ([pscustomobject]@{})
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match "missing required field 'id'"
        }

        It 'rejects an invalid scope value' {
            $rule = New-MinimalRule
            $rule.scope = 'NotARealScope'
            $r = Test-LATRule -Rule $rule
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match 'scope.*NotARealScope'
        }

        It 'rejects a condition with no recognized discriminator' {
            $rule = New-MinimalRule
            $rule.when.all = @([pscustomobject]@{ wat = 'huh' })
            $r = Test-LATRule -Rule $rule
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match 'no recognized discriminator'
        }

        It 'rejects an id that is not kebab-case' {
            $rule = New-MinimalRule
            $rule.id = 'NotKebab_Case'
            $r = Test-LATRule -Rule $rule
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match 'kebab-case'
        }

        It 'rejects confidence out of range' {
            $rule = New-MinimalRule
            $rule.confidence = 150
            $r = Test-LATRule -Rule $rule
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match 'confidence.*0\.\.100'
        }

        It 'rejects a component condition missing pattern' {
            $rule = New-MinimalRule
            $rule.when.all = @([pscustomobject]@{ component = 'ccmsetup' })
            $r = Test-LATRule -Rule $rule
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match "component condition requires 'pattern'"
        }

        It 'rejects a timeGap missing maxSec' {
            $rule = New-MinimalRule
            $rule.when.all = @([pscustomobject]@{ timeGap = [pscustomobject]@{ fromSignature = 'A'; toSignature = 'B' } })
            $r = Test-LATRule -Rule $rule
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match "missing required field 'maxSec'"
        }

        It 'rejects causalOrder entry referencing two condition types' {
            $rule = New-MinimalRule
            $rule | Add-Member -NotePropertyName causalOrder -NotePropertyValue @(
                [pscustomobject]@{ signature = 'CCM-001'; errorCode = '1603'; role = 'root' }
            )
            $r = Test-LATRule -Rule $rule
            $r.Valid | Should -BeFalse
            ($r.Errors -join '|') | Should -Match 'must reference exactly one'
        }
    }

    Context 'Baseline rule bundle' {

        BeforeAll {
            $script:BaselineFiles = @(Get-ChildItem -Path $script:BaselineRoot -Recurse -Filter *.json -ErrorAction Stop)
        }

        It 'baseline directory contains at least 5 rule files' {
            $script:BaselineFiles.Count | Should -BeGreaterOrEqual 5
        }

        It 'every baseline rule file is valid JSON and conforms to the schema' {
            $failures = New-Object System.Collections.Generic.List[string]
            foreach ($f in $script:BaselineFiles) {
                $rule = $null
                try {
                    $rule = Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                } catch {
                    $failures.Add("$($f.Name): JSON parse failed - $($_.Exception.Message)")
                    continue
                }
                $r = Test-LATRule -Rule $rule -Path $f.Name
                if (-not $r.Valid) {
                    $failures.Add(($r.Errors -join "`n  "))
                }
            }
            if ($failures.Count -gt 0) { Write-Host ($failures -join "`n----`n") }
            $failures.Count | Should -Be 0
        }

        It 'baseline rule ids are globally unique' {
            $ids = foreach ($f in $script:BaselineFiles) {
                $rule = Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                $rule.id
            }
            $dupes = $ids | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
            if ($dupes) { Write-Host "Duplicate ids: $($dupes -join ', ')" }
            @($dupes).Count | Should -Be 0
        }

        It 'baseline rule scope matches its parent directory' {
            $mismatches = New-Object System.Collections.Generic.List[string]
            foreach ($f in $script:BaselineFiles) {
                $rule = Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                $expectedScope = Split-Path -Leaf (Split-Path -Parent $f.FullName)
                if ($rule.scope -ne $expectedScope) {
                    $mismatches.Add("$($f.Name): scope='$($rule.scope)' but lives in '$expectedScope/'")
                }
            }
            if ($mismatches.Count -gt 0) { Write-Host ($mismatches -join "`n") }
            $mismatches.Count | Should -Be 0
        }

        It 'every baseline rule has source=baseline' {
            foreach ($f in $script:BaselineFiles) {
                $rule = Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                $rule.source | Should -Be 'baseline' -Because "($($f.Name)) baseline tracked rules must declare source=baseline"
            }
        }

        It 'every baseline rule has confidence >= 70 (per kickstart risk-vector mitigation)' {
            foreach ($f in $script:BaselineFiles) {
                $rule = Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                $rule.confidence | Should -BeGreaterOrEqual 70 -Because "($($f.Name)) baseline floor"
            }
        }
    }
}
