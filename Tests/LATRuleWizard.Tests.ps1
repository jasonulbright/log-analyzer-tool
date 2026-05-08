Describe 'LATRuleWizard (Session 8)' {

    BeforeAll {
        $script:RepoRoot    = Resolve-Path (Join-Path $PSScriptRoot '..')
        $script:ValidatorPs = Join-Path $script:RepoRoot 'Module\Test-LATRule.ps1'
        $script:EvaluatorPs = Join-Path $script:RepoRoot 'Module\Invoke-RuleEvaluator.ps1'
        $script:IncidentPs  = Join-Path $script:RepoRoot 'Module\LATIncident.ps1'
        $script:WizardPs    = Join-Path $script:RepoRoot 'Module\LATRuleWizard.ps1'
        . $script:ValidatorPs
        . $script:EvaluatorPs
        . $script:IncidentPs
        . $script:WizardPs

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

        function New-TempRoot {
            $p = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-wizard-" + [guid]::NewGuid().ToString('N').Substring(0,10))
            $null = New-Item -ItemType Directory -Path $p -Force
            return $p
        }
    }

    Context 'Get-LATDraftScope inference' {

        It 'maps APP-* signatures to App scope' {
            (Get-LATDraftScope -MatchedSignatures @('APP-001','APP-002')) | Should -Be 'App'
        }

        It 'maps WUA-*/SU-* to SoftwareUpdate' {
            (Get-LATDraftScope -MatchedSignatures @('WUA-002')) | Should -Be 'SoftwareUpdate'
        }

        It 'maps CCM-* to ClientInstall' {
            (Get-LATDraftScope -MatchedSignatures @('CCM-001','CCM-002')) | Should -Be 'ClientInstall'
        }

        It 'defaults to CrossScope for unknown prefixes' {
            (Get-LATDraftScope -MatchedSignatures @('DP-001','WMI-001')) | Should -Be 'CrossScope'
        }

        It 'returns CrossScope on empty input' {
            (Get-LATDraftScope -MatchedSignatures @()) | Should -Be 'CrossScope'
        }

        It 'tie-breaks away from CrossScope when tied' {
            # 1 CCM-* + 1 DP-* => one real scope, one CrossScope, should prefer CCM
            (Get-LATDraftScope -MatchedSignatures @('CCM-001','DP-001')) | Should -Be 'ClientInstall'
        }
    }

    Context 'New-LATRuleDraft pre-fill' {

        BeforeAll {
            $script:Pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'Failed to verify the authenticity of the MP' -SignatureId 'CCM-001' -DateTime (Get-Date '2026-04-24 09:00:00')),
                (New-FakeEntry -Component 'ClientIDManagerStartup' -Message 'certificate validation failed' -SignatureId 'CERT-001' -DateTime (Get-Date '2026-04-24 09:00:10') -ErrorCode '1603')
            )
            $script:Draft = New-LATRuleDraft -ParseResult $script:Pr
        }

        It 'draft is schema-valid' {
            $r = Test-LATRule -Rule $script:Draft
            if (-not $r.Valid) { Write-Host ($r.Errors -join "`n") }
            $r.Valid | Should -BeTrue
        }

        It 'kebab-case ID starts with `draft-`' {
            $script:Draft.id | Should -Match '^draft-[a-z0-9]+(-[a-z0-9]+)*$'
        }

        It 'when.all contains a condition per matched signature' {
            $sigs = @($script:Draft.when.all | Where-Object { $_.PSObject.Properties['signature'] } | ForEach-Object { $_.signature })
            $sigs | Should -Contain 'CCM-001'
            $sigs | Should -Contain 'CERT-001'
        }

        It 'when.all includes an errorCode condition from derived error codes' {
            $codes = @($script:Draft.when.all | Where-Object { $_.PSObject.Properties['errorCode'] })
            $codes.Count | Should -BeGreaterThan 0
            $codes[0].errorCode | Should -Be '1603'
        }

        It 'evidence is populated from flagged entries, sorted oldest first' {
            $script:Draft.evidence.Count | Should -BeGreaterThan 0
            $script:Draft.evidence[0].component | Should -Be 'ccmsetup'
            $script:Draft.evidence[0].match | Should -Match 'verify the authenticity'
        }

        It 'source is local (not baseline)' {
            $script:Draft.source | Should -Be 'local'
        }

        It 'scope inferred (CCM + CERT -> ClientInstall)' {
            $script:Draft.scope | Should -Be 'ClientInstall'
        }

        It 'seeds verdict from top match when an EvalResult is supplied' {
            $rules = @(
                [pscustomobject]@{
                    id = 'r1'; scope = 'ClientInstall'; confidence = 80; version = '1.0'
                    source = 'baseline'
                    when = [pscustomobject]@{ all = @([pscustomobject]@{ signature = 'CCM-001' }); any = @(); none = @() }
                    verdict = 'Seeded verdict from a fired rule.'
                    fix = 'Apply the seeded fix.'
                    evidence = @()
                }
            )
            $ev = Invoke-RuleEvaluator -ParseResult $script:Pr -Rules $rules
            $d  = New-LATRuleDraft -ParseResult $script:Pr -EvalResult $ev
            $d.verdict | Should -Match 'Seeded verdict'
        }
    }

    Context 'Get-LATDraftPreview' {

        It 'draft fires against the ParseResult it was seeded from' {
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            $d  = New-LATRuleDraft -ParseResult $pr
            $p  = Get-LATDraftPreview -DraftRule $d -CurrentParseResult $pr -IncidentRoot (New-TempRoot)
            $p.SchemaValid | Should -BeTrue
            $p.CurrentIncidentResult.Fires | Should -BeTrue
        }

        It 'reports missing conditions when the draft misses the current incident' {
            $pr  = New-LATParseResult -MatchedSignatures @('CCM-001')
            $d   = New-LATRuleDraft -ParseResult $pr
            # Add an extra unsatisfiable condition to force a miss
            $d.when.all += [pscustomobject]@{ signature = 'NEVER-FIRES' }
            $p   = Get-LATDraftPreview -DraftRule $d -CurrentParseResult $pr -IncidentRoot (New-TempRoot)
            $p.CurrentIncidentResult.Fires | Should -BeFalse
            @($p.CurrentIncidentResult.MissingConditions).Count | Should -Be 1
            $p.CurrentIncidentResult.MissingConditions[0].signature | Should -Be 'NEVER-FIRES'
        }

        It 'returns SchemaValid=false when the draft is malformed' {
            $pr = New-LATParseResult
            $bad = [pscustomobject]@{
                id = 'x'; scope = 'NotAScope'; confidence = 999
                when = [pscustomobject]@{ all = @() }
                verdict = 'short'
                fix     = 'short'
                version = '1.0'; source = 'local'
            }
            $p = Get-LATDraftPreview -DraftRule $bad -CurrentParseResult $pr -IncidentRoot (New-TempRoot)
            $p.SchemaValid | Should -BeFalse
            @($p.SchemaErrors).Count | Should -BeGreaterThan 0
        }

        It 'evaluates against stored incidents and aggregates fire/miss counts' {
            $root = New-TempRoot
            try {
                # Store one incident that will fire and one that will not.
                $hit  = New-LATParseResult -MatchedSignatures @('CCM-001')
                $miss = New-LATParseResult -MatchedSignatures @('UNRELATED-999')
                $rules = @(
                    [pscustomobject]@{
                        id='r1'; scope='ClientInstall'; confidence=80; version='1.0'; source='baseline'
                        when = [pscustomobject]@{ all = @([pscustomobject]@{ signature = 'CCM-001' }); any = @(); none = @() }
                        verdict = 'An adequate verdict for the preview test.'
                        fix = 'Apply whatever fix is needed.'
                        evidence = @()
                    }
                )
                $evHit  = Invoke-RuleEvaluator -ParseResult $hit  -Rules $rules
                $evMiss = Invoke-RuleEvaluator -ParseResult $miss -Rules $rules
                $null = New-LATIncident -ParseResult $hit  -EvalResult $evHit  -Label 'hit'  -IncidentRoot $root -Retention 0
                Start-Sleep -Milliseconds 1100
                $null = New-LATIncident -ParseResult $miss -EvalResult $evMiss -Label 'miss' -IncidentRoot $root -Retention 0

                # Draft built from the hitting incident
                $draft = New-LATRuleDraft -ParseResult $hit
                $p = Get-LATDraftPreview -DraftRule $draft -CurrentParseResult $hit -IncidentRoot $root
                $p.Summary.TotalStored | Should -Be 2
                $p.Summary.Fired  | Should -Be 1
                $p.Summary.Missed | Should -Be 1
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Show-LATRuleWizard (non-interactive orchestrator)' {

        It 'returns a draft+preview pair without prompting' {
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001') -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'scripted wizard run' -SignatureId 'CCM-001')
            )
            $out = Show-LATRuleWizard -ParseResult $pr -NonInteractive -IncidentRoot (New-TempRoot)
            $out.Draft   | Should -Not -BeNullOrEmpty
            $out.Preview | Should -Not -BeNullOrEmpty
            $out.Draft.scope | Should -Be 'ClientInstall'
            $out.Preview.CurrentIncidentResult.Fires | Should -BeTrue
        }
    }
}
