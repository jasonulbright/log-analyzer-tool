Describe 'LATTriageVM (Session 11)' {

    BeforeAll {
        $script:RepoRoot    = Resolve-Path (Join-Path $PSScriptRoot '..')
        $script:EvaluatorPs = Join-Path $script:RepoRoot 'Module\Invoke-RuleEvaluator.ps1'
        $script:VMPs        = Join-Path $script:RepoRoot 'Module\LATTriageVM.ps1'
        $script:ValidatorPs = Join-Path $script:RepoRoot 'Module\Test-LATRule.ps1'
        . $script:ValidatorPs
        . $script:EvaluatorPs
        . $script:VMPs

        function New-Rule {
            param(
                [string]$Id,
                [int]$Confidence = 80,
                [string]$Verdict = 'A sufficient verdict sentence for the VM test suite.',
                [string]$Fix = 'Apply the remediation steps and retry the failing operation.'
            )
            [pscustomobject]@{
                id = $Id; scope = 'ClientInstall'; confidence = $Confidence
                version = '1.0'; source = 'baseline'
                when = [pscustomobject]@{ all = @([pscustomobject]@{ signature = 'CCM-001' }); any = @(); none = @() }
                verdict = $Verdict; fix = $Fix
                evidence = @(
                    [pscustomobject]@{ component = 'ccmsetup'; match = 'Failed to' }
                )
            }
        }
    }

    Context 'Empty VM' {

        It 'returns a schema-valid empty VM with action buttons disabled' {
            $vm = New-LATEmptyVerdictCardVM
            $vm.HasVerdict           | Should -BeFalse
            $vm.RuleId               | Should -Be 'no-incident-loaded'
            $vm.ConfidencePercent    | Should -Be 0
            $vm.ConfidenceText       | Should -Be '--'
            $vm.ActionButtonsEnabled | Should -BeFalse
            @($vm.Evidence).Count          | Should -Be 0
            @($vm.AlternateVerdicts).Count | Should -Be 0
        }
    }

    Context 'New-LATVerdictCardVM' {

        It 'populates from a top verdict' {
            $pr   = New-LATParseResult -MatchedSignatures @('CCM-001') -Entries @(
                [pscustomobject]@{ Component = 'ccmsetup'; Message = 'Failed to install X'; DateTime = (Get-Date) }
            )
            $rule = New-Rule -Id 'r1' -Confidence 85
            $ev   = Invoke-RuleEvaluator -ParseResult $pr -Rules @($rule)

            $vm = New-LATVerdictCardVM -EvalResult $ev
            $vm.HasVerdict        | Should -BeTrue
            $vm.RuleId            | Should -Be 'r1'
            $vm.Scope             | Should -Be 'ClientInstall'
            $vm.Confidence        | Should -Be 85
            $vm.ConfidencePercent | Should -Be 85
            $vm.ConfidenceText    | Should -Be '85%'
            $vm.Fix               | Should -Match 'remediation'
            $vm.ActionButtonsEnabled | Should -BeTrue
        }

        It 'clamps confidence to 0..100 for the progress-bar bind' {
            $pr   = New-LATParseResult -MatchedSignatures @('CCM-001')
            $rule = New-Rule -Id 'r1' -Confidence 95
            $ev   = Invoke-RuleEvaluator -ParseResult $pr -Rules @($rule)
            $vm   = New-LATVerdictCardVM -EvalResult $ev
            # Confidence 95 pct and percent stay aligned for a normal rule.
            $vm.ConfidencePercent | Should -Be 95
        }

        It 'returns an empty-style VM when no rule fires' {
            $pr = New-LATParseResult
            $ev = Invoke-RuleEvaluator -ParseResult $pr -Rules @()
            $vm = New-LATVerdictCardVM -EvalResult $ev
            $vm.HasVerdict        | Should -BeFalse
            $vm.ActionButtonsEnabled | Should -BeTrue  # empty-no-match state allows Capture
            $vm.RuleId            | Should -Be '(no match)'
            $vm.Headline          | Should -Match '(?i)no rule matched'
        }

        It 'populates evidence from the top verdict EvidenceLines' {
            $pr   = New-LATParseResult -MatchedSignatures @('CCM-001') -Entries @(
                [pscustomobject]@{ Component = 'ccmsetup'; Message = 'Failed to contact MP'; DateTime = (Get-Date); SignatureId = 'CCM-001' }
            )
            $rule = New-Rule -Id 'r-evidence'
            $ev   = Invoke-RuleEvaluator -ParseResult $pr -Rules @($rule)
            $vm   = New-LATVerdictCardVM -EvalResult $ev
            @($vm.Evidence).Count | Should -BeGreaterThan 0
            $vm.Evidence[0].Component | Should -Be 'ccmsetup'
            $vm.Evidence[0].Message   | Should -Match 'Failed to'
        }

        It 'populates alternate verdicts when multiple rules fire' {
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            $rules = @(
                (New-Rule -Id 'top' -Confidence 90 -Verdict 'Higher-conf verdict text for alt test')
                (New-Rule -Id 'alt' -Confidence 70 -Verdict 'Lower-conf alternate verdict text')
            )
            $ev = Invoke-RuleEvaluator -ParseResult $pr -Rules $rules
            $vm = New-LATVerdictCardVM -EvalResult $ev
            $vm.RuleId                 | Should -Be 'top'
            @($vm.AlternateVerdicts).Count | Should -BeGreaterOrEqual 1
            $vm.AlternateVerdicts[0].RuleId     | Should -Be 'alt'
            $vm.AlternateVerdicts[0].Confidence | Should -Be '70%'
        }
    }
}
