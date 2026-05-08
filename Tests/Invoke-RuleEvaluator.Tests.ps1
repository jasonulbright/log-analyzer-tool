Describe 'Invoke-RuleEvaluator (Session 3)' {

    BeforeAll {
        $script:RepoRoot      = Resolve-Path (Join-Path $PSScriptRoot '..')
        $script:EvaluatorPath = Join-Path $script:RepoRoot 'Module\Invoke-RuleEvaluator.ps1'
        $script:ValidatorPath = Join-Path $script:RepoRoot 'Module\Test-LATRule.ps1'
        $script:BaselineRoot  = Join-Path $script:RepoRoot 'Rules\Baseline'
        . $script:ValidatorPath
        . $script:EvaluatorPath

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
            }
        }

        function New-Rule {
            param(
                [string]   $Id,
                [string]   $Scope = 'ClientInstall',
                [int]      $Confidence = 80,
                [object[]] $All = @(),
                [object[]] $Any = @(),
                [object[]] $None = @(),
                [string]   $Verdict = 'Test verdict sentence for the suite.',
                [string]   $Fix = 'Apply test fix and retry.',
                [object[]] $Evidence = @()
            )
            $rule = [pscustomobject]@{
                id         = $Id
                scope      = $Scope
                confidence = $Confidence
                version    = '1.0'
                source     = 'baseline'
                when       = [pscustomobject]@{
                    all  = $All
                    any  = $Any
                    none = $None
                }
                verdict    = $Verdict
                fix        = $Fix
                evidence   = $Evidence
            }
            return $rule
        }
    }

    Context 'New-LATParseResult' {

        It 'auto-derives MatchedSignatures from entries' {
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Message 'a' -SignatureId 'CCM-001'),
                (New-FakeEntry -Message 'b' -SignatureId 'CCM-001'),
                (New-FakeEntry -Message 'c' -SignatureId 'WMI-001')
            )
            ($pr.MatchedSignatures | Sort-Object) -join ',' | Should -Be 'CCM-001,WMI-001'
        }

        It 'auto-derives ErrorCodes from entries' {
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Message 'x' -ErrorCode '1603' -Component 'ccmsetup')
            )
            $pr.ErrorCodes.Count | Should -Be 1
            $pr.ErrorCodes[0].Code | Should -Be '1603'
            $pr.ErrorCodes[0].Component | Should -Be 'ccmsetup'
        }

        It 'returns empty derived arrays when entries are empty' {
            $pr = New-LATParseResult -Entries @()
            $pr.MatchedSignatures.Count | Should -Be 0
            $pr.ErrorCodes.Count | Should -Be 0
            $pr.Clusters.Count | Should -Be 0
        }
    }

    Context 'Condition: signature' {
        It 'matches when MatchedSignatures contains the id' {
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ signature = 'CCM-001' }) -ParseResult $pr) | Should -BeTrue
        }
        It 'does not match when absent' {
            $pr = New-LATParseResult -MatchedSignatures @('WMI-001')
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ signature = 'CCM-001' }) -ParseResult $pr) | Should -BeFalse
        }
    }

    Context 'Condition: errorCode' {
        It 'matches by code alone' {
            $pr = New-LATParseResult -ErrorCodes @([pscustomobject]@{ Code = '1603'; Component = 'ccmsetup' })
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ errorCode = '1603' }) -ParseResult $pr) | Should -BeTrue
        }
        It 'matches code+component case-insensitive' {
            $pr = New-LATParseResult -ErrorCodes @([pscustomobject]@{ Code = '0x80041002'; Component = 'CcmExec' })
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ errorCode = '0x80041002'; component = 'ccmexec' }) -ParseResult $pr) | Should -BeTrue
        }
        It 'rejects when component scope mismatches' {
            $pr = New-LATParseResult -ErrorCodes @([pscustomobject]@{ Code = '1603'; Component = 'msiexec' })
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ errorCode = '1603'; component = 'ccmsetup' }) -ParseResult $pr) | Should -BeFalse
        }
    }

    Context 'Condition: cluster' {
        It 'matches when cluster name is present' {
            $pr = New-LATParseResult -Clusters @('EVT-CONTENT', 'EVT-WMI')
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ cluster = 'EVT-WMI' }) -ParseResult $pr) | Should -BeTrue
        }
        It 'does not match an absent cluster' {
            $pr = New-LATParseResult -Clusters @('EVT-CONTENT')
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ cluster = 'EVT-MISSING' }) -ParseResult $pr) | Should -BeFalse
        }
    }

    Context 'Condition: probe' {
        It 'matches probe by name + result' {
            $pr = New-LATParseResult -Probes @([pscustomobject]@{ Name = 'Test-DnsResolution'; Result = 'Fail' })
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ probe = 'Test-DnsResolution'; result = 'Fail' }) -ParseResult $pr) | Should -BeTrue
        }
        It 'matches probe by name when result not specified' {
            $pr = New-LATParseResult -Probes @([pscustomobject]@{ Name = 'Test-MppCorruption'; Result = 'Pass' })
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ probe = 'Test-MppCorruption' }) -ParseResult $pr) | Should -BeTrue
        }
        It 'rejects when result mismatches' {
            $pr = New-LATParseResult -Probes @([pscustomobject]@{ Name = 'Test-DnsResolution'; Result = 'Pass' })
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ probe = 'Test-DnsResolution'; result = 'Fail' }) -ParseResult $pr) | Should -BeFalse
        }
    }

    Context 'Condition: component+pattern' {
        It 'matches a regex against an entry in the named component' {
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'Failed to verify the authenticity of the chain')
            )
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ component = 'ccmsetup'; pattern = 'verify the authenticity' }) -ParseResult $pr) | Should -BeTrue
        }
        It 'rejects when no entry in that component matches' {
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'PolicyAgent' -Message 'irrelevant')
            )
            (Test-LATConditionMatch -Condition ([pscustomobject]@{ component = 'ccmsetup'; pattern = 'verify' }) -ParseResult $pr) | Should -BeFalse
        }
    }

    Context 'Condition: timeGap' {
        It 'matches two signatures within the window' {
            $t1 = Get-Date '2026-04-24 09:00:00'
            $t2 = $t1.AddSeconds(30)
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Message 'a' -SignatureId 'CCM-001' -DateTime $t1),
                (New-FakeEntry -Message 'b' -SignatureId 'CERT-001' -DateTime $t2)
            )
            $cond = [pscustomobject]@{ timeGap = [pscustomobject]@{ fromSignature = 'CCM-001'; toSignature = 'CERT-001'; maxSec = 60 } }
            (Test-LATConditionMatch -Condition $cond -ParseResult $pr) | Should -BeTrue
        }
        It 'rejects when the gap exceeds maxSec' {
            $t1 = Get-Date '2026-04-24 09:00:00'
            $t2 = $t1.AddSeconds(120)
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Message 'a' -SignatureId 'CCM-001' -DateTime $t1),
                (New-FakeEntry -Message 'b' -SignatureId 'CERT-001' -DateTime $t2)
            )
            $cond = [pscustomobject]@{ timeGap = [pscustomobject]@{ fromSignature = 'CCM-001'; toSignature = 'CERT-001'; maxSec = 60 } }
            (Test-LATConditionMatch -Condition $cond -ParseResult $pr) | Should -BeFalse
        }
        It 'rejects when from-event is later than to-event' {
            $t1 = Get-Date '2026-04-24 09:00:00'
            $t2 = $t1.AddSeconds(-30)
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Message 'a' -SignatureId 'CCM-001' -DateTime $t1),
                (New-FakeEntry -Message 'b' -SignatureId 'CERT-001' -DateTime $t2)
            )
            $cond = [pscustomobject]@{ timeGap = [pscustomobject]@{ fromSignature = 'CCM-001'; toSignature = 'CERT-001'; maxSec = 60 } }
            (Test-LATConditionMatch -Condition $cond -ParseResult $pr) | Should -BeFalse
        }
    }

    Context 'Test-LATRuleMatches (boolean: all AND !none AND (empty(any) | any))' {

        It 'fires when all match and none/any are empty' {
            $rule = New-Rule -Id 'r1' -All @([pscustomobject]@{ signature = 'CCM-001' })
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            (Test-LATRuleMatches -Rule $rule -ParseResult $pr) | Should -BeTrue
        }

        It 'does not fire when an `all` condition is missing' {
            $rule = New-Rule -Id 'r1' -All @(
                [pscustomobject]@{ signature = 'CCM-001' },
                [pscustomobject]@{ signature = 'WMI-001' }
            )
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            (Test-LATRuleMatches -Rule $rule -ParseResult $pr) | Should -BeFalse
        }

        It 'is suppressed by a none condition' {
            $rule = New-Rule -Id 'r1' `
                -All  @([pscustomobject]@{ signature = 'CCM-001' }) `
                -None @([pscustomobject]@{ signature = 'DNS-001' })
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001', 'DNS-001')
            (Test-LATRuleMatches -Rule $rule -ParseResult $pr) | Should -BeFalse
        }

        It 'requires at least one any to match when any is non-empty' {
            $rule = New-Rule -Id 'r1' `
                -All @([pscustomobject]@{ signature = 'CCM-001' }) `
                -Any @(
                    [pscustomobject]@{ errorCode = '1603' },
                    [pscustomobject]@{ errorCode = '10' }
                )
            $prHit  = New-LATParseResult -MatchedSignatures @('CCM-001') -ErrorCodes @([pscustomobject]@{ Code = '10'; Component = 'ccmsetup' })
            $prMiss = New-LATParseResult -MatchedSignatures @('CCM-001')
            (Test-LATRuleMatches -Rule $rule -ParseResult $prHit)  | Should -BeTrue
            (Test-LATRuleMatches -Rule $rule -ParseResult $prMiss) | Should -BeFalse
        }
    }

    Context 'Invoke-RuleEvaluator: empty / no-match cases' {

        It 'returns empty Verdicts on empty rulebase' {
            $r = Invoke-RuleEvaluator -ParseResult (New-LATParseResult) -Rules @()
            $r.MatchedCount | Should -Be 0
            @($r.Verdicts).Count | Should -Be 0
        }

        It 'returns empty Verdicts when no rule fires' {
            $rule = New-Rule -Id 'no-fire' -All @([pscustomobject]@{ signature = 'CCM-999' })
            $r = Invoke-RuleEvaluator -ParseResult (New-LATParseResult) -Rules @($rule)
            $r.MatchedCount | Should -Be 0
            $r.EvaluatedCount | Should -Be 1
        }
    }

    Context 'Invoke-RuleEvaluator: ranker' {

        It 'ranks higher confidence first when specificity is equal' {
            $low  = New-Rule -Id 'low'  -Confidence 70 -All @([pscustomobject]@{ signature = 'CCM-001' })
            $high = New-Rule -Id 'high' -Confidence 95 -All @([pscustomobject]@{ signature = 'CCM-001' })
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules @($low, $high)
            $r.Verdicts[0].RuleId | Should -Be 'high'
            $r.Verdicts[1].RuleId | Should -Be 'low'
        }

        It 'ranks higher specificity first when confidence is equal' {
            $thin  = New-Rule -Id 'thin'  -Confidence 80 -All @([pscustomobject]@{ signature = 'CCM-001' })
            $thick = New-Rule -Id 'thick' -Confidence 80 -All @(
                [pscustomobject]@{ signature = 'CCM-001' },
                [pscustomobject]@{ signature = 'CERT-001' }
            )
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001', 'CERT-001')
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules @($thin, $thick)
            $r.Verdicts[0].RuleId | Should -Be 'thick'
        }

        It 'breaks ties alphabetically by RuleId for full determinism' {
            $a = New-Rule -Id 'aaa-rule' -Confidence 80 -All @([pscustomobject]@{ signature = 'CCM-001' })
            $z = New-Rule -Id 'zzz-rule' -Confidence 80 -All @([pscustomobject]@{ signature = 'CCM-001' })
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules @($z, $a)
            $r.Verdicts[0].RuleId | Should -Be 'aaa-rule'
        }

        It 'honors TopN' {
            $rules = 1..5 | ForEach-Object {
                New-Rule -Id "rule-$_" -Confidence (60 + $_) -All @([pscustomobject]@{ signature = 'CCM-001' })
            }
            $pr = New-LATParseResult -MatchedSignatures @('CCM-001')
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules $rules -TopN 2
            $r.Verdicts.Count | Should -Be 2
            $r.AllMatches.Count | Should -Be 5
        }
    }

    Context 'Resolve-LATEvidence' {

        It 'attaches the first matching entry message + component' {
            $rule = New-Rule -Id 'r' -All @([pscustomobject]@{ signature = 'CCM-001' }) `
                -Evidence @([pscustomobject]@{ component = 'ccmsetup'; match = 'verify the authenticity' })
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'Failed to verify the authenticity of the MP cert' -SignatureId 'CCM-001')
            )
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules @($rule)
            $r.Verdicts[0].EvidenceLines[0].Message | Should -Match 'verify the authenticity'
            $r.Verdicts[0].EvidenceLines[0].Component | Should -Be 'ccmsetup'
        }

        It 'falls back to the entry that satisfied a signature condition when the curated pattern misses' {
            # When the curated evidence[].match does not appear in the
            # bundle (common as MS rephrases CMTrace messages between
            # client builds), the resolver synthesizes evidence from
            # the entries that satisfied the rule's when.all conditions.
            # Condition hits ARE evidence by definition.  No placeholder
            # ever appears on the verdict card.
            $rule = New-Rule -Id 'r' -All @([pscustomobject]@{ signature = 'CCM-001' }) `
                -Evidence @([pscustomobject]@{ component = 'ccmsetup'; match = 'this string is not in the bundle' })
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'unrelated chatter that satisfies CCM-001' -SignatureId 'CCM-001')
            )
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules @($rule)
            @($r.Verdicts[0].EvidenceLines).Count | Should -BeGreaterThan 0
            $r.Verdicts[0].EvidenceLines[0].Message | Should -Not -Match 'evidence pattern not located'
            $r.Verdicts[0].EvidenceLines[0].Message | Should -Be 'unrelated chatter that satisfies CCM-001'
            $r.Verdicts[0].EvidenceLines[0].Component | Should -Be 'ccmsetup'
        }

        It 'falls back to the entry that satisfied an errorCode condition' {
            $rule = New-Rule -Id 'r2' `
                -All @([pscustomobject]@{ errorCode = '0x80072EE7' }) `
                -Evidence @([pscustomobject]@{ component = 'ccmsetup'; match = 'phrase that does not appear' })
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'transport error 0x80072EE7 against MP' -ErrorCode '0x80072EE7')
            )
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules @($rule)
            $r.Verdicts[0].EvidenceLines[0].Message | Should -Not -Match 'evidence pattern not located'
            $r.Verdicts[0].EvidenceLines[0].Message | Should -Match '0x80072EE7'
        }

        It 'never emits the (evidence pattern not located ...) placeholder' {
            # Anchor against the regression: the placeholder was a bug
            # in the original resolver and must never reappear.
            $rule = New-Rule -Id 'r3' `
                -All @([pscustomobject]@{ signature = 'CCM-002' }) `
                -Evidence @(
                    [pscustomobject]@{ component = 'ccmsetup'; match = 'unrelated 1' }
                    [pscustomobject]@{ component = 'ccmsetup'; match = 'unrelated 2' }
                )
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'satisfies CCM-002' -SignatureId 'CCM-002')
            )
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules @($rule)
            foreach ($line in $r.Verdicts[0].EvidenceLines) {
                $line.Message | Should -Not -Match 'evidence pattern not located'
            }
        }
    }

    Context 'Get-LATRules: loader + local-overlay precedence' {

        BeforeAll {
            $script:TempBaseline = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-eval-baseline-" + [guid]::NewGuid())
            $script:TempLocal    = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-eval-local-"    + [guid]::NewGuid())
            $null = New-Item -ItemType Directory -Path $script:TempBaseline
            $null = New-Item -ItemType Directory -Path $script:TempLocal

            $baselineRule = @{
                id         = 'shared-id'
                scope      = 'ClientInstall'
                confidence = 70
                version    = '1.0'
                source     = 'baseline'
                when       = @{ all = @( @{ signature = 'CCM-001' } ) }
                verdict    = 'Baseline-version verdict.'
                fix        = 'Baseline fix steps.'
            } | ConvertTo-Json -Depth 8
            Set-Content -Path (Join-Path $script:TempBaseline 'shared-id.json') -Value $baselineRule -Encoding UTF8

            $localRule = @{
                id         = 'shared-id'
                scope      = 'ClientInstall'
                confidence = 95
                version    = '1.1'
                source     = 'local'
                when       = @{ all = @( @{ signature = 'CCM-001' } ) }
                verdict    = 'LOCAL-version verdict.'
                fix        = 'Local fix steps.'
            } | ConvertTo-Json -Depth 8
            Set-Content -Path (Join-Path $script:TempLocal 'shared-id.json') -Value $localRule -Encoding UTF8

            $invalidRule = '{ "id": "broken", "scope": "BadScope" }'
            Set-Content -Path (Join-Path $script:TempBaseline 'broken.json') -Value $invalidRule -Encoding UTF8
        }

        AfterAll {
            Remove-Item $script:TempBaseline -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item $script:TempLocal    -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'loads baseline rules from a directory' {
            $rules = @(Get-LATRules -BaselinePath $script:TempBaseline -WarningAction SilentlyContinue)
            @($rules | Where-Object { $_.id -eq 'shared-id' }).Count | Should -Be 1
        }

        It 'skips invalid rule files with a warning, not a throw' {
            $rules = @(Get-LATRules -BaselinePath $script:TempBaseline -WarningAction SilentlyContinue)
            @($rules | Where-Object { $_.id -eq 'broken' }).Count | Should -Be 0
        }

        It 'local overlay wins on id collision' {
            $rules = @(Get-LATRules -BaselinePath $script:TempBaseline -LocalPath $script:TempLocal -WarningAction SilentlyContinue)
            $shared = @($rules | Where-Object { $_.id -eq 'shared-id' })
            $shared.Count | Should -Be 1
            $shared[0].confidence | Should -Be 95
            $shared[0].verdict    | Should -Match 'LOCAL'
        }
    }

    Context 'Smoke: real baseline rule fires on a composed bundle' {

        It 'fires mp-cert-chain-mismatch when the right signatures are present' {
            $rules = @(Get-LATRules -BaselinePath $script:BaselineRoot -WarningAction SilentlyContinue)
            $rules.Count | Should -BeGreaterOrEqual 5
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'Failed to verify the authenticity of the MP HTTPS chain' -SignatureId 'CCM-001'),
                (New-FakeEntry -Component 'ClientIDManagerStartup' -Message 'certificate validation failed for MP' -SignatureId 'CERT-001' -LogFile 'ClientIDManagerStartup.log')
            )
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules $rules
            $top = $r.Verdicts[0]
            $top.RuleId | Should -Be 'mp-cert-chain-mismatch'
            $top.Verdict | Should -Match 'certificate'
            $top.EvidenceLines.Count | Should -BeGreaterThan 0
        }

        It 'suppresses mp-cert-chain-mismatch when the DNS-001 negative guard fires' {
            $rules = @(Get-LATRules -BaselinePath $script:BaselineRoot -WarningAction SilentlyContinue)
            $pr = New-LATParseResult -Entries @(
                (New-FakeEntry -Component 'ccmsetup' -Message 'Failed to verify the authenticity' -SignatureId 'CCM-001'),
                (New-FakeEntry -Component 'ClientIDManagerStartup' -Message 'certificate validation failed' -SignatureId 'CERT-001'),
                (New-FakeEntry -Component 'ccmsetup' -Message 'failed to resolve MP FQDN' -SignatureId 'DNS-001')
            )
            $r = Invoke-RuleEvaluator -ParseResult $pr -Rules $rules
            @($r.AllMatches | Where-Object { $_.RuleId -eq 'mp-cert-chain-mismatch' }).Count | Should -Be 0
        }
    }
}
