# Invoke-RuleEvaluator.ps1
#
# LAT decision-engine evaluator. Loads a rulebase, evaluates each rule
# against a parsed log bundle, ranks the matches, and returns verdicts
# (verdict + evidence + fix). Mirrors the contract documented in
# brain/docs/lat-decision-engine-kickstart.md section 5 / Track A.
#
# Loaded by: Tests/Invoke-RuleEvaluator.Tests.ps1, and (Session 11) by
# the WPF triage module.

Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

function Get-LATProperty {
    # PS 5.1 strict-mode-safe property access. Returns $Default if the
    # property is missing on the object.
    param(
        $Object,
        [string]$Name,
        $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

function Get-LATArrayProperty {
    param(
        $Object,
        [string]$Name
    )
    $v = Get-LATProperty -Object $Object -Name $Name -Default @()
    return @($v)
}

# ---------------------------------------------------------------------------
# ParseResult builder (test-friendly; production use composes this from the
# existing parse + signature + cluster + probe layer)
# ---------------------------------------------------------------------------

function New-LATParseResult {
    <#
    .SYNOPSIS
        Build a ParseResult object for the evaluator.
    .DESCRIPTION
        Convenience constructor. Accepts entries (post-signature-detection
        log lines) and optional already-summarized derived inputs. Missing
        derived inputs are auto-derived from entries where possible.
    #>
    param(
        $Entries = @(),
        $MatchedSignatures = $null,
        $ErrorCodes = $null,
        $Probes = $null,
        $Clusters = $null
    )
    $entriesArr = @($Entries)
    if ($null -eq $MatchedSignatures) {
        $MatchedSignatures = @($entriesArr |
            Where-Object { (Get-LATProperty $_ 'SignatureId') } |
            ForEach-Object { $_.SignatureId } |
            Select-Object -Unique)
    }
    if ($null -eq $ErrorCodes) {
        $ErrorCodes = @()
        foreach ($e in $entriesArr) {
            $ec = Get-LATProperty $e 'ErrorCode'
            if ($ec) {
                $ErrorCodes += [pscustomobject]@{
                    Code      = [string]$ec
                    Component = (Get-LATProperty $e 'Component' '')
                }
            }
        }
    }
    if ($null -eq $Probes) { $Probes = @() }
    if ($null -eq $Clusters) { $Clusters = @() }
    return [pscustomobject]@{
        Entries           = $entriesArr
        MatchedSignatures = @($MatchedSignatures)
        ErrorCodes        = @($ErrorCodes)
        Probes            = @($Probes)
        Clusters          = @($Clusters)
    }
}

# ---------------------------------------------------------------------------
# Condition evaluation
# ---------------------------------------------------------------------------

function Test-LATConditionMatch {
    <#
    .SYNOPSIS
        Evaluate a single condition against a ParseResult. Returns $true
        when the condition is satisfied.
    .NOTES
        Discriminator priority matches Test-LATRule.ps1: timeGap, cluster,
        probe, signature, errorCode, component.
    #>
    param(
        [Parameter(Mandatory)] $Condition,
        [Parameter(Mandatory)] $ParseResult
    )
    $names = @($Condition.PSObject.Properties.Name)
    if ($names -contains 'timeGap') {
        $tg = $Condition.timeGap
        $from = $tg.fromSignature
        $to   = $tg.toSignature
        $maxSec = [int]$tg.maxSec
        $fromEntries = @($ParseResult.Entries | Where-Object { (Get-LATProperty $_ 'SignatureId') -eq $from })
        $toEntries   = @($ParseResult.Entries | Where-Object { (Get-LATProperty $_ 'SignatureId') -eq $to })
        foreach ($a in $fromEntries) {
            foreach ($b in $toEntries) {
                $aT = Get-LATProperty $a 'DateTime'
                $bT = Get-LATProperty $b 'DateTime'
                if ($null -eq $aT -or $null -eq $bT) { continue }
                if ($aT -le $bT -and ($bT - $aT).TotalSeconds -le $maxSec) {
                    return $true
                }
            }
        }
        return $false
    }
    if ($names -contains 'cluster') {
        return @($ParseResult.Clusters) -contains $Condition.cluster
    }
    if ($names -contains 'probe') {
        $needName = $Condition.probe
        $needRes  = Get-LATProperty $Condition 'result' $null
        foreach ($p in @($ParseResult.Probes)) {
            $pName = Get-LATProperty $p 'Name'
            if ($pName -ne $needName) { continue }
            if ($null -eq $needRes) { return $true }
            $pRes = Get-LATProperty $p 'Result'
            if ($pRes -eq $needRes) { return $true }
        }
        return $false
    }
    if ($names -contains 'signature') {
        return @($ParseResult.MatchedSignatures) -contains $Condition.signature
    }
    if ($names -contains 'errorCode') {
        $needCode = [string]$Condition.errorCode
        $needComp = Get-LATProperty $Condition 'component' $null
        foreach ($ec in @($ParseResult.ErrorCodes)) {
            $code = [string](Get-LATProperty $ec 'Code')
            if ($code -ne $needCode) { continue }
            if ($null -eq $needComp) { return $true }
            $comp = [string](Get-LATProperty $ec 'Component' '')
            if ($comp -ieq $needComp) { return $true }
        }
        return $false
    }
    if (($names -contains 'component') -and ($names -contains 'pattern')) {
        $needComp = $Condition.component
        $rx = [regex]::new($Condition.pattern)
        foreach ($e in $ParseResult.Entries) {
            $comp = [string](Get-LATProperty $e 'Component' '')
            if ($comp -ine $needComp) { continue }
            $msg = [string](Get-LATProperty $e 'Message' '')
            if ($rx.IsMatch($msg)) { return $true }
        }
        return $false
    }
    # Unknown condition shape - treat as non-matching rather than throwing,
    # so a malformed local-overlay rule does not crash a triage session.
    return $false
}

# ---------------------------------------------------------------------------
# Rule evaluation, scoring, and ranking
# ---------------------------------------------------------------------------

function Get-LATRuleSpecificity {
    <#
    .SYNOPSIS
        Specificity score for a matched rule. Drives the ranker tie-break.
    #>
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] $ParseResult
    )
    $when = $Rule.when
    $allCount  = @(Get-LATArrayProperty $when 'all').Count
    $noneCount = @(Get-LATArrayProperty $when 'none').Count
    $anyMatched = 0
    foreach ($c in @(Get-LATArrayProperty $when 'any')) {
        if (Test-LATConditionMatch -Condition $c -ParseResult $ParseResult) {
            $anyMatched++
        }
    }
    return ($allCount + (0.5 * $anyMatched) + (0.5 * $noneCount))
}

function Test-LATRuleMatches {
    <#
    .SYNOPSIS
        Returns $true if the rule fires against the ParseResult:
        ALL of when.all AND NONE of when.none AND
        (when.any empty OR ANY of when.any).
    #>
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] $ParseResult
    )
    $when = $Rule.when
    foreach ($c in @(Get-LATArrayProperty $when 'all')) {
        if (-not (Test-LATConditionMatch -Condition $c -ParseResult $ParseResult)) {
            return $false
        }
    }
    foreach ($c in @(Get-LATArrayProperty $when 'none')) {
        if (Test-LATConditionMatch -Condition $c -ParseResult $ParseResult) {
            return $false
        }
    }
    $any = @(Get-LATArrayProperty $when 'any')
    if ($any.Count -gt 0) {
        $anyHit = $false
        foreach ($c in $any) {
            if (Test-LATConditionMatch -Condition $c -ParseResult $ParseResult) {
                $anyHit = $true
                break
            }
        }
        if (-not $anyHit) { return $false }
    }
    return $true
}

function Resolve-LATEvidence {
    <#
    .SYNOPSIS
        Resolve a rule's evidence shortlist into concrete log lines from
        the ParseResult.

    .DESCRIPTION
        Two-pass resolution.  Pass 1 walks the rule's curated
        `evidence[]` patterns and tries to find each in the parsed
        entries.  Pass 2 falls back to entries that satisfied the
        rule's when.all conditions when Pass 1 fails to find anything;
        condition hits ARE evidence by definition, so an unfound
        curated pattern never leaves the verdict card empty.

        Curated evidence patterns drift over time as Microsoft
        rephrases CMTrace messages between client builds; the fallback
        keeps verdicts useful even when curated lines fail to match.
    #>
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] $ParseResult,
        [int]$MaxEvidence = 3
    )
    $resolved = New-Object System.Collections.Generic.List[object]
    $usedKeys = @{}
    function _AddHit {
        param($Entry, $List, $Used)
        if ($null -eq $Entry) { return }
        $key = "{0}|{1}|{2}" -f `
            ([string](Get-LATProperty $Entry 'Component' '')), `
            ([string](Get-LATProperty $Entry 'LogFile' '')), `
            ([string](Get-LATProperty $Entry 'Message' ''))
        if ($Used.ContainsKey($key)) { return }
        $Used[$key] = $true
        $List.Add([pscustomobject]@{
            Component = [string](Get-LATProperty $Entry 'Component' '')
            DateTime  = (Get-LATProperty $Entry 'DateTime' $null)
            Message   = [string](Get-LATProperty $Entry 'Message' '')
            LogFile   = [string](Get-LATProperty $Entry 'LogFile' '')
        })
    }

    # Pass 1: curated evidence patterns.
    foreach ($ev in @(Get-LATArrayProperty $Rule 'evidence')) {
        if ($resolved.Count -ge $MaxEvidence) { break }
        $needComp = Get-LATProperty $ev 'component' $null
        $needMatch = [string](Get-LATProperty $ev 'match' '')
        if ([string]::IsNullOrWhiteSpace($needMatch)) { continue }
        $isRegex = [bool](Get-LATProperty $ev 'isRegex' $false)
        $rx = $null
        if ($isRegex) {
            try { $rx = [regex]::new($needMatch) } catch { $rx = $null }
        }
        $hit = $null
        foreach ($e in $ParseResult.Entries) {
            if ($needComp) {
                $comp = [string](Get-LATProperty $e 'Component' '')
                if ($comp -ine $needComp) { continue }
            }
            $msg = [string](Get-LATProperty $e 'Message' '')
            $matched = $false
            if ($rx) {
                $matched = $rx.IsMatch($msg)
            } else {
                $matched = $msg.IndexOf($needMatch, [StringComparison]::OrdinalIgnoreCase) -ge 0
            }
            if ($matched) { $hit = $e; break }
        }
        # Curated pattern miss: no placeholder.  Fallback below covers it.
        _AddHit -Entry $hit -List $resolved -Used $usedKeys
    }

    # Pass 2: synthesize from entries that satisfied when.all conditions.
    # Engaged when curated patterns produced fewer than MaxEvidence hits
    # OR found nothing at all.  Walks the matched conditions in order and
    # picks the first concrete entry that proves each one.
    if ($resolved.Count -lt $MaxEvidence) {
        $when = Get-LATProperty $Rule 'when' $null
        if ($when) {
            foreach ($c in @(Get-LATArrayProperty $when 'all')) {
                if ($resolved.Count -ge $MaxEvidence) { break }
                $names = @($c.PSObject.Properties.Name)
                $hit = $null
                if ($names -contains 'signature') {
                    $sigId = [string]$c.signature
                    foreach ($e in $ParseResult.Entries) {
                        if ((Get-LATProperty $e 'SignatureId') -eq $sigId) { $hit = $e; break }
                    }
                } elseif ($names -contains 'errorCode') {
                    $needCode = [string]$c.errorCode
                    $needComp = Get-LATProperty $c 'component' $null
                    foreach ($e in $ParseResult.Entries) {
                        if ((Get-LATProperty $e 'ErrorCode') -ne $needCode) { continue }
                        if ($needComp) {
                            $comp = [string](Get-LATProperty $e 'Component' '')
                            if ($comp -ine $needComp) { continue }
                        }
                        $hit = $e; break
                    }
                } elseif (($names -contains 'component') -and ($names -contains 'pattern')) {
                    $needComp = [string]$c.component
                    $rx = $null
                    try { $rx = [regex]::new($c.pattern) } catch { }
                    if ($rx) {
                        foreach ($e in $ParseResult.Entries) {
                            $comp = [string](Get-LATProperty $e 'Component' '')
                            if ($comp -ine $needComp) { continue }
                            $msg = [string](Get-LATProperty $e 'Message' '')
                            if ($rx.IsMatch($msg)) { $hit = $e; break }
                        }
                    }
                }
                _AddHit -Entry $hit -List $resolved -Used $usedKeys
            }
        }
    }
    return $resolved.ToArray()
}

function Compare-LATMatch {
    # Sort comparator. Returns negative if A ranks higher (sorted first).
    param($A, $B)
    if ($A.Score -ne $B.Score)             { return ($B.Score - $A.Score) }
    if ($A.Specificity -ne $B.Specificity) { return ($B.Specificity - $A.Specificity) }
    if ($A.Confidence -ne $B.Confidence)   { return ($B.Confidence - $A.Confidence) }
    return [string]::Compare($A.RuleId, $B.RuleId, [StringComparison]::OrdinalIgnoreCase)
}

# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------

function Get-LATRules {
    <#
    .SYNOPSIS
        Load the rulebase. Baseline rules first, then local-overlay rules.
        Local-overlay always wins on ID collision regardless of source.
    .PARAMETER BaselinePath
        Directory or file paths searched recursively for *.json baseline rules.
    .PARAMETER LocalPath
        Directory or file paths for the local overlay (typically
        $env:LOCALAPPDATA\LogAnalyzer\rules).
    .PARAMETER ValidatorPath
        Optional override path to Module/Test-LATRule.ps1. Auto-detected
        from $PSScriptRoot when omitted.
    .OUTPUTS
        Array of validated rule objects. Invalid rule files are skipped
        and reported via Write-Warning.
    #>
    [CmdletBinding()]
    param(
        [string[]]$BaselinePath = @(),
        [string[]]$LocalPath    = @(),
        [string]  $ValidatorPath = $null
    )
    if (-not $ValidatorPath) {
        $ValidatorPath = Join-Path $PSScriptRoot 'Test-LATRule.ps1'
    }
    if (Test-Path $ValidatorPath) { . $ValidatorPath }

    $byId = [ordered]@{}
    function _LoadFrom {
        param([string[]]$Paths, [string]$Source, $Acc)
        foreach ($p in $Paths) {
            if ([string]::IsNullOrWhiteSpace($p) -or -not (Test-Path $p)) { continue }
            $files = if ((Get-Item $p).PSIsContainer) {
                Get-ChildItem -Path $p -Recurse -Filter *.json -ErrorAction SilentlyContinue
            } else {
                Get-Item -Path $p
            }
            foreach ($f in @($files)) {
                $rule = $null
                try {
                    $rule = Get-Content -Path $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
                } catch {
                    Write-Warning "Get-LATRules: $($f.Name) is not valid JSON ($($_.Exception.Message))"
                    continue
                }
                $r = Test-LATRule -Rule $rule -Path $f.Name
                if (-not $r.Valid) {
                    Write-Warning "Get-LATRules: $($f.Name) failed schema validation:`n  $($r.Errors -join "`n  ")"
                    continue
                }
                if (-not (Get-LATProperty $rule 'source')) {
                    $rule | Add-Member -NotePropertyName source -NotePropertyValue $Source -Force
                }
                $Acc[$rule.id] = $rule
            }
        }
    }
    _LoadFrom -Paths $BaselinePath -Source 'baseline' -Acc $byId
    _LoadFrom -Paths $LocalPath    -Source 'local'    -Acc $byId
    return @($byId.Values)
}

function Invoke-RuleEvaluator {
    <#
    .SYNOPSIS
        Evaluate a rulebase against a ParseResult and return ranked verdicts.
    .DESCRIPTION
        Per kickstart Track A pseudocode:
          1. Take loaded rules + ParseResult.
          2. Evaluate when.all AND !when.none AND (empty(any) OR any).
          3. Score each match: Score = Confidence * Specificity * Recency.
          4. Sort descending; tie-break by Specificity, Confidence, then RuleId.
          5. Return TopN as Verdicts plus the full sorted AllMatches.
          6. Resolve evidence[] against ParseResult.Entries.
    .PARAMETER ParseResult
        Object produced by New-LATParseResult or by the parse pipeline.
    .PARAMETER Rules
        Array of validated rule objects (from Get-LATRules or test fixtures).
    .PARAMETER TopN
        How many ranked matches to surface as Verdicts. Default 3.
    .OUTPUTS
        PSCustomObject with Verdicts, AllMatches, MatchedCount, EvaluatedCount.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ParseResult,
        [Parameter(Mandatory)] $Rules,
        [int] $TopN = 3
    )
    if ($null -eq $ParseResult) { throw 'ParseResult is required.' }
    $rulesArr = @($Rules)
    $matches = New-Object System.Collections.Generic.List[object]
    foreach ($rule in $rulesArr) {
        if (-not (Test-LATRuleMatches -Rule $rule -ParseResult $ParseResult)) { continue }
        $spec = Get-LATRuleSpecificity -Rule $rule -ParseResult $ParseResult
        $conf = [int]$rule.confidence
        $score = [double]$conf * [double]$spec
        $evidence = Resolve-LATEvidence -Rule $rule -ParseResult $ParseResult
        $matches.Add([pscustomobject]@{
            RuleId        = $rule.id
            Scope         = $rule.scope
            Source        = (Get-LATProperty $rule 'source' 'baseline')
            Verdict       = $rule.verdict
            Fix           = $rule.fix
            Confidence    = $conf
            Specificity   = $spec
            Score         = $score
            EvidenceLines = $evidence
            References    = @(Get-LATArrayProperty $rule 'references')
        })
    }
    # Sort using the comparator (Sort-Object -Property handles ties by
    # secondary keys, but Score is double + we want a fully-defined order).
    $sorted = @($matches | Sort-Object -Property `
        @{ Expression = 'Score';       Descending = $true }, `
        @{ Expression = 'Specificity'; Descending = $true }, `
        @{ Expression = 'Confidence';  Descending = $true }, `
        @{ Expression = 'RuleId';      Descending = $false })
    $top = if ($sorted.Count -gt 0) { @($sorted | Select-Object -First $TopN) } else { @() }
    return [pscustomobject]@{
        Verdicts       = $top
        AllMatches     = $sorted
        MatchedCount   = $sorted.Count
        EvaluatedCount = $rulesArr.Count
    }
}
