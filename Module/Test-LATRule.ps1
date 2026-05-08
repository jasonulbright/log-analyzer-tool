# Test-LATRule.ps1
#
# Structural validator for LAT decision-engine rules. Mirrors
# Rules/Schema/rule.schema.json. Hand-rolled because PowerShell 5.1 has no
# native JSON-schema validator and the LAT project gate forbids vendoring
# Newtonsoft.Json.Schema.
#
# Loaded by Tests/RuleSchema.Tests.ps1 and (Session 3) by
# Invoke-RuleEvaluator.ps1.

Set-StrictMode -Version Latest

$script:LATRule_AllowedScopes        = @('App', 'SoftwareUpdate', 'ClientInstall', 'CrossScope')
$script:LATRule_AllowedSources       = @('baseline', 'local', 'community')
$script:LATRule_AllowedRoles         = @('root', 'trigger', 'symptom', 'consequence')
$script:LATRule_RequiredTopFields    = @('id', 'scope', 'confidence', 'version', 'when', 'verdict', 'fix')
$script:LATRule_AllowedTopFields     = @('id', 'scope', 'confidence', 'version', 'authoredAt', 'authoredBy', 'source', 'when', 'causalOrder', 'verdict', 'evidence', 'fix', 'references')
$script:LATRule_IdPattern            = '^[a-z0-9]+(-[a-z0-9]+)*$'
$script:LATRule_VersionPattern       = '^\d+\.\d+$'
$script:LATRule_ConditionDiscriminators = @('signature', 'errorCode', 'probe', 'cluster', 'component', 'timeGap')

function Get-LATRulePropertyNames {
    param($Object)
    if ($null -eq $Object) { return @() }
    @($Object.PSObject.Properties | ForEach-Object { $_.Name })
}

function Test-LATRuleCondition {
    param(
        $Condition,
        [string]$Path
    )
    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Condition) {
        $errors.Add("${Path}: condition is null")
        return $errors
    }
    $names = Get-LATRulePropertyNames -Object $Condition
    # Resolve the discriminator by priority. `component` appears as both
    # a sub-property of errorCode-conditions AND as the head of
    # component+pattern conditions, so order matters here.
    $type = $null
    if ($names -contains 'timeGap')                                      { $type = 'timeGap' }
    elseif ($names -contains 'cluster')                                  { $type = 'cluster' }
    elseif ($names -contains 'probe')                                    { $type = 'probe' }
    elseif ($names -contains 'signature')                                { $type = 'signature' }
    elseif ($names -contains 'errorCode')                                { $type = 'errorCode' }
    elseif (($names -contains 'component') -and ($names -contains 'pattern')) { $type = 'component' }
    elseif ($names -contains 'component') {
        $errors.Add("${Path}: component condition requires 'pattern'")
        return $errors
    }
    if ($null -eq $type) {
        $errors.Add("${Path}: condition has no recognized discriminator (expected one of: $($script:LATRule_ConditionDiscriminators -join ', '))")
        return $errors
    }
    switch ($type) {
        'signature' {
            $allowed = @('signature')
            if ($Condition.signature -isnot [string] -or [string]::IsNullOrWhiteSpace($Condition.signature)) {
                $errors.Add("$Path.signature: must be a non-empty string")
            }
        }
        'errorCode' {
            $allowed = @('errorCode', 'component')
            if ($Condition.errorCode -isnot [string] -or [string]::IsNullOrWhiteSpace($Condition.errorCode)) {
                $errors.Add("$Path.errorCode: must be a non-empty string")
            }
        }
        'probe' {
            $allowed = @('probe', 'result')
            if ($Condition.probe -isnot [string] -or [string]::IsNullOrWhiteSpace($Condition.probe)) {
                $errors.Add("$Path.probe: must be a non-empty string")
            }
        }
        'cluster' {
            $allowed = @('cluster')
            if ($Condition.cluster -isnot [string] -or [string]::IsNullOrWhiteSpace($Condition.cluster)) {
                $errors.Add("$Path.cluster: must be a non-empty string")
            }
        }
        'component' {
            $allowed = @('component', 'pattern')
            if ($Condition.component -isnot [string] -or [string]::IsNullOrWhiteSpace($Condition.component)) {
                $errors.Add("$Path.component: must be a non-empty string")
            }
            if (-not ($names -contains 'pattern')) {
                $errors.Add("${Path}: component condition requires 'pattern'")
            } elseif ($Condition.pattern -isnot [string] -or [string]::IsNullOrWhiteSpace($Condition.pattern)) {
                $errors.Add("$Path.pattern: must be a non-empty string")
            } else {
                try { [void][regex]::new($Condition.pattern) }
                catch { $errors.Add("$Path.pattern: invalid regex ($($_.Exception.Message))") }
            }
        }
        'timeGap' {
            $allowed = @('timeGap')
            $tg = $Condition.timeGap
            if ($null -eq $tg) {
                $errors.Add("$Path.timeGap: must be an object")
            } else {
                $tgNames = Get-LATRulePropertyNames -Object $tg
                foreach ($req in @('fromSignature', 'toSignature', 'maxSec')) {
                    if (-not ($tgNames -contains $req)) {
                        $errors.Add("$Path.timeGap: missing required field '$req'")
                    }
                }
                if (($tgNames -contains 'maxSec') -and ($tg.maxSec -isnot [int] -and $tg.maxSec -isnot [long])) {
                    $errors.Add("$Path.timeGap.maxSec: must be an integer")
                } elseif (($tgNames -contains 'maxSec') -and $tg.maxSec -lt 0) {
                    $errors.Add("$Path.timeGap.maxSec: must be >= 0")
                }
            }
        }
    }
    $extra = @($names | Where-Object { $allowed -notcontains $_ })
    foreach ($ex in $extra) {
        $errors.Add("${Path}: unexpected property '$ex' for $type-condition")
    }
    return $errors
}

function Test-LATRule {
    <#
    .SYNOPSIS
        Validate a parsed LAT rule object against the rule schema.
    .DESCRIPTION
        Pass the result of `Get-Content rule.json -Raw | ConvertFrom-Json`.
        Returns a result object with Valid (bool) and Errors (string[]).
        Mirrors Rules/Schema/rule.schema.json.
    .PARAMETER Rule
        The parsed rule object (PSCustomObject).
    .PARAMETER Path
        Optional source path for error messages. Defaults to '<rule>'.
    .OUTPUTS
        PSCustomObject @{ Valid; Errors }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Rule,
        [string]$Path = '<rule>'
    )
    $errors = New-Object System.Collections.Generic.List[string]
    if ($null -eq $Rule) {
        $errors.Add("${Path}: rule is null")
        return [pscustomobject]@{ Valid = $false; Errors = $errors.ToArray() }
    }
    $names = Get-LATRulePropertyNames -Object $Rule
    foreach ($req in $script:LATRule_RequiredTopFields) {
        if (-not ($names -contains $req)) {
            $errors.Add("${Path}: missing required field '$req'")
        }
    }
    foreach ($n in $names) {
        if ($script:LATRule_AllowedTopFields -notcontains $n) {
            $errors.Add("${Path}: unexpected property '$n'")
        }
    }
    if (($names -contains 'id') -and ($Rule.id -is [string])) {
        if ($Rule.id -notmatch $script:LATRule_IdPattern) {
            $errors.Add("$Path.id: '$($Rule.id)' does not match kebab-case pattern $script:LATRule_IdPattern")
        }
        if ($Rule.id.Length -lt 3 -or $Rule.id.Length -gt 80) {
            $errors.Add("$Path.id: length must be 3..80")
        }
    }
    if (($names -contains 'scope') -and ($script:LATRule_AllowedScopes -notcontains $Rule.scope)) {
        $errors.Add("$Path.scope: '$($Rule.scope)' not in $($script:LATRule_AllowedScopes -join ', ')")
    }
    if ($names -contains 'confidence') {
        if ($Rule.confidence -isnot [int] -and $Rule.confidence -isnot [long]) {
            $errors.Add("$Path.confidence: must be an integer")
        } elseif ($Rule.confidence -lt 0 -or $Rule.confidence -gt 100) {
            $errors.Add("$Path.confidence: must be 0..100")
        }
    }
    if (($names -contains 'version') -and ($Rule.version -isnot [string] -or $Rule.version -notmatch $script:LATRule_VersionPattern)) {
        $errors.Add("$Path.version: must match $script:LATRule_VersionPattern")
    }
    if (($names -contains 'source') -and ($script:LATRule_AllowedSources -notcontains $Rule.source)) {
        $errors.Add("$Path.source: '$($Rule.source)' not in $($script:LATRule_AllowedSources -join ', ')")
    }
    if ($names -contains 'when') {
        $when = $Rule.when
        if ($null -eq $when) {
            $errors.Add("$Path.when: must be an object")
        } else {
            $whenNames = Get-LATRulePropertyNames -Object $when
            foreach ($wn in $whenNames) {
                if (@('all','any','none') -notcontains $wn) {
                    $errors.Add("$Path.when: unexpected property '$wn'")
                }
            }
            if (-not ($whenNames -contains 'all')) {
                $errors.Add("$Path.when: missing required 'all'")
            } else {
                $allArr = @($when.all)
                if ($allArr.Count -lt 1) {
                    $errors.Add("$Path.when.all: must contain at least one condition")
                }
                for ($i = 0; $i -lt $allArr.Count; $i++) {
                    foreach ($e in (Test-LATRuleCondition -Condition $allArr[$i] -Path "$Path.when.all[$i]")) {
                        $errors.Add($e)
                    }
                }
            }
            foreach ($section in @('any','none')) {
                if ($whenNames -contains $section) {
                    $arr = @($when.$section)
                    for ($i = 0; $i -lt $arr.Count; $i++) {
                        foreach ($e in (Test-LATRuleCondition -Condition $arr[$i] -Path "$Path.when.$section[$i]")) {
                            $errors.Add($e)
                        }
                    }
                }
            }
        }
    }
    if (($names -contains 'verdict') -and ($Rule.verdict -is [string])) {
        if ($Rule.verdict.Length -lt 10 -or $Rule.verdict.Length -gt 240) {
            $errors.Add("$Path.verdict: length must be 10..240 (got $($Rule.verdict.Length))")
        }
    }
    if (($names -contains 'fix') -and ($Rule.fix -is [string])) {
        if ($Rule.fix.Length -lt 10 -or $Rule.fix.Length -gt 600) {
            $errors.Add("$Path.fix: length must be 10..600 (got $($Rule.fix.Length))")
        }
    }
    if ($names -contains 'evidence') {
        $ev = @($Rule.evidence)
        if ($ev.Count -gt 5) {
            $errors.Add("$Path.evidence: max 5 items (got $($ev.Count))")
        }
        for ($i = 0; $i -lt $ev.Count; $i++) {
            $evNames = Get-LATRulePropertyNames -Object $ev[$i]
            foreach ($n in $evNames) {
                if (@('component','match','isRegex') -notcontains $n) {
                    $errors.Add("$Path.evidence[$i]: unexpected property '$n'")
                }
            }
            if (-not ($evNames -contains 'match')) {
                $errors.Add("$Path.evidence[$i]: missing required 'match'")
            } elseif ($ev[$i].match -isnot [string] -or [string]::IsNullOrWhiteSpace($ev[$i].match)) {
                $errors.Add("$Path.evidence[$i].match: must be a non-empty string")
            }
        }
    }
    if ($names -contains 'causalOrder') {
        $co = @($Rule.causalOrder)
        for ($i = 0; $i -lt $co.Count; $i++) {
            $coNames = Get-LATRulePropertyNames -Object $co[$i]
            if (-not ($coNames -contains 'role')) {
                $errors.Add("$Path.causalOrder[$i]: missing required 'role'")
            } elseif ($script:LATRule_AllowedRoles -notcontains $co[$i].role) {
                $errors.Add("$Path.causalOrder[$i].role: '$($co[$i].role)' not in $($script:LATRule_AllowedRoles -join ', ')")
            }
            $refKeys = @('signature','errorCode','probe','cluster')
            $refsPresent = @($coNames | Where-Object { $refKeys -contains $_ })
            if ($refsPresent.Count -ne 1) {
                $errors.Add("$Path.causalOrder[$i]: must reference exactly one of $($refKeys -join ', ') (found $($refsPresent.Count))")
            }
            foreach ($n in $coNames) {
                if (@('role','signature','errorCode','probe','cluster') -notcontains $n) {
                    $errors.Add("$Path.causalOrder[$i]: unexpected property '$n'")
                }
            }
        }
    }
    return [pscustomobject]@{ Valid = ($errors.Count -eq 0); Errors = $errors.ToArray() }
}
