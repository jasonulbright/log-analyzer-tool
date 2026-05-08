# LATRuleWizard.ps1
#
# Session 8: wizard data layer. Three entry points:
#
#   New-LATRuleDraft       -- pre-fill a rule draft from a ParseResult +
#                             EvalResult (last triage run).
#   Get-LATDraftPreview    -- run the draft against the current incident
#                             plus all stored incidents; report which
#                             fire, which don't, and which condition
#                             blocked each miss.
#   Show-LATRuleWizard     -- lightweight orchestrator. Runs the
#                             pre-fill, renders a preview table, optionally
#                             prompts (Read-Host) for verdict/fix/scope/
#                             confidence edits, returns the final draft.
#
# No WPF in this file. The visual wizard attaches in Session 11 when
# the WPF shell (Session 10) is in place; binding a WPF form to the
# draft object is trivial once the data layer is solid.
#
# This module depends on Invoke-RuleEvaluator.ps1 + LATIncident.ps1 +
# Test-LATRule.ps1 (dot-sourced by the caller or the test harness).

Set-StrictMode -Version Latest

$script:LATRuleWizard_DefaultConfidence = 70   # baseline floor per kickstart
$script:LATRuleWizard_DefaultEvidenceCount = 3
$script:LATRuleWizard_MaxEvidenceMatchLen = 80
$script:LATRuleWizard_ValidScopes = @('App', 'SoftwareUpdate', 'ClientInstall', 'CrossScope')

function Get-LATDraftScope {
    # Infer the analysis scope from the dominant signature ID family.
    # LAT signature prefixes: APP-*, WUA-*/SU-*, CCM-*. Everything else
    # (DP-*, DNS-*, WMI-*, CERT-*, POLICY-*, ACCESS-*, REBOOT-*, BITS-*,
    # CACHE-*) crosses scopes, so the draft defaults to CrossScope.
    param([string[]]$MatchedSignatures)
    if (-not $MatchedSignatures -or @($MatchedSignatures).Count -eq 0) {
        return 'CrossScope'
    }
    $counts = @{}
    foreach ($sig in $MatchedSignatures) {
        $scope = switch -Regex ($sig) {
            '^APP-'         { 'App';            break }
            '^(WUA|SU)-'    { 'SoftwareUpdate'; break }
            '^CCM-'         { 'ClientInstall';  break }
            default         { 'CrossScope' }
        }
        if (-not $counts.ContainsKey($scope)) { $counts[$scope] = 0 }
        $counts[$scope]++
    }
    # Pick the scope with the highest count; ties break toward non-CrossScope.
    $top = $counts.GetEnumerator() |
        Sort-Object @{ Expression = 'Value'; Descending = $true },
                    @{ Expression = { if ($_.Name -eq 'CrossScope') { 1 } else { 0 } } } |
        Select-Object -First 1
    return $top.Name
}

function New-LATRuleDraftId {
    # Generate an initial rule ID. Draft IDs are editable before save.
    # Format: draft-<primary-signal>-<8-char-guid>. Kebab-case per schema.
    param(
        [string[]]$MatchedSignatures,
        [object[]]$ErrorCodes
    )
    $hint = 'triage'
    if (@($MatchedSignatures).Count -gt 0) {
        $hint = ($MatchedSignatures[0] -replace '[^a-z0-9]+', '-').Trim('-').ToLowerInvariant()
    } elseif (@($ErrorCodes).Count -gt 0) {
        $code = [string](Get-LATProperty $ErrorCodes[0] 'Code' '')
        if ($code) { $hint = ($code -replace '[^a-z0-9]+', '').ToLowerInvariant() }
    }
    if (-not $hint) { $hint = 'triage' }
    if ($hint.Length -gt 30) { $hint = $hint.Substring(0, 30) }
    $short = [guid]::NewGuid().ToString('N').Substring(0, 8)
    return "draft-$hint-$short"
}

function New-LATRuleDraftEvidence {
    # Take up to N entries that matched either a signature or an error code,
    # sorted by DateTime (oldest first for causal reading), and project to
    # evidence[] shape.
    param(
        $Entries,
        [int]$MaxItems = $script:LATRuleWizard_DefaultEvidenceCount
    )
    $flagged = @($Entries | Where-Object {
        (Get-LATProperty $_ 'SignatureId') -or (Get-LATProperty $_ 'ErrorCode')
    })
    $sorted = @($flagged | Sort-Object { Get-LATProperty $_ 'DateTime' $([datetime]::MinValue) })
    $top = @($sorted | Select-Object -First $MaxItems)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($e in $top) {
        $msg = [string](Get-LATProperty $e 'Message' '')
        if ($msg.Length -gt $script:LATRuleWizard_MaxEvidenceMatchLen) {
            $msg = $msg.Substring(0, $script:LATRuleWizard_MaxEvidenceMatchLen).TrimEnd()
        }
        if ([string]::IsNullOrWhiteSpace($msg)) { continue }
        $out.Add([pscustomobject]@{
            component = [string](Get-LATProperty $e 'Component' '')
            match     = $msg
        })
    }
    return $out.ToArray()
}

function New-LATRuleDraft {
    <#
    .SYNOPSIS
        Generate a rule draft from a ParseResult + EvalResult, suitable for
        human refinement in the wizard.
    .PARAMETER ParseResult
        Output of New-LATParseResult / the parse pipeline.
    .PARAMETER EvalResult
        Output of Invoke-RuleEvaluator (optional; used to seed verdict text).
    .OUTPUTS
        PSCustomObject matching rule.schema.json. `source = 'local'`.
        IDs auto-generated; fields are editable by the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ParseResult,
        $EvalResult,
        [string]$AuthoredBy = $env:USERNAME
    )
    $sigs  = @($ParseResult.MatchedSignatures)
    $codes = @($ParseResult.ErrorCodes)
    $probes = @($ParseResult.Probes)
    $clusters = @($ParseResult.Clusters)

    $allConds = New-Object System.Collections.Generic.List[object]
    foreach ($s in $sigs) {
        $allConds.Add([pscustomobject]@{ signature = $s })
    }
    $seen = @{}
    foreach ($c in $codes) {
        $code = [string](Get-LATProperty $c 'Code' '')
        $comp = [string](Get-LATProperty $c 'Component' '')
        if (-not $code) { continue }
        $k = "$code|$comp"
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        $obj = [ordered]@{ errorCode = $code }
        if ($comp) { $obj.component = $comp }
        $allConds.Add([pscustomobject]$obj)
    }
    foreach ($cl in $clusters) {
        $allConds.Add([pscustomobject]@{ cluster = [string]$cl })
    }
    foreach ($p in $probes) {
        $pn = [string](Get-LATProperty $p 'Name' '')
        $pr = [string](Get-LATProperty $p 'Result' '')
        if (-not $pn) { continue }
        $obj = [ordered]@{ probe = $pn }
        if ($pr) { $obj.result = $pr }
        $allConds.Add([pscustomobject]$obj)
    }

    # Seed verdict from top match if the EvalResult carried one; else a
    # short placeholder that still meets the 10-char minLength.
    $verdict = 'Captured triage. Edit this verdict with the observed root cause.'
    if ($EvalResult) {
        $top = @(Get-LATProperty $EvalResult 'Verdicts' @())
        if ($top.Count -gt 0 -and (Get-LATProperty $top[0] 'Verdict')) {
            $verdict = [string]$top[0].Verdict
        }
    }

    $fix = 'Edit this fix text. List the remediation steps a responder would take.'
    $scope = Get-LATDraftScope -MatchedSignatures $sigs
    $id    = New-LATRuleDraftId -MatchedSignatures $sigs -ErrorCodes $codes
    $evidence = New-LATRuleDraftEvidence -Entries $ParseResult.Entries

    $draft = [pscustomobject]@{
        id         = $id
        scope      = $scope
        confidence = $script:LATRuleWizard_DefaultConfidence
        version    = '1.0'
        authoredAt = (Get-Date -Format 'yyyy-MM-dd')
        authoredBy = $AuthoredBy
        source     = 'local'
        when       = [pscustomobject]@{
            all  = $allConds.ToArray()
            any  = @()
            none = @()
        }
        verdict    = $verdict
        fix        = $fix
        evidence   = $evidence
        references = @()
    }
    return $draft
}

# ---------------------------------------------------------------------------
# Preview against current incident + stored incidents
# ---------------------------------------------------------------------------

function Get-LATDraftMissingConditions {
    # Return the subset of when.all conditions the ParseResult fails to
    # satisfy, so the wizard can explain why the draft missed an incident.
    param(
        [Parameter(Mandatory)] $DraftRule,
        [Parameter(Mandatory)] $ParseResult
    )
    $missing = New-Object System.Collections.Generic.List[object]
    foreach ($c in @(Get-LATArrayProperty $DraftRule.when 'all')) {
        if (-not (Test-LATConditionMatch -Condition $c -ParseResult $ParseResult)) {
            $missing.Add($c)
        }
    }
    return $missing.ToArray()
}

function Get-LATDraftPreview {
    <#
    .SYNOPSIS
        Run a draft rule against the current ParseResult + every stored
        incident. Returns a per-incident match table with missing-condition
        reporting for each miss.
    .PARAMETER DraftRule
        Draft rule object (from New-LATRuleDraft or hand-authored).
    .PARAMETER CurrentParseResult
        The ParseResult the draft was seeded from (preview against self).
    .PARAMETER IncidentRoot
        Override for the incident storage root (tests).
    .OUTPUTS
        PSCustomObject with CurrentIncidentResult, StoredIncidentResults,
        Summary{TotalStored, Fired, Missed}.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $DraftRule,
        $CurrentParseResult,
        [string]$IncidentRoot
    )
    # Validate the draft schema before preview. Authors hand-edit drafts;
    # catching schema errors here keeps bad drafts from reaching save.
    $schemaCheck = Test-LATRule -Rule $DraftRule -Path 'draft'
    if (-not $schemaCheck.Valid) {
        return [pscustomobject]@{
            SchemaValid = $false
            SchemaErrors = $schemaCheck.Errors
            CurrentIncidentResult = $null
            StoredIncidentResults = @()
            Summary = [pscustomobject]@{ TotalStored = 0; Fired = 0; Missed = 0 }
        }
    }

    $current = $null
    if ($CurrentParseResult) {
        $fires = Test-LATRuleMatches -Rule $DraftRule -ParseResult $CurrentParseResult
        $miss  = @()
        if (-not $fires) {
            $miss = Get-LATDraftMissingConditions -DraftRule $DraftRule -ParseResult $CurrentParseResult
        }
        $current = [pscustomobject]@{
            Fires             = [bool]$fires
            MissingConditions = $miss
        }
    }

    $storedResults = New-Object System.Collections.Generic.List[object]
    $stored = @(Get-LATIncidentList -IncidentRoot $IncidentRoot)
    foreach ($entry in $stored) {
        $bundle = $null
        try {
            $bundle = Import-LATIncident -Path $entry.FullName
            $fires = Test-LATRuleMatches -Rule $DraftRule -ParseResult $bundle.ParseResult
            $miss  = @()
            if (-not $fires) {
                $miss = Get-LATDraftMissingConditions -DraftRule $DraftRule -ParseResult $bundle.ParseResult
            }
            $storedResults.Add([pscustomobject]@{
                Path               = $entry.FullName
                Label              = (Get-LATProperty $bundle.Manifest 'label' '')
                Timestamp          = (Get-LATProperty $bundle.Manifest 'timestamp' '')
                OriginalTopVerdict = (Get-LATProperty $bundle.Manifest 'topVerdictRuleId' $null)
                Fires              = [bool]$fires
                MissingConditions  = $miss
            })
        } catch {
            $storedResults.Add([pscustomobject]@{
                Path               = $entry.FullName
                Label              = '(unreadable)'
                Timestamp          = $null
                OriginalTopVerdict = $null
                Fires              = $false
                MissingConditions  = @()
                ImportError        = $_.Exception.Message
            })
        } finally {
            if ($bundle -and $bundle.ExtractRoot -and (Test-Path $bundle.ExtractRoot)) {
                Remove-Item $bundle.ExtractRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $fired  = @($storedResults | Where-Object { $_.Fires }).Count
    $missed = $storedResults.Count - $fired
    return [pscustomobject]@{
        SchemaValid           = $true
        SchemaErrors          = @()
        CurrentIncidentResult = $current
        StoredIncidentResults = $storedResults.ToArray()
        Summary               = [pscustomobject]@{
            TotalStored = $storedResults.Count
            Fired       = $fired
            Missed      = $missed
        }
    }
}

# ---------------------------------------------------------------------------
# Console orchestrator (scripted + interactive modes)
# ---------------------------------------------------------------------------

function Format-LATDraftPreviewTable {
    # Human-readable preview summary. Returned as a string so callers can
    # Write-Host or log it; keeps the function pure.
    param([Parameter(Mandatory)] $Preview)
    $sb = New-Object System.Text.StringBuilder
    if (-not $Preview.SchemaValid) {
        [void]$sb.AppendLine('Draft is not schema-valid:')
        foreach ($e in $Preview.SchemaErrors) { [void]$sb.AppendLine("  - $e") }
        return $sb.ToString()
    }
    [void]$sb.AppendLine("Current incident: fires={0}" -f $Preview.CurrentIncidentResult.Fires)
    if (-not $Preview.CurrentIncidentResult.Fires) {
        [void]$sb.AppendLine("  missing conditions: {0}" -f @($Preview.CurrentIncidentResult.MissingConditions).Count)
    }
    [void]$sb.AppendLine("Stored incidents: {0} total, {1} fire, {2} miss" -f `
        $Preview.Summary.TotalStored, $Preview.Summary.Fired, $Preview.Summary.Missed)
    foreach ($r in $Preview.StoredIncidentResults) {
        $fires = if ($r.Fires) { '[+]' } else { '[-]' }
        $label = if ($r.Label) { $r.Label } else { (Split-Path $r.Path -Leaf) }
        [void]$sb.AppendLine("  $fires $label -- was:$($r.OriginalTopVerdict)")
    }
    return $sb.ToString()
}

function Show-LATRuleWizard {
    <#
    .SYNOPSIS
        Wizard orchestrator. Pre-fills a draft, renders preview, optionally
        prompts for field edits. Returns the final draft.
    .PARAMETER ParseResult
        Current triage ParseResult.
    .PARAMETER EvalResult
        Current triage EvalResult (used to seed verdict text).
    .PARAMETER NonInteractive
        Skip Read-Host prompts. Returns the pre-filled draft unchanged.
        Used by tests and scripted callers.
    .PARAMETER IncidentRoot
        Override for stored-incident location (tests).
    .PARAMETER WriteHost
        Write the preview table to host. Default: off in NonInteractive mode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ParseResult,
        $EvalResult,
        [switch]$NonInteractive,
        [string]$IncidentRoot,
        [switch]$WriteHost
    )
    $draft = New-LATRuleDraft -ParseResult $ParseResult -EvalResult $EvalResult
    $preview = Get-LATDraftPreview -DraftRule $draft -CurrentParseResult $ParseResult -IncidentRoot $IncidentRoot
    if ($WriteHost -or -not $NonInteractive) {
        Write-Host (Format-LATDraftPreviewTable -Preview $preview)
    }
    if ($NonInteractive) {
        return [pscustomobject]@{
            Draft   = $draft
            Preview = $preview
        }
    }
    # Interactive edits -- minimal CLI. Each prompt keeps current value
    # on blank input. The WPF version (Session 11) replaces this block.
    $new = Read-Host "Verdict [$($draft.verdict)]"
    if ($new) { $draft.verdict = $new }
    $new = Read-Host "Fix [$($draft.fix)]"
    if ($new) { $draft.fix = $new }
    $new = Read-Host "Scope (App/SoftwareUpdate/ClientInstall/CrossScope) [$($draft.scope)]"
    if ($new -and ($script:LATRuleWizard_ValidScopes -contains $new)) { $draft.scope = $new }
    $new = Read-Host "Confidence 0-100 [$($draft.confidence)]"
    if ($new -match '^\d+$') {
        $n = [int]$new
        if ($n -ge 0 -and $n -le 100) { $draft.confidence = $n }
    }
    # Re-run preview after edits
    $preview = Get-LATDraftPreview -DraftRule $draft -CurrentParseResult $ParseResult -IncidentRoot $IncidentRoot
    return [pscustomobject]@{
        Draft   = $draft
        Preview = $preview
    }
}
