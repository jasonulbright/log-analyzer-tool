#
# KB (Rules) module -- Session 12.
#
# Read-only browser over the currently-loaded rulebase (baseline +
# local overlay).  No edit / delete / reorder UI; authoring still
# happens through the Triage Capture-as-Rule flow (Session 11c).
#
# Handler scope rules: this is a factory-returns-UserControl module.
# The factory returns BEFORE the user clicks anything in the view.
# So per PS51-WPF-005, handlers on btnKbRefresh / cmbKbScope etc.
# need .GetNewClosure() to capture factory-local controls.  And
# because GetNewClosure strips script-scope function lookup in flat
# .ps1 (PS51-WPF-003), any call to Get-LATLoadedRules etc. from a
# handler body goes through a local plain-{...} wrapper that carries
# script-scope SessionState (Rule 8 / PS51-WPF-006).
#

Set-StrictMode -Version Latest

function New-LATKBRuleVM {
    <#
    .SYNOPSIS
        Translate a raw rule object (from Get-LATRules) into the DataGrid
        row shape.  Pure function, no WPF dependency -- unit-testable.
    .DESCRIPTION
        Emits two source fields:
          - Source: canonical internal value ('baseline' | 'local') from
            the rule schema.  Unchanged from what Get-LATRules loads.
          - SourceLabel: display value ('SYSTEM' | 'USER') for the
            DataGrid + filter combo.  "SYSTEM" reads as "ships with LAT"
            and "USER" as "I authored this via the wizard", which is more
            intuitive than baseline/local at a glance.
    #>
    param([Parameter(Mandatory)] $Rule)
    $source = [string](Get-LATProperty $Rule 'source' 'baseline')
    $label = switch ($source) {
        'local' { 'USER' }
        default { 'SYSTEM' }
    }
    $verdict = [string](Get-LATProperty $Rule 'verdict' '')
    if ($verdict.Length -gt 120) { $verdict = $verdict.Substring(0, 117) + '...' }
    return [pscustomobject]@{
        Id              = [string](Get-LATProperty $Rule 'id' '')
        Scope           = [string](Get-LATProperty $Rule 'scope' '')
        Confidence      = [int](Get-LATProperty $Rule 'confidence' 0)
        Source          = $source
        SourceLabel     = $label
        VerdictSnippet  = $verdict
        RawRule         = $Rule
    }
}

function Format-LATKBRuleDetail {
    <#
    .SYNOPSIS
        Multi-line human-readable breakdown of a rule for the detail pane.
        Not JSON -- JSON is noisy and hides the rule's shape behind
        punctuation.  This is the "at a glance" view.
    #>
    param([Parameter(Mandatory)] $Rule)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("id         : $(Get-LATProperty $Rule 'id' '')")
    [void]$sb.AppendLine("scope      : $(Get-LATProperty $Rule 'scope' '')")
    [void]$sb.AppendLine("confidence : $(Get-LATProperty $Rule 'confidence' 0)")
    [void]$sb.AppendLine("source     : $(Get-LATProperty $Rule 'source' 'baseline')")
    [void]$sb.AppendLine("version    : $(Get-LATProperty $Rule 'version' '')")
    [void]$sb.AppendLine("authoredBy : $(Get-LATProperty $Rule 'authoredBy' '')")
    [void]$sb.AppendLine("authoredAt : $(Get-LATProperty $Rule 'authoredAt' '')")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('verdict ----------')
    [void]$sb.AppendLine([string](Get-LATProperty $Rule 'verdict' ''))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('fix --------------')
    [void]$sb.AppendLine([string](Get-LATProperty $Rule 'fix' ''))
    [void]$sb.AppendLine('')

    $when = Get-LATProperty $Rule 'when' $null
    if ($when) {
        foreach ($bucket in 'all','any','none') {
            $conds = @(Get-LATArrayProperty $when $bucket)
            if ($conds.Count -eq 0) { continue }
            [void]$sb.AppendLine("when.$bucket --------")
            foreach ($c in $conds) {
                $k = $c.PSObject.Properties | Where-Object { $_.Value } | Select-Object -First 1
                if ($k) {
                    [void]$sb.AppendLine(("  - {0}: {1}" -f $k.Name, $k.Value))
                }
            }
            [void]$sb.AppendLine('')
        }
    }

    $evidence = @(Get-LATArrayProperty $Rule 'evidence')
    if ($evidence.Count -gt 0) {
        [void]$sb.AppendLine('evidence ---------')
        foreach ($e in $evidence) {
            $comp  = [string](Get-LATProperty $e 'component' '')
            $match = [string](Get-LATProperty $e 'match' '')
            if ($comp) { [void]$sb.AppendLine(("  [{0}] {1}" -f $comp, $match)) }
            else       { [void]$sb.AppendLine("  $match") }
        }
        [void]$sb.AppendLine('')
    }

    $refs = @(Get-LATArrayProperty $Rule 'references')
    if ($refs.Count -gt 0) {
        [void]$sb.AppendLine('references -------')
        foreach ($r in $refs) { [void]$sb.AppendLine("  $r") }
    }
    return $sb.ToString()
}

function New-LATKBView {
    param([hashtable]$Context)

    $setStatus = $Context.SetStatus
    $log       = $Context.Log

    $xamlPath = Join-Path $PSScriptRoot 'KB.xaml'
    $raw      = Get-Content -LiteralPath $xamlPath -Raw
    $reader   = New-Object System.Xml.XmlNodeReader ([xml]$raw)
    $view     = [Windows.Markup.XamlReader]::Load($reader)

    # Resolve controls.
    $txtSearch   = $view.FindName('txtKbSearch')
    $cmbScope    = $view.FindName('cmbKbScope')
    $cmbSource   = $view.FindName('cmbKbSource')
    $btnRefresh  = $view.FindName('btnKbRefresh')
    $gridRules   = $view.FindName('gridKbRules')
    $txtDetail   = $view.FindName('txtKbDetail')
    $txtFooter   = $view.FindName('txtKbFooter')

    # Populate filter combos.
    foreach ($s in @('(all scopes)','App','SoftwareUpdate','ClientInstall','CrossScope')) {
        [void]$cmbScope.Items.Add($s)
    }
    $cmbScope.SelectedIndex = 0
    foreach ($s in @('(all sources)','SYSTEM','USER')) {
        [void]$cmbSource.Items.Add($s)
    }
    $cmbSource.SelectedIndex = 0

    # State.  All rules kept once; filter is pure function over them.
    $state = @{
        AllRuleVMs = @()
        Rows       = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    }
    $gridRules.ItemsSource = $state.Rows

    # ---- Local scriptblock wrappers (Rule 8 / PS51-WPF-006) --------------
    # Plain {...}: carry script-scope SessionState, resolve Get-LATLoadedRules.
    # Invoked via `&` from GetNewClosure'd handlers.
    $loadRulesSb = {
        param($GetLoadedRules)
        $rules = & $GetLoadedRules
        $vms = foreach ($r in @($rules)) { New-LATKBRuleVM -Rule $r }
        return ,@($vms)  # comma-prefix to preserve array shape on single element
    }

    $formatDetailSb = {
        param($RawRule)
        return Format-LATKBRuleDetail -Rule $RawRule
    }

    # Filtering is pure and uses only captured locals -- no script-scope
    # calls -- so a GetNewClosure variant is fine here.  Filter value
    # for Source matches VM.SourceLabel (SYSTEM / USER) directly; the
    # canonical VM.Source ('baseline' | 'local') is only used for counts.
    $applyFilterSb = {
        $searchText = [string]$txtSearch.Text
        $scopePick  = [string]$cmbScope.SelectedItem
        $sourcePick = [string]$cmbSource.SelectedItem
        $state.Rows.Clear()
        $shownSystem = 0
        $shownUser   = 0
        foreach ($vm in $state.AllRuleVMs) {
            if ($scopePick -and $scopePick -ne '(all scopes)' -and $vm.Scope -ne $scopePick) { continue }
            if ($sourcePick -and $sourcePick -ne '(all sources)' -and $vm.SourceLabel -ne $sourcePick) { continue }
            if ($searchText) {
                $needle = $searchText.Trim()
                if ($needle) {
                    $id   = [string]$vm.Id
                    $vsnp = [string]$vm.VerdictSnippet
                    if (($id -notlike "*$needle*") -and ($vsnp -notlike "*$needle*")) { continue }
                }
            }
            $state.Rows.Add($vm)
            if ($vm.SourceLabel -eq 'USER') { $shownUser++ } else { $shownSystem++ }
        }
        $totalSystem = @($state.AllRuleVMs | Where-Object { $_.SourceLabel -ne 'USER' }).Count
        $totalUser   = @($state.AllRuleVMs | Where-Object { $_.SourceLabel -eq 'USER' }).Count
        $txtFooter.Text = "Showing {0} of {1} rules  --  SYSTEM: {2}/{3}  --  USER: {4}/{5}" -f `
            $state.Rows.Count, $state.AllRuleVMs.Count, $shownSystem, $totalSystem, $shownUser, $totalUser
    }.GetNewClosure()

    # Two wrappers to cleanly separate initial-load from user refresh:
    #   $initialLoadSb uses the cached Context.GetLoadedRules.  First
    #     open of the module does not pay a re-scan cost.
    #   $hardRefreshSb uses Context.ReloadRules so the Refresh button
    #     picks up rules saved in %LOCALAPPDATA%\LogAnalyzer\rules
    #     since the shell launched, without a relaunch.
    $initialLoadSb = {
        $vms = & $loadRulesSb -GetLoadedRules $Context.GetLoadedRules
        $state.AllRuleVMs = @($vms)
        & $applyFilterSb
    }.GetNewClosure()

    $hardRefreshSb = {
        $reloader = if ($Context.ReloadRules) { $Context.ReloadRules } else { $Context.GetLoadedRules }
        $vms = & $loadRulesSb -GetLoadedRules $reloader
        $state.AllRuleVMs = @($vms)
        & $applyFilterSb
    }.GetNewClosure()

    # Wire events.
    $btnRefresh.Add_Click({
        try {
            & $hardRefreshSb
            & $log -Message ("KB: refreshed -- {0} rules loaded" -f $state.AllRuleVMs.Count) -Level 'INFO'
        } catch {
            & $log -Message "KB refresh failed: $($_.Exception.Message)" -Level 'ERROR'
        }
    }.GetNewClosure())

    $cmbScope.Add_SelectionChanged({ & $applyFilterSb }.GetNewClosure())
    $cmbSource.Add_SelectionChanged({ & $applyFilterSb }.GetNewClosure())
    $txtSearch.Add_TextChanged({ & $applyFilterSb }.GetNewClosure())

    $gridRules.Add_SelectionChanged({
        try {
            $sel = $gridRules.SelectedItem
            if ($null -eq $sel) {
                $txtDetail.Text = 'Select a rule to view its schema, conditions, evidence, and fix.'
                return
            }
            $txtDetail.Text = & $formatDetailSb -RawRule $sel.RawRule
        } catch {
            $txtDetail.Text = "Detail render failed: $($_.Exception.Message)"
        }
    }.GetNewClosure())

    # Initial load.  Synchronous -- rule count is low (hundreds at most)
    # and Get-LATLoadedRules is cached after first invocation.
    try {
        & $initialLoadSb
    } catch {
        $txtFooter.Text = "Load failed: $($_.Exception.Message)"
        & $log -Message "KB initial load failed: $($_.Exception.Message)" -Level 'ERROR'
    }

    return $view
}
