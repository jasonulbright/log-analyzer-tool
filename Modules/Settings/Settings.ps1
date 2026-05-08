#
# Settings module -- Session 12.
#
# Read-only view of the rulebase and incident-storage paths, plus
# three actions: Reload rules (bust the launcher's rule cache),
# Open folder (Baseline / Overlay / Incidents), and Trim incidents
# (apply FIFO retention now).
#
# No preferences file in v1.  Retention cap is the evaluator default
# (50) displayed read-only; wiring it to a prefs file is Session 13+
# work.
#

Set-StrictMode -Version Latest

function New-LATSettingsView {
    param([hashtable]$Context)

    $setStatus = $Context.SetStatus
    $log       = $Context.Log

    $xamlPath = Join-Path $PSScriptRoot 'Settings.xaml'
    $raw      = Get-Content -LiteralPath $xamlPath -Raw
    $reader   = New-Object System.Xml.XmlNodeReader ([xml]$raw)
    $view     = [Windows.Markup.XamlReader]::Load($reader)

    $txtBaselinePath  = $view.FindName('txtBaselinePath')
    $txtOverlayPath   = $view.FindName('txtOverlayPath')
    $txtRuleCount     = $view.FindName('txtRuleCount')
    $txtIncidentRoot  = $view.FindName('txtIncidentRoot')
    $txtIncidentCount = $view.FindName('txtIncidentCount')
    $txtRetentionCap  = $view.FindName('txtRetentionCap')

    $btnOpenBaseline  = $view.FindName('btnOpenBaseline')
    $btnOpenOverlay   = $view.FindName('btnOpenOverlay')
    $btnReloadRules   = $view.FindName('btnReloadRules')
    $btnOpenIncidents = $view.FindName('btnOpenIncidents')
    $btnTrimIncidents = $view.FindName('btnTrimIncidents')

    # Capture path values at factory scope so GetNewClosure'd button
    # handlers can read them via lexical-local copies.  Reaching for
    # $script:LAT_BaselineRoot or bare Get-LATLocalOverlayRoot from
    # inside a closure would trip PS51-WPF-001 (script var returns
    # $null) and PS51-WPF-003 (script fn throws CommandNotFound).
    $baselineRoot = $script:LAT_BaselineRoot
    $overlayRoot  = Get-LATLocalOverlayRoot
    $incidentRoot = Get-LATIncidentRoot

    # ---- Local scriptblock wrappers (Rule 8) -----------------------------
    $getCountsSb = {
        param($GetLoadedRules)
        $rules = @(& $GetLoadedRules)
        $baselineN = @($rules | Where-Object { (Get-LATProperty $_ 'source' 'baseline') -ne 'local' }).Count
        $localN    = @($rules | Where-Object { (Get-LATProperty $_ 'source' 'baseline') -eq 'local' }).Count
        $incidents = @(Get-LATIncidentList).Count
        return [pscustomobject]@{
            Total     = $rules.Count
            Baseline  = $baselineN
            Local     = $localN
            Incidents = $incidents
        }
    }
    $reloadRulesSb = {
        param($ReloadRules)
        return @(& $ReloadRules)
    }
    $trimIncidentsSb = {
        param([int]$Retention = 50)
        return Trim-LATIncidents -Retention $Retention
    }
    $openFolderSb = {
        # Plain wrapper.  Creates the overlay dir on demand (it may not
        # exist yet on a fresh install).
        param([string]$Path)
        if ([string]::IsNullOrEmpty($Path)) { return }
        if (-not (Test-Path $Path)) {
            try { $null = New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop } catch { }
        }
        if (Test-Path $Path) {
            Start-Process -FilePath 'explorer.exe' -ArgumentList $Path | Out-Null
        }
    }

    $refreshSb = {
        $txtBaselinePath.Text = [string]$baselineRoot
        $txtOverlayPath.Text  = [string]$overlayRoot
        $txtIncidentRoot.Text = [string]$incidentRoot
        try {
            $counts = & $getCountsSb -GetLoadedRules $Context.GetLoadedRules
            $txtRuleCount.Text    = "{0}  (baseline: {1}, local: {2})" -f $counts.Total, $counts.Baseline, $counts.Local
            $txtIncidentCount.Text = [string]$counts.Incidents
        } catch {
            $txtRuleCount.Text    = "(load failed: $($_.Exception.Message))"
            $txtIncidentCount.Text = '(load failed)'
        }
        $txtRetentionCap.Text = '50 (default, FIFO)'
    }.GetNewClosure()

    # ---- Handlers --------------------------------------------------------
    # Path args come from factory-local captures (no $script:/script-scope
    # function calls inside the closure; PS51-WPF-001/003).
    $btnOpenBaseline.Add_Click({
        try { & $openFolderSb -Path $baselineRoot } catch { & $log -Message "Open failed: $($_.Exception.Message)" -Level 'WARN' }
    }.GetNewClosure())

    $btnOpenOverlay.Add_Click({
        try { & $openFolderSb -Path $overlayRoot } catch { & $log -Message "Open failed: $($_.Exception.Message)" -Level 'WARN' }
    }.GetNewClosure())

    $btnOpenIncidents.Add_Click({
        try { & $openFolderSb -Path $incidentRoot } catch { & $log -Message "Open failed: $($_.Exception.Message)" -Level 'WARN' }
    }.GetNewClosure())

    $btnReloadRules.Add_Click({
        try {
            if ($Context.ReloadRules) {
                $rules = & $reloadRulesSb -ReloadRules $Context.ReloadRules
                & $log -Message ("Settings: rulebase reloaded -- {0} rules" -f @($rules).Count) -Level 'INFO'
                & $setStatus -Message "Rulebase reloaded"
            }
            & $refreshSb
        } catch {
            & $log -Message "Reload failed: $($_.Exception.Message)" -Level 'ERROR'
            & $setStatus -Message 'Reload failed -- see log'
        }
    }.GetNewClosure())

    $btnTrimIncidents.Add_Click({
        try {
            $deleted = & $trimIncidentsSb -Retention 50
            & $log -Message ("Settings: trimmed {0} incident(s) over the retention cap" -f $deleted) -Level 'INFO'
            & $setStatus -Message "Trimmed $deleted incident(s)"
            & $refreshSb
        } catch {
            & $log -Message "Trim failed: $($_.Exception.Message)" -Level 'ERROR'
            & $setStatus -Message 'Trim failed -- see log'
        }
    }.GetNewClosure())

    # Initial load.
    try {
        & $refreshSb
    } catch {
        & $log -Message "Settings initial load failed: $($_.Exception.Message)" -Level 'ERROR'
    }

    return $view
}
