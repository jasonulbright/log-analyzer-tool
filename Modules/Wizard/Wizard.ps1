# Wizard sidebar module.  The interactive dialog itself lives in
# WizardDialog.ps1 (Session 11c); this sidebar page is the *standalone*
# entry point so clicking the sidebar "Wizard" button actually launches
# the wizard.  Incident selection driven by %LOCALAPPDATA%\LogAnalyzer\incidents
# -- rehydrate the picked bundle via Import-LATIncident, pass its
# ParseResult + EvalResult to Show-LATRuleWizardDialog.
#
# Dot-sourcing WizardDialog.ps1 here at file top level: this file is
# itself dot-sourced by the launcher (the foreach over $script:LAT_Modules
# runs at launcher top-level scope), so a nested . at top level of THIS
# file also lands in launcher script scope and Show-LATRuleWizardDialog
# is reachable from handlers below.
. (Join-Path $PSScriptRoot 'WizardDialog.ps1')

function New-LATWizardIncidentRowVM {
    <#
    .SYNOPSIS
        Build a combo-box row label + file path pair from an incident
        bundle's manifest.  "2026-04-24 15:17:28  --  client-certificate-issue"
        beats a raw GUID filename in the picker.
    #>
    param(
        [Parameter(Mandatory)] $FileInfo,
        $Manifest
    )
    $ts = ''
    $tsStr = [string](Get-LATProperty $Manifest 'timestamp' '')
    if ($tsStr) {
        try {
            $dt = [datetime]::Parse($tsStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
            $ts = $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        } catch {
            $ts = $tsStr
        }
    } else {
        $ts = $FileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
    $top   = [string](Get-LATProperty $Manifest 'topVerdictRuleId' '')
    $label = [string](Get-LATProperty $Manifest 'label' '')
    $suffix = if ($top) { $top } elseif ($label) { $label } else { '(no match)' }
    return [pscustomobject]@{
        Display = "{0}  --  {1}" -f $ts, $suffix
        Path    = $FileInfo.FullName
    }
}

function New-LATWizardView {
    param([hashtable]$Context)

    $setStatus = $Context.SetStatus
    $log       = $Context.Log
    $window    = $Context.Window

    $xamlPath = Join-Path $PSScriptRoot 'Wizard.xaml'
    $raw      = Get-Content -LiteralPath $xamlPath -Raw
    $reader   = New-Object System.Xml.XmlNodeReader ([xml]$raw)
    $view     = [Windows.Markup.XamlReader]::Load($reader)

    $cmbIncident = $view.FindName('cmbWizIncident')
    $btnRefresh  = $view.FindName('btnWizRefresh')
    $btnLaunch   = $view.FindName('btnWizLaunch')
    $txtHint     = $view.FindName('txtWizHint')

    $state = @{
        Items = New-Object System.Collections.Generic.List[object]
    }

    # ---- Local scriptblock wrappers (Rule 8) -----------------------------
    # Plain wrappers carry script-scope SessionState so Get-LATIncidentList,
    # Import-LATIncident, Show-LATRuleWizardDialog all resolve at invoke.
    $listIncidentsSb = {
        $files = @(Get-LATIncidentList)
        $out = New-Object System.Collections.Generic.List[object]
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        foreach ($f in $files) {
            $manifest = $null
            $archive = $null
            try {
                $archive = [System.IO.Compression.ZipFile]::OpenRead($f.FullName)
                $entry = $archive.Entries | Where-Object { $_.FullName -eq 'manifest.json' } | Select-Object -First 1
                if ($entry) {
                    $stream = $entry.Open()
                    try {
                        $rdr = New-Object System.IO.StreamReader($stream)
                        try { $manifest = $rdr.ReadToEnd() | ConvertFrom-Json }
                        finally { $rdr.Dispose() }
                    } finally { $stream.Dispose() }
                }
            } catch { } finally {
                if ($archive) { $archive.Dispose() }
            }
            $out.Add((New-LATWizardIncidentRowVM -FileInfo $f -Manifest $manifest))
        }
        return ,@($out.ToArray())
    }

    $importIncidentSb = {
        param([string]$Path)
        return Import-LATIncident -Path $Path
    }

    $showWizardSb = {
        param([System.Windows.Window]$Owner, $ParseResult, $EvalResult, [hashtable]$Context)
        return Show-LATRuleWizardDialog -Owner $Owner -ParseResult $ParseResult -EvalResult $EvalResult -Context $Context
    }

    # Rebuild the picker list and update the Launch button state.
    $refreshSb = {
        $cmbIncident.Items.Clear()
        $state.Items.Clear()
        try {
            $vms = & $listIncidentsSb
            foreach ($vm in @($vms)) {
                $state.Items.Add($vm)
                [void]$cmbIncident.Items.Add($vm.Display)
            }
            if ($cmbIncident.Items.Count -gt 0) {
                $cmbIncident.SelectedIndex = 0
                $btnLaunch.IsEnabled = $true
                $txtHint.Text = "{0} stored incident(s). Most recent is preselected." -f $cmbIncident.Items.Count
            } else {
                $btnLaunch.IsEnabled = $false
                $txtHint.Text = 'No stored incidents yet. Run a triage to capture one.'
            }
        } catch {
            $btnLaunch.IsEnabled = $false
            $txtHint.Text = "Load failed: $($_.Exception.Message)"
        }
    }.GetNewClosure()

    # ---- Handlers --------------------------------------------------------
    $btnRefresh.Add_Click({
        try { & $refreshSb } catch { & $log -Message "Wizard refresh failed: $($_.Exception.Message)" -Level 'ERROR' }
    }.GetNewClosure())

    $btnLaunch.Add_Click({
        try {
            $idx = $cmbIncident.SelectedIndex
            if ($idx -lt 0 -or $idx -ge $state.Items.Count) { return }
            $row = $state.Items[$idx]
            & $setStatus -Message "Loading incident $($row.Display)..."
            $bundle = & $importIncidentSb -Path $row.Path
            & $setStatus -Message 'Wizard open...'
            $result = & $showWizardSb -Owner $window -ParseResult $bundle.ParseResult -EvalResult $bundle.EvalResult -Context $Context
            if ($result.Saved)   { & $log -Message "Wizard saved: $($result.SavedPath)" -Level 'INFO' }
            if ($result.Patched) { & $log -Message "Wizard patch: $($result.PatchedPath) -> $($result.TargetRepoPath)" -Level 'INFO' }
            if ($result.Saved -and $result.Patched) {
                & $setStatus -Message "Rule saved + patch exported"
            } elseif ($result.Saved) {
                & $setStatus -Message "Rule saved: $([System.IO.Path]::GetFileName($result.SavedPath))"
            } elseif ($result.Patched) {
                & $setStatus -Message "Patch written: $([System.IO.Path]::GetFileName($result.PatchedPath))"
            } else {
                & $setStatus -Message 'Wizard cancelled'
            }
        } catch {
            & $log -Message "Wizard launch failed: $($_.Exception.Message)" -Level 'ERROR'
            & $setStatus -Message 'Wizard launch failed -- see log'
        }
    }.GetNewClosure())

    # Initial load.
    try { & $refreshSb } catch { $txtHint.Text = "Load failed: $($_.Exception.Message)" }

    return $view
}
