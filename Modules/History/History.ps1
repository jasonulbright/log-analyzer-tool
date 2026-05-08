#
# History module -- Session 12.
#
# Read-only browser over %LOCALAPPDATA%\LogAnalyzer\incidents.  List
# shows manifest-level metadata per bundle; Re-analyze button replays
# a selected bundle against the current rulebase so the user can see
# how newly-authored rules would have scored prior incidents.
#
# Same handler-scope shape as KB.ps1: factory returns the UserControl,
# handlers fire later, so .GetNewClosure() + local scriptblock wrappers
# for any script-scope data-layer call.
#

Set-StrictMode -Version Latest

function New-LATHistoryRowVM {
    <#
    .SYNOPSIS
        Project an incident zip + its manifest into a DataGrid row shape.
    #>
    param(
        [Parameter(Mandatory)] $FileInfo,
        $Manifest
    )
    $timestampLocal = ''
    $tsStr = [string](Get-LATProperty $Manifest 'timestamp' '')
    if ($tsStr) {
        try {
            $dt = [datetime]::Parse($tsStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
            $timestampLocal = $dt.ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss')
        } catch {
            $timestampLocal = $tsStr
        }
    } else {
        $timestampLocal = $FileInfo.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
    return [pscustomobject]@{
        TimestampLocal    = $timestampLocal
        Label             = [string](Get-LATProperty $Manifest 'label' '')
        EntryCount        = [int](Get-LATProperty $Manifest 'entryCount' 0)
        MatchedRuleCount  = [int](Get-LATProperty $Manifest 'matchedRuleCount' 0)
        TopVerdictRuleId  = [string](Get-LATProperty $Manifest 'topVerdictRuleId' '')
        Path              = $FileInfo.FullName
    }
}

function Format-LATReplayDiff {
    <#
    .SYNOPSIS
        Render the Invoke-LATIncidentReplay result as a text block for
        the history pane.
    #>
    param([Parameter(Mandatory)] $Replay)
    $sb = New-Object System.Text.StringBuilder
    $added    = @(Get-LATArrayProperty $Replay.Diff 'AddedRuleIds')
    $removed  = @(Get-LATArrayProperty $Replay.Diff 'RemovedRuleIds')
    $retained = @(Get-LATArrayProperty $Replay.Diff 'RetainedRuleIds')
    $origTop = $null
    if ($Replay.Original) {
        $origVerdicts = @(Get-LATArrayProperty $Replay.Original 'Verdicts')
        if ($origVerdicts.Count -gt 0) { $origTop = [string]$origVerdicts[0].RuleId }
    }
    $newTop = $null
    $newVerdicts = @(Get-LATArrayProperty $Replay.Replay 'Verdicts')
    if ($newVerdicts.Count -gt 0) { $newTop = [string]$newVerdicts[0].RuleId }

    [void]$sb.AppendLine(("originally fired : {0}" -f ($retained.Count + $removed.Count)))
    [void]$sb.AppendLine(("replay fires     : {0}" -f ($retained.Count + $added.Count)))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine(("original top     : {0}" -f ($origTop | ForEach-Object { if ($_) { $_ } else { '(none)' } })))
    [void]$sb.AppendLine(("replay top       : {0}" -f ($newTop  | ForEach-Object { if ($_) { $_ } else { '(none)' } })))
    [void]$sb.AppendLine('')
    if ($added.Count -gt 0) {
        [void]$sb.AppendLine('added (new rules that fire now):')
        foreach ($id in $added) { [void]$sb.AppendLine("  + $id") }
        [void]$sb.AppendLine('')
    }
    if ($removed.Count -gt 0) {
        [void]$sb.AppendLine('removed (no longer fire):')
        foreach ($id in $removed) { [void]$sb.AppendLine("  - $id") }
        [void]$sb.AppendLine('')
    }
    if ($retained.Count -gt 0) {
        [void]$sb.AppendLine('retained (fire in both runs):')
        foreach ($id in $retained) { [void]$sb.AppendLine("  = $id") }
    }
    if ($added.Count -eq 0 -and $removed.Count -eq 0 -and $retained.Count -eq 0) {
        [void]$sb.AppendLine('(no rule fired in either run)')
    }
    return $sb.ToString()
}

function New-LATHistoryView {
    param([hashtable]$Context)

    $setStatus = $Context.SetStatus
    $log       = $Context.Log

    $xamlPath = Join-Path $PSScriptRoot 'History.xaml'
    $raw      = Get-Content -LiteralPath $xamlPath -Raw
    $reader   = New-Object System.Xml.XmlNodeReader ([xml]$raw)
    $view     = [Windows.Markup.XamlReader]::Load($reader)

    $btnRefresh   = $view.FindName('btnHistRefresh')
    $btnReanalyze = $view.FindName('btnHistReanalyze')
    $btnOpenFolder = $view.FindName('btnHistOpenFolder')
    $gridHistory  = $view.FindName('gridHistory')
    $txtDiff      = $view.FindName('txtHistDiff')
    $txtFooter    = $view.FindName('txtHistFooter')

    $state = @{
        Rows = New-Object System.Collections.ObjectModel.ObservableCollection[object]
    }
    $gridHistory.ItemsSource = $state.Rows

    # Capture stable paths at factory scope so GetNewClosure'd handlers
    # can read them via lexical-local copy without tripping PS51-WPF-003
    # (bare script-scope function call inside a closure throws).
    $incidentRoot = Get-LATIncidentRoot

    # ---- Local scriptblock wrappers (Rule 8) -----------------------------
    $listIncidentsSb = {
        # Read each bundle's manifest for label/counts.  For the default
        # retention cap (50) this is fast; if retention is raised >500
        # the module should lazy-hydrate, but that is out of scope for v1.
        $files = @(Get-LATIncidentList)
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($f in $files) {
            $manifest = $null
            $archive = $null
            try {
                # Read just manifest.json via System.IO.Compression so
                # we do not expand the whole zip per row.
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                $archive = [System.IO.Compression.ZipFile]::OpenRead($f.FullName)
                $entry = $archive.Entries | Where-Object { $_.FullName -eq 'manifest.json' } | Select-Object -First 1
                if ($entry) {
                    $stream = $entry.Open()
                    try {
                        $reader = New-Object System.IO.StreamReader($stream)
                        try {
                            $json = $reader.ReadToEnd()
                            $manifest = $json | ConvertFrom-Json
                        } finally { $reader.Dispose() }
                    } finally { $stream.Dispose() }
                }
            } catch {
                # Corrupt zip or unreadable manifest -- fall through with
                # $manifest = $null; the VM falls back to the file's
                # LastWriteTime for the timestamp column.
            } finally {
                if ($archive) { $archive.Dispose() }
            }
            $out.Add((New-LATHistoryRowVM -FileInfo $f -Manifest $manifest))
        }
        return ,@($out.ToArray())
    }

    $replayIncidentSb = {
        # Plain scriptblock: carries script-scope SessionState so
        # Invoke-LATIncidentReplay + Get-LATArrayProperty resolve.
        # Returns pre-computed counts so the (closured) handler body
        # does not need any script-scope call itself.
        param([string]$Path, $GetLoadedRules)
        $rules = & $GetLoadedRules
        $replay = Invoke-LATIncidentReplay -Path $Path -Rules $rules
        return [pscustomobject]@{
            Replay   = $replay
            Added    = @(Get-LATArrayProperty $replay.Diff 'AddedRuleIds').Count
            Removed  = @(Get-LATArrayProperty $replay.Diff 'RemovedRuleIds').Count
            Retained = @(Get-LATArrayProperty $replay.Diff 'RetainedRuleIds').Count
        }
    }

    $formatDiffSb = {
        param($Replay)
        return Format-LATReplayDiff -Replay $Replay
    }

    $openFolderSb = {
        # Plain wrapper; $log is not captured.  Caller decides what to
        # do when the directory is missing.  Returns $true on open.
        param([string]$Path)
        if (Test-Path $Path) {
            Start-Process -FilePath 'explorer.exe' -ArgumentList $Path | Out-Null
            return $true
        }
        return $false
    }

    # ---- Handlers --------------------------------------------------------
    $refreshSb = {
        $state.Rows.Clear()
        try {
            $vms = & $listIncidentsSb
            foreach ($v in @($vms)) { $state.Rows.Add($v) }
            $txtFooter.Text = "{0} incident(s) in {1}" -f $state.Rows.Count, $incidentRoot
        } catch {
            $txtFooter.Text = "Load failed: $($_.Exception.Message)"
        }
    }.GetNewClosure()

    $btnRefresh.Add_Click({
        try {
            & $refreshSb
            & $log -Message ("History: refreshed -- {0} incidents" -f $state.Rows.Count) -Level 'INFO'
        } catch {
            & $log -Message "History refresh failed: $($_.Exception.Message)" -Level 'ERROR'
        }
    }.GetNewClosure())

    $btnReanalyze.Add_Click({
        try {
            $sel = $gridHistory.SelectedItem
            if ($null -eq $sel) { return }
            & $setStatus -Message "Replaying $($sel.TimestampLocal)..."
            $r = & $replayIncidentSb -Path $sel.Path -GetLoadedRules $Context.GetLoadedRules
            $txtDiff.Text = & $formatDiffSb -Replay $r.Replay
            & $setStatus -Message ("Replay done -- {0} added, {1} removed" -f $r.Added, $r.Removed)
            & $log -Message ("History replay: {0} added, {1} removed, {2} retained" -f $r.Added, $r.Removed, $r.Retained) -Level 'INFO'
        } catch {
            $txtDiff.Text = "Replay failed: $($_.Exception.Message)"
            & $log -Message "History replay failed: $($_.Exception.Message)" -Level 'ERROR'
            & $setStatus -Message 'Replay failed -- see log'
        }
    }.GetNewClosure())

    $btnOpenFolder.Add_Click({
        try {
            $opened = & $openFolderSb -Path $incidentRoot
            if (-not $opened) {
                & $log -Message "Incident folder does not exist yet: $incidentRoot" -Level 'WARN'
            }
        } catch {
            & $log -Message "Open folder failed: $($_.Exception.Message)" -Level 'WARN'
        }
    }.GetNewClosure())

    $gridHistory.Add_SelectionChanged({
        $btnReanalyze.IsEnabled = [bool]$gridHistory.SelectedItem
    }.GetNewClosure())

    # Initial load.
    try {
        & $refreshSb
    } catch {
        $txtFooter.Text = "Load failed: $($_.Exception.Message)"
    }

    return $view
}
