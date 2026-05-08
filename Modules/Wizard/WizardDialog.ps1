#
# Show-LATRuleWizardDialog -- Session 11c.
#
# MetroWindow modal invoked from the Triage Capture-as-Rule handler.
# Seeds a draft rule from the current triage run, lets the user edit
# verdict / fix / scope / confidence / evidence, runs preview on demand,
# and saves to the local overlay (or emits a submit-upstream patch).
#
# Handler-scope rules (IMPORTANT):
#   - This function blocks on $dlg.ShowDialog() until the user closes
#     the dialog.  Every internal button handler fires WHILE this
#     function is still on the call stack, so lexical parent scope
#     is alive.
#   - Per PS51-WPF-004, .GetNewClosure() on those handlers is strictly
#     a loss -- it would strip script-scope function lookup
#     (Get-LATDraftPreview, Save-LATRuleDraft, Export-LATRulePatch,
#     Format-LATDraftPreviewTable) and $script: reads/writes.  We rely
#     on lexical scope instead, so NO .GetNewClosure() anywhere below.
#   - Cross-handler mutable state (what action the user picked) lives
#     in a local hashtable $state.  Hashtables are reference types, so
#     handlers can mutate keys and the post-ShowDialog readback sees
#     the update -- no $script: needed (PS51-WPF-013).
#   - Every .NET method call whose return we do not want on the
#     pipeline is cast [void] (ThemeManager.ChangeTheme, Items.Add,
#     Children.Add) per PS51-WPF-008.

Set-StrictMode -Version Latest

function Show-LATRuleWizardDialog {
    <#
    .SYNOPSIS
        Open the Capture-as-Rule wizard, modal over the main window.
    .PARAMETER Owner
        Main window used as the dialog's Owner for z-order + theme
        propagation.  Capture it as a factory-local in the calling
        handler per PS51-WPF-007 before passing it here.
    .PARAMETER ParseResult
        Current triage ParseResult (from the last Select-Logs run).
    .PARAMETER EvalResult
        Current triage EvalResult.  Optional; seeds verdict text if
        the top rule has non-empty Verdict.
    .PARAMETER Context
        Shell module context hashtable.  Reserved for future logging
        hooks.  May be $null.
    .OUTPUTS
        [pscustomobject] with fields:
          Action         : 'saved' | 'patched' | 'cancelled'
          Path           : saved-rule path | patch-file path | $null
          TargetRepoPath : target-path string for patched; else $null
          Draft          : final draft object (saved/patched); else $null
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Windows.Window]$Owner,
        [Parameter(Mandatory)] $ParseResult,
        $EvalResult,
        [hashtable]$Context
    )

    # Seed the draft from the current triage run.  All field-default
    # values come from here.
    $draft = New-LATRuleDraft -ParseResult $ParseResult -EvalResult $EvalResult

    # Load XAML.
    $xamlPath = Join-Path $PSScriptRoot 'WizardDialog.xaml'
    $raw = Get-Content -LiteralPath $xamlPath -Raw
    $raw = $raw -replace 'x:Class="[^"]+"', ''
    $reader = New-Object System.Xml.XmlNodeReader ([xml]$raw)
    $dlg = [Windows.Markup.XamlReader]::Load($reader)
    # PS51-WPF-033: function is dot-sourced from start-loganalyzer-wpf.ps1.
    if (Get-Command Install-TitleBarDragFallback -ErrorAction SilentlyContinue) {
        Install-TitleBarDragFallback -Window $dlg
    }

    # Theme propagation from Owner.  Best-effort; a swallowed failure
    # here leaves the dialog on the default (Dark.Steel) theme which
    # still meets WCAG AA.
    try {
        $theme = [ControlzEx.Theming.ThemeManager]::Current.DetectTheme($Owner)
        if ($theme) {
            [void][ControlzEx.Theming.ThemeManager]::Current.ChangeTheme($dlg, $theme)
        }
    } catch { }
    $dlg.Owner = $Owner
    try {
        $dlg.WindowTitleBrush          = $Owner.WindowTitleBrush
        $dlg.NonActiveWindowTitleBrush = $Owner.WindowTitleBrush
        $dlg.GlowBrush                 = $Owner.GlowBrush
        $dlg.NonActiveGlowBrush        = $Owner.GlowBrush
    } catch { }

    # Resolve named controls.
    $txtRuleId      = $dlg.FindName('txtRuleId')
    $cmbScope       = $dlg.FindName('cmbScope')
    $sldConfidence  = $dlg.FindName('sldConfidence')
    $txtConfReadout = $dlg.FindName('txtConfidenceReadout')
    $txtVerdict     = $dlg.FindName('txtVerdict')
    $txtFix         = $dlg.FindName('txtFix')
    $pnlEvidence    = $dlg.FindName('pnlEvidence')
    $txtPreview     = $dlg.FindName('txtPreview')
    $btnPreview     = $dlg.FindName('btnPreview')
    $btnSave        = $dlg.FindName('btnSave')
    $btnSubmit      = $dlg.FindName('btnSubmit')
    $btnCancel      = $dlg.FindName('btnCancel')

    # Pre-fill form.
    $txtRuleId.Text = [string]$draft.id
    foreach ($s in @('App','SoftwareUpdate','ClientInstall','CrossScope')) {
        [void]$cmbScope.Items.Add($s)
    }
    $cmbScope.SelectedItem = [string]$draft.scope
    $sldConfidence.Value   = [double]$draft.confidence
    $txtConfReadout.Text   = [string][int]$draft.confidence
    $txtVerdict.Text       = [string]$draft.verdict
    $txtFix.Text           = [string]$draft.fix

    # Evidence checkboxes -- populated programmatically so we can read
    # back the user's selection without fighting PS 5.1 WPF binding of
    # PSCustomObject collections.  $evidenceRefs is the parallel array
    # of { CheckBox, Evidence } used on save/patch/preview.
    $evidenceRefs = New-Object System.Collections.Generic.List[object]
    foreach ($e in @($draft.evidence)) {
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.IsChecked = $true
        $cb.Margin    = '0,2,0,2'
        $cb.FontSize  = 12
        $label = if ($e.component) {
            "{0} -- {1}" -f $e.component, $e.match
        } else {
            [string]$e.match
        }
        $cb.Content = $label
        $cb.ToolTip = [string]$e.match
        [void]$pnlEvidence.Children.Add($cb)
        $evidenceRefs.Add([pscustomobject]@{ CheckBox = $cb; Evidence = $e })
    }
    if ($evidenceRefs.Count -eq 0) {
        $tb = New-Object System.Windows.Controls.TextBlock
        $tb.Text       = '(No pre-seeded evidence -- the triage did not flag any entries.)'
        $tb.FontStyle  = 'Italic'
        $tb.Foreground = $dlg.FindResource('MahApps.Brushes.Gray3')
        [void]$pnlEvidence.Children.Add($tb)
    }

    # Slider <-> readout sync.  No GetNewClosure -- see header.
    $sldConfidence.Add_ValueChanged({
        $txtConfReadout.Text = [string][int]$sldConfidence.Value
    })

    # Mutable result state.  Hashtable = reference type; handlers
    # mutate in place, post-ShowDialog readback sees the final values.
    # Save and Patch are INDEPENDENT -- both can be true if the author
    # saved then exported a patch on the same draft.
    $state = @{
        Saved          = $false
        SavedPath      = $null
        Patched        = $false
        PatchedPath    = $null
        TargetRepoPath = $null
        Draft          = $null
    }

    # Resolve the dialog status strip (the new inline status line at
    # the bottom of the dialog; replaces close-on-success UX).
    $txtDialogStatus = $dlg.FindName('txtDialogStatus')

    # Build a fresh draft snapshot from the current form values.  Runs
    # each time Preview / Save / Submit fires so the user sees exactly
    # what would be persisted.  $draft (seed) stays untouched so the
    # when.all / when.none conditions + id survive unchanged.
    $getCurrentDraft = {
        $current = $draft | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        $current.scope      = [string]$cmbScope.SelectedItem
        $current.confidence = [int]$sldConfidence.Value
        $current.verdict    = [string]$txtVerdict.Text
        $current.fix        = [string]$txtFix.Text
        $selected = New-Object System.Collections.Generic.List[object]
        foreach ($r in $evidenceRefs) {
            if ($r.CheckBox.IsChecked) {
                $selected.Add([pscustomobject]@{
                    component = [string]$r.Evidence.component
                    match     = [string]$r.Evidence.match
                })
            }
        }
        $current.evidence = $selected.ToArray()
        return $current
    }

    # Preview: re-run Get-LATDraftPreview against current + stored
    # incidents, paint the text-table into the preview pane.  Schema
    # failures land here too (readable) rather than dying silently.
    $btnPreview.Add_Click({
        try {
            $current = & $getCurrentDraft
            $preview = Get-LATDraftPreview -DraftRule $current -CurrentParseResult $ParseResult
            $txtPreview.Text = Format-LATDraftPreviewTable -Preview $preview
        } catch {
            $txtPreview.Text = "Preview failed: $($_.Exception.Message)"
        }
    })

    # Save: write to %LOCALAPPDATA%\LogAnalyzer\rules\<id>.json.  Non-
    # terminal -- updates the status strip and stays open so the author
    # can keep editing.  Flips the Cancel button to "Close" once any
    # persistent action has fired (there is no unsaved work to warn
    # about).
    $btnSave.Add_Click({
        try {
            $current = & $getCurrentDraft
            $path = Save-LATRuleDraft -Rule $current -Force
            $state.Saved     = $true
            $state.SavedPath = $path
            $state.Draft     = $current
            $txtDialogStatus.Text = "Saved: $path"
            $btnCancel.Content = 'Close'
        } catch {
            $txtDialogStatus.Text = "Save failed: $($_.Exception.Message)"
        }
    })

    # Submit patch: emit a git-applicable diff under c:/temp/ and copy
    # the body to clipboard.  Non-terminal for the same reason as Save.
    $btnSubmit.Add_Click({
        try {
            $current = & $getCurrentDraft
            $result  = Export-LATRulePatch -Rule $current -CopyToClipboard -Force
            $state.Patched        = $true
            $state.PatchedPath    = $result.Path
            $state.TargetRepoPath = $result.TargetRepoPath
            $state.Draft          = $current
            $txtDialogStatus.Text = "Patch exported: $($result.Path)  (clipboard updated)"
            $btnCancel.Content = 'Close'
        } catch {
            $txtDialogStatus.Text = "Patch export failed: $($_.Exception.Message)"
        }
    })

    # Cancel / Close: state reflects whatever was done.  If neither
    # Save nor Patch fired, this is a cancellation.
    $btnCancel.Add_Click({ $dlg.Close() })

    [void]$dlg.ShowDialog()

    return [pscustomobject]@{
        Saved          = [bool]$state.Saved
        SavedPath      = $state.SavedPath
        Patched        = [bool]$state.Patched
        PatchedPath    = $state.PatchedPath
        TargetRepoPath = $state.TargetRepoPath
        Cancelled      = -not ($state.Saved -or $state.Patched)
        Draft          = $state.Draft
    }
}
