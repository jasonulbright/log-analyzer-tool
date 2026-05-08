#
# Triage module init -- Session 11.
#
# End-to-end wiring: Select Logs -> parse via LogAnalyzerCommon
# pipeline -> Invoke-RuleEvaluator -> populate verdict card bindings
# -> persist incident via New-LATIncident.
#
# Pure VM construction lives in Module/LATTriageVM.ps1 so it can be
# unit-tested without a WPF host. This file only does the UI glue.
#
# Handler scope rules (PS51-WPF-003 / Rule 8): any call to a script-scope
# LAT function from inside a .GetNewClosure()'d handler body throws
# CommandNotFoundException at click time, because GetNewClosure strips
# script-scope function lookup in flat .ps1. Every such call goes through
# a local scriptblock wrapper (plain {...}, NOT .GetNewClosure()) so the
# body executes with its own SessionStateInternal -- which is this file's
# script scope, which is the launcher's script scope (dot-sourced), where
# the data-layer functions live. See reference_pitfalls_ps51_wpf.md.
#

function New-LATTriageView {
    param([hashtable]$Context)

    $setStatus = $Context.SetStatus
    $log       = $Context.Log
    $window    = $Context.Window

    $xamlPath = Join-Path $PSScriptRoot 'Triage.xaml'
    $raw      = Get-Content -LiteralPath $xamlPath -Raw
    $reader   = New-Object System.Xml.XmlNodeReader ([xml]$raw)
    $view     = [Windows.Markup.XamlReader]::Load($reader)

    # Resolve named elements up front.
    $btnSelectLogs      = $view.FindName('btnSelectLogs')
    $txtDropHint        = $view.FindName('txtDropHint')
    $txtVerdictRuleId   = $view.FindName('txtVerdictRuleId')
    $txtVerdictScope    = $view.FindName('txtVerdictScope')
    $txtVerdictHeadline = $view.FindName('txtVerdictHeadline')
    $txtConfidenceValue = $view.FindName('txtConfidenceValue')
    $barConfidence      = $view.FindName('barConfidence')
    $lstEvidence        = $view.FindName('lstEvidence')
    $lstAlternates      = $view.FindName('lstAlternateVerdicts')
    $txtFix             = $view.FindName('txtFix')
    $btnCaptureAsRule   = $view.FindName('btnCaptureAsRule')
    $btnCopyFix         = $view.FindName('btnCopyFix')

    # Cached triage state -- wizard + copy-fix refer to this.
    $state = [pscustomobject]@{
        ParseResult  = $null
        EvalResult   = $null
        VM           = $null  # set below via & $buildEmptyVMSb
        IncidentPath = $null
    }

    # ---- Local scriptblock wrappers (Rule 8 / PS51-WPF-006) ----------------
    #
    # Wrappers that call script-scope LAT functions are PLAIN {...} (no
    # GetNewClosure). Their SessionStateInternal carries this file's scope,
    # which resolves New-LATParseResultFromLogFiles etc. Handlers capture
    # these wrappers as factory locals via .GetNewClosure() and invoke them
    # with `&` -- the `&` runs the wrapper body in its own SessionState, so
    # script-scope function lookup works.
    #
    # $applyVMSb is the only wrapper that uses .GetNewClosure(), because it
    # reads captured local control refs and never calls a script-scope LAT
    # function.

    $applyVMSb = {
        param($VM)
        $txtVerdictRuleId.Text     = $VM.RuleId
        $txtVerdictScope.Text      = $VM.Scope
        $txtVerdictHeadline.Text   = $VM.Headline
        $txtConfidenceValue.Text   = $VM.ConfidenceText
        $barConfidence.Value       = [double]$VM.ConfidencePercent
        $txtFix.Text               = $VM.Fix
        $lstEvidence.ItemsSource   = $VM.Evidence
        $lstAlternates.ItemsSource = $VM.AlternateVerdicts
        $btnCaptureAsRule.IsEnabled = [bool]$VM.ActionButtonsEnabled
        $btnCopyFix.IsEnabled       = [bool]($VM.ActionButtonsEnabled -and $VM.Fix)
    }.GetNewClosure()

    $buildEmptyVMSb = {
        return New-LATEmptyVerdictCardVM
    }

    $runAnalysisSb = {
        param([string[]]$Paths, $GetLoadedRules)
        $parse = New-LATParseResultFromLogFiles -Paths $Paths
        $rules = & $GetLoadedRules
        $eval  = Invoke-RuleEvaluator -ParseResult $parse -Rules $rules
        $vm    = New-LATVerdictCardVM -EvalResult $eval
        return [pscustomobject]@{ Parse = $parse; Eval = $eval; VM = $vm }
    }

    $persistIncidentSb = {
        param($ParseResult, $EvalResult, [string]$Label, [string[]]$LogFiles)
        return New-LATIncident -ParseResult $ParseResult -EvalResult $EvalResult `
                               -Label $Label -LogFiles $LogFiles
    }

    # Session 11c: Capture-as-Rule now routes through the WPF wizard
    # dialog (Show-LATRuleWizardDialog, defined in
    # Modules/Wizard/WizardDialog.ps1 and dot-sourced at launcher scope
    # via Wizard.ps1).  The wrapper stays plain {...} so invocation via
    # `&` runs in script scope, which can resolve Show-LATRuleWizardDialog.
    $showWizardSb = {
        param([System.Windows.Window]$Owner, $ParseResult, $EvalResult, [hashtable]$Context)
        return Show-LATRuleWizardDialog -Owner $Owner -ParseResult $ParseResult `
                                        -EvalResult $EvalResult -Context $Context
    }

    # Seed the verdict card with the empty-state VM. Runs synchronously
    # before the factory returns, so the wrapper invocation resolves its
    # script-scope call via normal lexical scope.
    $state.VM = & $buildEmptyVMSb
    & $applyVMSb -VM $state.VM

    # ---- Select Logs handler -----------------------------------------------
    $btnSelectLogs.Add_Click({
        try {
            $dlg = New-Object Microsoft.Win32.OpenFileDialog
            $dlg.Title = 'Select MECM client logs to triage'
            $dlg.Filter = 'Log files (*.log;*.lo_)|*.log;*.lo_|All files (*.*)|*.*'
            $dlg.Multiselect = $true
            $dlg.CheckFileExists = $true
            $null = $dlg.ShowDialog($window)
            if (-not $dlg.FileNames -or @($dlg.FileNames).Count -eq 0) { return }
            $paths = @($dlg.FileNames)
            & $log -Message ("Triage: selected {0} log file(s)" -f $paths.Count) -Level 'INFO'
            & $setStatus -Message "Parsing $($paths.Count) log(s)..."

            # Parse + evaluate + build VM. Wrapper invocation carries the
            # launcher script scope, so script-scope data-layer calls resolve.
            $result = & $runAnalysisSb -Paths $paths -GetLoadedRules $Context.GetLoadedRules
            $state.ParseResult = $result.Parse
            $state.EvalResult  = $result.Eval
            $state.VM          = $result.VM
            & $applyVMSb -VM $result.VM

            # Persist the incident bundle so wizard preview + history module
            # can reference it.
            try {
                $label = [System.IO.Path]::GetFileNameWithoutExtension($paths[0])
                $state.IncidentPath = & $persistIncidentSb -ParseResult $result.Parse `
                                                          -EvalResult $result.Eval `
                                                          -Label $label -LogFiles $paths
                & $log -Message "Incident stored at $($state.IncidentPath)" -Level 'INFO'
            } catch {
                & $log -Message "Incident persist failed: $($_.Exception.Message)" -Level 'WARN'
            }

            $entryCount   = @($result.Parse.Entries).Count
            $matchedCount = @($result.Eval.AllMatches).Count
            & $setStatus -Message "Analyzed $entryCount entries -- $matchedCount rule(s) fired"
            & $log -Message ("Triage: {0} matches against rulebase; top={1}" -f $matchedCount, $result.VM.RuleId) -Level 'INFO'
            $txtDropHint.Text = "Analyzed $entryCount entries from $($paths.Count) log(s)."
        } catch {
            & $log -Message "Triage failed: $($_.Exception.Message)" -Level 'ERROR'
            & $setStatus -Message "Triage failed -- see log"
        }
    }.GetNewClosure())

    # ---- Copy Fix handler --------------------------------------------------
    # Set-Clipboard is a built-in cmdlet, not a script-scope function, so
    # it is resolvable inside GetNewClosure. No wrapper needed.
    $btnCopyFix.Add_Click({
        try {
            if ($state.VM.Fix) {
                Set-Clipboard -Value $state.VM.Fix
                & $setStatus -Message 'Fix copied to clipboard'
            }
        } catch {
            & $log -Message "Copy Fix failed: $($_.Exception.Message)" -Level 'WARN'
        }
    }.GetNewClosure())

    # ---- Capture as Rule handler (Session 11c: WPF wizard dialog) ---------
    #
    # Opens the themed MetroWindow wizard (Show-LATRuleWizardDialog) where
    # the user can edit verdict / fix / scope / confidence / evidence,
    # preview the draft against the current + stored incidents, and save
    # to the local overlay or export an upstream patch.  Three return
    # actions are handled: saved, patched, cancelled.
    $btnCaptureAsRule.Add_Click({
        try {
            if (-not $state.ParseResult) {
                & $setStatus -Message 'No triage loaded -- nothing to capture'
                return
            }
            $result = & $showWizardSb -Owner $window `
                                      -ParseResult $state.ParseResult `
                                      -EvalResult  $state.EvalResult `
                                      -Context     $Context
            # Save and Patch are independent; report whichever happened.
            if ($result.Saved) {
                & $log -Message "Captured as rule: $($result.SavedPath)" -Level 'INFO'
            }
            if ($result.Patched) {
                & $log -Message "Patch written: $($result.PatchedPath) -> $($result.TargetRepoPath) (clipboard updated)" -Level 'INFO'
            }
            if ($result.Saved -and $result.Patched) {
                & $setStatus -Message "Rule saved + patch exported"
            } elseif ($result.Saved) {
                & $setStatus -Message "Rule saved: $([System.IO.Path]::GetFileName($result.SavedPath))"
            } elseif ($result.Patched) {
                & $setStatus -Message "Patch written: $([System.IO.Path]::GetFileName($result.PatchedPath))"
            } else {
                & $setStatus -Message 'Capture cancelled'
            }
        } catch {
            & $log -Message "Capture failed: $($_.Exception.Message)" -Level 'ERROR'
            & $setStatus -Message "Capture failed -- see log"
        }
    }.GetNewClosure())

    return $view
}
