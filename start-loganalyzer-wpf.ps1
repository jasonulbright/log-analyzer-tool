<#
.SYNOPSIS
    WPF shell for Log Analyzer Tool (decision-engine era).

.DESCRIPTION
    Scaffold shell introduced in Session 10 of the decision-engine pivot.
    The old WinForms entry point start-loganalyzer.ps1 stays alongside
    this one until the WPF surface is feature-complete (Session 14).

    This launcher:
      - Loads MahApps DLLs from .\Lib\
      - Parses MainWindow.xaml
      - Wires sidebar button clicks to swap the ContentControl content
        by loading the matching Modules/<Name>/<Name>.xaml UserControl
      - Wires the sidebar theme toggle (Dark.Steel / Light.Blue)
      - Invokes nothing data-side (Session 11 wires the evaluator)

    -TestMode parses XAML, constructs the window without Show()-ing it,
    and exits. Used by Tests/WpfShell.Tests.ps1 for CI-friendly
    smoke tests.

.PARAMETER TestMode
    Parse + construct, do NOT show the window. Returns $true on success.

.EXAMPLE
    .\start-loganalyzer-wpf.ps1
    .\start-loganalyzer-wpf.ps1 -TestMode
#>
[CmdletBinding()]
param(
    [switch]$TestMode
)

$ErrorActionPreference = 'Stop'

# =============================================================================
# Assembly loading (must happen before XAML parse)
# =============================================================================
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

$libDir = Join-Path $PSScriptRoot 'Lib'
[System.Reflection.Assembly]::LoadFrom((Join-Path $libDir 'Microsoft.Xaml.Behaviors.dll')) | Out-Null
[System.Reflection.Assembly]::LoadFrom((Join-Path $libDir 'ControlzEx.dll'))                | Out-Null
[System.Reflection.Assembly]::LoadFrom((Join-Path $libDir 'MahApps.Metro.dll'))             | Out-Null

# =============================================================================
# Data-layer modules (dot-sourced so module init scripts can call them)
# =============================================================================
$moduleDir = Join-Path $PSScriptRoot 'Module'
. (Join-Path $moduleDir 'Test-LATRule.ps1')
. (Join-Path $moduleDir 'Invoke-RuleEvaluator.ps1')
. (Join-Path $moduleDir 'LATIncident.ps1')
. (Join-Path $moduleDir 'LATRuleWizard.ps1')
. (Join-Path $moduleDir 'LATRuleSave.ps1')
. (Join-Path $moduleDir 'LATTriageVM.ps1')
# LogAnalyzerCommon is the existing v1.6 parsing + signature-detection
# pipeline. Triage reuses it verbatim.
Import-Module (Join-Path $moduleDir 'LogAnalyzerCommon.psd1') -Force -DisableNameChecking

# =============================================================================
# Config
# =============================================================================
$script:LAT_ModuleRoot     = Join-Path $PSScriptRoot 'Modules'
$script:LAT_MainWindowXaml = Join-Path $PSScriptRoot 'MainWindow.xaml'
$script:LAT_BaselineRoot   = Join-Path $PSScriptRoot 'Rules\Baseline'
$script:LAT_LoadedRules    = $null  # lazy

# Ordered list drives sidebar enumeration. Real metadata comes from
# per-module module.json at load time.
$script:LAT_Modules = @('Triage','History','KB','Wizard','Settings')

# Dot-source every module entry script at the launcher's top level.
# Dot-sourcing INSIDE a later function (previous approach) put the init
# functions into that function's local scope, so when a WPF event handler
# fired after the function had returned it could not resolve sibling
# helpers like New-LATParseResultFromLogFiles. Top-level sourcing keeps
# everything in the launcher's script scope, which lives for the shell's
# lifetime.
foreach ($mod in $script:LAT_Modules) {
    $manifestPath = Join-Path $script:LAT_ModuleRoot "$mod\module.json"
    if (-not (Test-Path -LiteralPath $manifestPath)) { continue }
    try {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $entry = Join-Path $script:LAT_ModuleRoot "$mod\$($manifest.EntryScript)"
        if (Test-Path -LiteralPath $entry) { . $entry }
    } catch {
        Write-Warning "Failed to load module $mod`: $($_.Exception.Message)"
    }
}

# =============================================================================
# Title-bar drag fallback. PS51-WPF-033.
# Some VS Code PowerShell launch contexts can leave MahApps' custom title
# thumb unable to initiate native window move. Install a WM_NCHITTEST hook
# returning HTCAPTION for the title band, plus a managed DragMove fallback
# for hosts where HwndSource cannot be hooked. Wire on every MetroWindow
# (main window and every modal popup -- e.g., WizardDialog).
# =============================================================================
$script:TitleBarHitTestWindows = @{}
$script:TitleBarHitTestHooks   = @{}

function Get-TitleBarDragHeight {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    try {
        $h = [double]$Window.TitleBarHeight
        if ($h -gt 0 -and -not [double]::IsNaN($h)) { return $h }
    } catch { $null = $_ }
    return 30.0
}

function Get-InputAncestors {
    param([System.Windows.DependencyObject]$Start)
    $cur = $Start
    while ($cur) {
        $cur
        $parent = $null
        if ($cur -is [System.Windows.Media.Visual] -or $cur -is [System.Windows.Media.Media3D.Visual3D]) {
            try { $parent = [System.Windows.Media.VisualTreeHelper]::GetParent($cur) } catch { $parent = $null }
        }
        if (-not $parent -and $cur -is [System.Windows.FrameworkElement]) { $parent = $cur.Parent }
        if (-not $parent -and $cur -is [System.Windows.FrameworkContentElement]) { $parent = $cur.Parent }
        if (-not $parent -and $cur -is [System.Windows.ContentElement]) {
            try { $parent = [System.Windows.ContentOperations]::GetParent($cur) } catch { $parent = $null }
        }
        $cur = $parent
    }
}

function Test-IsWindowCommandPoint {
    param([MahApps.Metro.Controls.MetroWindow]$Window, [System.Windows.Point]$Point)
    try {
        [void]$Window.ApplyTemplate()
        $commands = $Window.Template.FindName('PART_WindowButtonCommands', $Window)
        if ($commands -and $commands.IsVisible -and $commands.ActualWidth -gt 0 -and $commands.ActualHeight -gt 0) {
            $origin = $commands.TransformToAncestor($Window).Transform([System.Windows.Point]::new(0, 0))
            if ($Point.X -ge $origin.X -and $Point.X -le ($origin.X + $commands.ActualWidth) -and
                $Point.Y -ge $origin.Y -and $Point.Y -le ($origin.Y + $commands.ActualHeight)) {
                return $true
            }
        }
    } catch { $null = $_ }
    return ($Window.ActualWidth -gt 150 -and $Point.X -ge ($Window.ActualWidth - 150))
}

function Add-NativeTitleBarHitTestHook {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    try {
        $helper = [System.Windows.Interop.WindowInteropHelper]::new($Window)
        $source = [System.Windows.Interop.HwndSource]::FromHwnd($helper.Handle)
        if (-not $source) { return }
        $key = $helper.Handle.ToInt64().ToString()
        if ($script:TitleBarHitTestHooks.ContainsKey($key)) { return }
        $script:TitleBarHitTestWindows[$key] = $Window
        $hook = [System.Windows.Interop.HwndSourceHook]{
            param([IntPtr]$hwnd, [int]$msg, [IntPtr]$wParam, [IntPtr]$lParam, [ref]$handled)
            $WM_NCHITTEST = 0x0084; $HTCAPTION = 2
            if ($msg -ne $WM_NCHITTEST) { return [IntPtr]::Zero }
            try {
                $target = $script:TitleBarHitTestWindows[$hwnd.ToInt64().ToString()]
                if (-not $target) { return [IntPtr]::Zero }
                $raw = $lParam.ToInt64()
                $screenX = [int]($raw -band 0xffff); if ($screenX -ge 0x8000) { $screenX -= 0x10000 }
                $screenY = [int](($raw -shr 16) -band 0xffff); if ($screenY -ge 0x8000) { $screenY -= 0x10000 }
                $pt = $target.PointFromScreen([System.Windows.Point]::new($screenX, $screenY))
                $titleBarH = Get-TitleBarDragHeight -Window $target
                if ($pt.X -lt 0 -or $pt.X -gt $target.ActualWidth) { return [IntPtr]::Zero }
                if ($pt.Y -lt 4 -or $pt.Y -gt $titleBarH) { return [IntPtr]::Zero }
                if (Test-IsWindowCommandPoint -Window $target -Point $pt) { return [IntPtr]::Zero }
                $handled.Value = $true
                return [IntPtr]$HTCAPTION
            } catch { return [IntPtr]::Zero }
        }
        $script:TitleBarHitTestHooks[$key] = $hook
        $source.AddHook($hook)
    } catch { $null = $_ }
}

function Remove-NativeTitleBarHitTestHook {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    try {
        $helper = [System.Windows.Interop.WindowInteropHelper]::new($Window)
        $key = $helper.Handle.ToInt64().ToString()
        if ($script:TitleBarHitTestHooks.ContainsKey($key)) {
            $source = [System.Windows.Interop.HwndSource]::FromHwnd($helper.Handle)
            if ($source) { $source.RemoveHook($script:TitleBarHitTestHooks[$key]) }
            $script:TitleBarHitTestHooks.Remove($key)
        }
        if ($script:TitleBarHitTestWindows.ContainsKey($key)) {
            $script:TitleBarHitTestWindows.Remove($key)
        }
    } catch { $null = $_ }
}

function Install-TitleBarDragFallback {
    param([MahApps.Metro.Controls.MetroWindow]$Window)
    $Window.Add_SourceInitialized({ param($s, $e) Add-NativeTitleBarHitTestHook -Window $s })
    $Window.Add_Closed({ param($s, $e) Remove-NativeTitleBarHitTestHook -Window $s })
    $Window.Add_PreviewMouseLeftButtonDown({
        param($s, $e)
        try {
            if ($s.WindowState -eq [System.Windows.WindowState]::Maximized) { return }
            $titleBarH = Get-TitleBarDragHeight -Window $s
            $pos = $e.GetPosition($s)
            if ($pos.Y -lt 4 -or $pos.Y -gt $titleBarH) { return }
            if (Test-IsWindowCommandPoint -Window $s -Point $pos) { return }
            foreach ($ancestor in Get-InputAncestors -Start ($e.OriginalSource -as [System.Windows.DependencyObject])) {
                if ($ancestor -is [System.Windows.Controls.Primitives.ButtonBase]) { return }
            }
            $s.DragMove()
            $e.Handled = $true
        } catch { $null = $_ }
    })
}

# =============================================================================
# Helpers
# =============================================================================
function Read-LATXaml {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "XAML not found: $Path" }
    $raw = Get-Content -LiteralPath $Path -Raw
    # PS 5.1 XamlReader chokes on x:Class (expects a compiled code-behind
    # type). Strip it for runtime load. Same approach as app-packager /
    # mmc-if launchers.
    $raw = $raw -replace 'x:Class="[^"]+"', ''
    return [xml]$raw
}

function Get-LATModuleManifest {
    param([Parameter(Mandatory)][string]$ModuleName)
    $p = Join-Path $script:LAT_ModuleRoot "$ModuleName\module.json"
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { return Get-Content -LiteralPath $p -Raw | ConvertFrom-Json }
    catch { return $null }
}

function Get-LATLoadedRules {
    # Lazy-load once per shell session. The Settings module (Session 12)
    # will expose a "Reload rules" button that clears this.
    #
    # Both the baseline bundle AND the local overlay
    # (%LOCALAPPDATA%\LogAnalyzer\rules) are passed.  Get-LATRules
    # handles a missing overlay directory silently, so a first-run user
    # who has not yet saved a rule gets exactly the baseline set.  The
    # overlay wins on id collision (see Get-LATRules doc).
    if ($null -ne $script:LAT_LoadedRules) { return $script:LAT_LoadedRules }
    $overlayRoot = Get-LATLocalOverlayRoot
    $script:LAT_LoadedRules = @(Get-LATRules `
        -BaselinePath $script:LAT_BaselineRoot `
        -LocalPath    $overlayRoot `
        -WarningAction SilentlyContinue)
    return $script:LAT_LoadedRules
}

function Load-LATModule {
    param(
        [Parameter(Mandatory)][string]$ModuleName,
        [Parameter(Mandatory)][System.Windows.Controls.ContentControl]$ContentHost,
        [System.Windows.Controls.TextBlock]$TitleBlock,
        [System.Windows.Controls.TextBlock]$SubtitleBlock,
        [Parameter(Mandatory)][hashtable]$ModuleContext
    )
    $manifest = Get-LATModuleManifest -ModuleName $ModuleName
    if (-not $manifest) {
        throw "Module manifest not found: $ModuleName/module.json"
    }
    $fnName = $manifest.InitFunction
    $fn = Get-Item -LiteralPath "function:\$fnName" -ErrorAction SilentlyContinue
    if (-not $fn) {
        throw "Module init function '$fnName' not registered. Was Modules/$ModuleName/$($manifest.EntryScript) dot-sourced at launcher startup?"
    }
    $view = & $fnName -Context $ModuleContext
    if (-not $view) { throw "$ModuleName init returned no view" }
    $ContentHost.Content = $view
    if ($TitleBlock   -and $manifest.Title)    { $TitleBlock.Text    = $manifest.Title }
    if ($SubtitleBlock -and $manifest.Subtitle) { $SubtitleBlock.Text = $manifest.Subtitle }
    return $view
}

function Set-LATTheme {
    param(
        [Parameter(Mandatory)][System.Windows.Window]$Window,
        [Parameter(Mandatory)][bool]$Dark,
        [System.Windows.Controls.TextBlock]$ThemeLabel
    )
    $uri = if ($Dark) {
        'pack://application:,,,/MahApps.Metro;component/Styles/Themes/Dark.Steel.xaml'
    } else {
        'pack://application:,,,/MahApps.Metro;component/Styles/Themes/Light.Blue.xaml'
    }
    $dict = New-Object System.Windows.ResourceDictionary
    $dict.Source = [uri]$uri

    # Swap the last theme dictionary (always loaded last per our MainWindow
    # merged-dictionary order). Safer than appending, which grows the list.
    $dicts = $Window.Resources.MergedDictionaries
    if ($dicts.Count -gt 0) {
        $dicts.RemoveAt($dicts.Count - 1)
    }
    $dicts.Add($dict)

    if ($ThemeLabel) {
        $ThemeLabel.Text = if ($Dark) { 'Dark Theme' } else { 'Light Theme' }
    }
}

# =============================================================================
# Build window
# =============================================================================
function New-LATMainWindow {
    $xaml = Read-LATXaml -Path $script:LAT_MainWindowXaml
    $reader = New-Object System.Xml.XmlNodeReader $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)
    Install-TitleBarDragFallback -Window $window

    # Resolve named elements
    $contentHost   = $window.FindName('contentHost')
    $txtTitle      = $window.FindName('txtModuleTitle')
    $txtSubtitle   = $window.FindName('txtModuleSubtitle')
    $txtLog        = $window.FindName('txtLog')
    $txtStatus     = $window.FindName('txtStatus')
    $txtAppVersion = $window.FindName('txtAppVersion')
    $toggleTheme   = $window.FindName('toggleTheme')
    $txtThemeLabel = $window.FindName('txtThemeLabel')

    if ($txtAppVersion) { $txtAppVersion.Text = 'v1.0.0' }

    # Module context -- passed to every init function. Scriptblocks so
    # modules can update status/log without direct reference to the
    # window controls.
    $setStatus = {
        param([string]$Message)
        if ($txtStatus) { $txtStatus.Text = $Message }
    }.GetNewClosure()
    $logSink = {
        param([string]$Message, [string]$Level = 'INFO')
        if (-not $txtLog) { return }
        $line = "[{0}] {1,-5} {2}`r`n" -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
        $txtLog.AppendText($line)
        $txtLog.ScrollToEnd()
    }.GetNewClosure()
    $moduleContext = @{
        SetStatus       = $setStatus
        Log             = $logSink
        Window          = $window
        GetLoadedRules  = { Get-LATLoadedRules }
        # ReloadRules: bust the session's lazy-cache so a subsequent
        # GetLoadedRules re-scans disk.  Modules that offer an explicit
        # "Reload" action (KB / Settings) use this; Triage stays on the
        # cached accessor so a Select-Logs pass is cheap.
        ReloadRules     = { $script:LAT_LoadedRules = $null; Get-LATLoadedRules }
    }

    # Local scriptblock wrappers (Rule 8 / PS51-WPF-006). Handlers below
    # are .GetNewClosure()'d so they can fire after this factory returns;
    # GetNewClosure in flat .ps1 strips script-scope function lookup, so
    # direct calls to Load-LATModule / Set-LATTheme from handler bodies
    # throw CommandNotFoundException at click time. Plain {...} wrappers
    # carry this file's SessionStateInternal and resolve those functions
    # when invoked via `&`. See reference_pitfalls_ps51_wpf.md.
    $loadModuleSb = {
        param([string]$ModuleName, $ContentHost, $TitleBlock, $SubtitleBlock, [hashtable]$ModuleContext)
        return Load-LATModule -ModuleName $ModuleName -ContentHost $ContentHost `
                              -TitleBlock $TitleBlock -SubtitleBlock $SubtitleBlock `
                              -ModuleContext $ModuleContext
    }
    $applyThemeSb = {
        param($Window, [bool]$Dark, $ThemeLabel)
        Set-LATTheme -Window $Window -Dark $Dark -ThemeLabel $ThemeLabel
    }

    # Sidebar button wiring
    foreach ($name in $script:LAT_Modules) {
        $btn = $window.FindName("btn$name")
        if (-not $btn) { continue }
        $capture = $name
        $btn.Add_Click({
            try {
                $null = & $loadModuleSb -ModuleName $capture -ContentHost $contentHost `
                                        -TitleBlock $txtTitle -SubtitleBlock $txtSubtitle `
                                        -ModuleContext $moduleContext
                & $setStatus "Loaded module: $capture"
            } catch {
                & $logSink "Failed to load $capture`: $($_.Exception.Message)" 'ERROR'
                & $setStatus "Failed to load $capture -- see log"
            }
        }.GetNewClosure())
    }

    # Theme toggle. MahApps ToggleSwitch fires `Toggled`, not the WPF
    # IsCheckedChanged -- per the mmc-if reference impl.
    if ($toggleTheme) {
        $toggleTheme.Add_Toggled({
            $dark = [bool]$toggleTheme.IsOn
            & $applyThemeSb -Window $window -Dark $dark -ThemeLabel $txtThemeLabel
        }.GetNewClosure())
    }

    # Initial module = Triage. Suppress Load-LATModule's UserControl return
    # so it does not contaminate New-LATMainWindow's pipeline output -- a
    # polluted return would make $window an object array and .ShowDialog()
    # would blow up on the first (non-Window) element.
    $null = Load-LATModule -ModuleName 'Triage' -ContentHost $contentHost `
                           -TitleBlock $txtTitle -SubtitleBlock $txtSubtitle `
                           -ModuleContext $moduleContext

    return $window
}

# =============================================================================
# Entry point
# =============================================================================
try {
    $window = New-LATMainWindow
    # Sanity: if any helper accidentally emitted output, $window ends up
    # as an Object[] and ShowDialog() blows up on the first non-Window
    # element. Guard against the regression.
    if ($window -is [array]) {
        throw "New-LATMainWindow returned an array (length $($window.Count)). A helper is emitting output; pipe it to `$null or cast to [void]. Types: $((@($window | ForEach-Object { $_.GetType().FullName })) -join ', ')"
    }
    if ($window -isnot [System.Windows.Window]) {
        throw "New-LATMainWindow returned $($window.GetType().FullName); expected a System.Windows.Window subclass."
    }
    if ($TestMode) {
        # Headless construction complete. Drop the window and return.
        $window = $null
        return $true
    }
    $null = $window.ShowDialog()
} catch {
    Write-Error "Log Analyzer WPF shell failed to start: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
    if ($TestMode) { return $false }
    exit 1
}
