<#
.SYNOPSIS
    WinForms front-end for LogAnalyzerTool (LAT) - MECM log analysis and error interpretation.

.DESCRIPTION
    Provides a GUI for analyzing MECM client logs from remote devices.
    On launch, performs LOCAL-ONLY operations (no network access).
    Network operations occur only when the user clicks Analyze.

    Features:
      - Retrieve MECM client logs from devices via ADMIN$ share
      - Parse CMTrace-format log files
      - Translate error codes to plain English
      - Detect 3010 exit code masking
      - Identify root causes (firewall, DNS, domain, MPP corruption)
      - Export results to CSV or HTML

.EXAMPLE
    .\start-loganalyzer.ps1

.NOTES
    Requirements:
      - PowerShell 5.1
      - .NET Framework 4.8+
      - Windows Forms (System.Windows.Forms)
      - ADMIN$ share access to target devices

    ScriptName : start-loganalyzer.ps1
    Purpose    : WinForms front-end for MECM log analysis
    Version    : 1.0.0
    Updated    : 2026-02-25
#>

param()

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()
try { [System.Windows.Forms.Application]::SetCompatibleTextRenderingDefault($false) } catch { }

$moduleRoot = Join-Path $PSScriptRoot "Module"
Import-Module (Join-Path $moduleRoot "LogAnalyzerCommon.psd1") -Force

$errorCodesRoot = Join-Path $PSScriptRoot "ErrorCodes"
if (Test-Path -LiteralPath $errorCodesRoot) {
    Import-ErrorCodeDatabase -ErrorCodesRoot $errorCodesRoot
}

# Initialize tool logging
$toolLogFolder = Join-Path $PSScriptRoot "Logs"
if (-not (Test-Path -LiteralPath $toolLogFolder)) {
    New-Item -ItemType Directory -Path $toolLogFolder -Force | Out-Null
}
$toolLogPath = Join-Path $toolLogFolder ("LogAnalyzer-{0}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Initialize-Logging -LogPath $toolLogPath

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Set-ModernButtonStyle {
    param(
        [Parameter(Mandatory)][System.Windows.Forms.Button]$Button,
        [Parameter(Mandatory)][System.Drawing.Color]$BackColor
    )

    $Button.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $Button.FlatAppearance.BorderSize = 0
    $Button.BackColor = $BackColor
    $Button.ForeColor = [System.Drawing.Color]::White
    $Button.UseVisualStyleBackColor = $false
    $Button.Cursor = [System.Windows.Forms.Cursors]::Hand

    $hover = [System.Drawing.Color]::FromArgb(
        [Math]::Max(0, $BackColor.R - 18),
        [Math]::Max(0, $BackColor.G - 18),
        [Math]::Max(0, $BackColor.B - 18)
    )
    $down = [System.Drawing.Color]::FromArgb(
        [Math]::Max(0, $BackColor.R - 36),
        [Math]::Max(0, $BackColor.G - 36),
        [Math]::Max(0, $BackColor.B - 36)
    )

    $Button.FlatAppearance.MouseOverBackColor = $hover
    $Button.FlatAppearance.MouseDownBackColor = $down
}

function Enable-DoubleBuffer {
    param([Parameter(Mandatory)][System.Windows.Forms.Control]$Control)
    $prop = $Control.GetType().GetProperty("DoubleBuffered", [System.Reflection.BindingFlags] "Instance,NonPublic")
    if ($prop) { $prop.SetValue($Control, $true, $null) | Out-Null }
}

function Add-LogLine {
    param(
        [Parameter(Mandatory)][System.Windows.Forms.TextBox]$TextBox,
        [Parameter(Mandatory)][string]$Message
    )
    $ts = (Get-Date).ToString("HH:mm:ss")
    $line = "{0}  {1}" -f $ts, $Message

    if ([string]::IsNullOrWhiteSpace($TextBox.Text)) {
        $TextBox.Text = $line
    }
    else {
        $TextBox.AppendText([Environment]::NewLine + $line)
    }

    $TextBox.SelectionStart = $TextBox.TextLength
    $TextBox.ScrollToCaret()
}

function Save-WindowState {
    $statePath = Join-Path $PSScriptRoot "LogAnalyzer.windowstate.json"
    $state = @{
        X                = $form.Location.X
        Y                = $form.Location.Y
        Width            = $form.Size.Width
        Height           = $form.Size.Height
        Maximized        = ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Maximized)
        SplitterDistance = $splitMain.SplitterDistance
    }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
}

function Restore-WindowState {
    $statePath = Join-Path $PSScriptRoot "LogAnalyzer.windowstate.json"
    if (-not (Test-Path -LiteralPath $statePath)) { return }

    try {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($state.Maximized) {
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Maximized
        } else {
            $form.Location = New-Object System.Drawing.Point($state.X, $state.Y)
            $form.Size = New-Object System.Drawing.Size($state.Width, $state.Height)
        }
        if ($state.SplitterDistance) {
            $splitMain.SplitterDistance = [int]$state.SplitterDistance
        }
    } catch { }
}

# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------

function Get-LatPreferences {
    $prefsPath = Join-Path $PSScriptRoot "LogAnalyzer.prefs.json"
    $defaults = @{ DarkMode = $false }

    if (Test-Path -LiteralPath $prefsPath) {
        try {
            $loaded = Get-Content -LiteralPath $prefsPath -Raw | ConvertFrom-Json
            if ($null -ne $loaded.DarkMode) { $defaults.DarkMode = [bool]$loaded.DarkMode }
        } catch { }
    }

    return $defaults
}

function Save-LatPreferences {
    param([hashtable]$Prefs)
    $prefsPath = Join-Path $PSScriptRoot "LogAnalyzer.prefs.json"
    $Prefs | ConvertTo-Json | Set-Content -LiteralPath $prefsPath -Encoding UTF8
}

$script:Prefs = Get-LatPreferences

# ---------------------------------------------------------------------------
# Colors (theme-aware)
# ---------------------------------------------------------------------------

$clrAccent = [System.Drawing.Color]::FromArgb(0, 120, 212)

if ($script:Prefs.DarkMode) {
    $clrFormBg     = [System.Drawing.Color]::FromArgb(30, 30, 30)
    $clrPanelBg    = [System.Drawing.Color]::FromArgb(40, 40, 40)
    $clrHint       = [System.Drawing.Color]::FromArgb(140, 140, 140)
    $clrSubtitle   = [System.Drawing.Color]::FromArgb(180, 200, 220)
    $clrGridAlt    = [System.Drawing.Color]::FromArgb(48, 48, 48)
    $clrGridLine   = [System.Drawing.Color]::FromArgb(60, 60, 60)
    $clrDetailBg   = [System.Drawing.Color]::FromArgb(45, 45, 45)
    $clrSepLine    = [System.Drawing.Color]::FromArgb(55, 55, 55)
    $clrLogBg      = [System.Drawing.Color]::FromArgb(35, 35, 35)
    $clrLogFg      = [System.Drawing.Color]::FromArgb(200, 200, 200)
    $clrText       = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $clrGridText   = [System.Drawing.Color]::FromArgb(220, 220, 220)
    $clrErrText    = [System.Drawing.Color]::FromArgb(255, 100, 100)
    $clrWarnText   = [System.Drawing.Color]::FromArgb(255, 200, 80)
} else {
    $clrFormBg     = [System.Drawing.Color]::FromArgb(245, 246, 248)
    $clrPanelBg    = [System.Drawing.Color]::White
    $clrHint       = [System.Drawing.Color]::FromArgb(140, 140, 140)
    $clrSubtitle   = [System.Drawing.Color]::FromArgb(220, 230, 245)
    $clrGridAlt    = [System.Drawing.Color]::FromArgb(248, 250, 252)
    $clrGridLine   = [System.Drawing.Color]::FromArgb(230, 230, 230)
    $clrDetailBg   = [System.Drawing.Color]::FromArgb(250, 250, 250)
    $clrSepLine    = [System.Drawing.Color]::FromArgb(218, 220, 224)
    $clrLogBg      = [System.Drawing.Color]::White
    $clrLogFg      = [System.Drawing.Color]::Black
    $clrText       = [System.Drawing.Color]::Black
    $clrGridText   = [System.Drawing.Color]::Black
    $clrErrText    = [System.Drawing.Color]::FromArgb(180, 0, 0)
    $clrWarnText   = [System.Drawing.Color]::FromArgb(180, 120, 0)
}

# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------

function Show-PreferencesDialog {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Preferences"
    $dlg.Size = New-Object System.Drawing.Size(420, 280)
    $dlg.MinimumSize = $dlg.Size
    $dlg.MaximumSize = $dlg.Size
    $dlg.StartPosition = "CenterParent"
    $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.ShowInTaskbar = $false
    $dlg.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
    $dlg.BackColor = $clrFormBg

    # Dark mode
    $grpAppearance = New-Object System.Windows.Forms.GroupBox
    $grpAppearance.Text = "Appearance"
    $grpAppearance.SetBounds(16, 12, 372, 60)
    $grpAppearance.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $grpAppearance.ForeColor = $clrText
    $grpAppearance.BackColor = $clrFormBg
    $dlg.Controls.Add($grpAppearance)

    $chkDark = New-Object System.Windows.Forms.CheckBox
    $chkDark.Text = "Enable dark mode (requires restart)"
    $chkDark.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $chkDark.AutoSize = $true
    $chkDark.Location = New-Object System.Drawing.Point(14, 24)
    $chkDark.Checked = $script:Prefs.DarkMode
    $chkDark.ForeColor = $clrText
    $chkDark.BackColor = $clrFormBg
    $grpAppearance.Controls.Add($chkDark)

    # Future settings (disabled placeholders)
    $grpFuture = New-Object System.Windows.Forms.GroupBox
    $grpFuture.Text = "MECM Connection (coming soon)"
    $grpFuture.SetBounds(16, 82, 372, 100)
    $grpFuture.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $grpFuture.ForeColor = $clrHint
    $grpFuture.BackColor = $clrFormBg
    $dlg.Controls.Add($grpFuture)

    $lblSiteCode = New-Object System.Windows.Forms.Label
    $lblSiteCode.Text = "Site Code:"
    $lblSiteCode.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblSiteCode.Location = New-Object System.Drawing.Point(14, 28)
    $lblSiteCode.AutoSize = $true
    $lblSiteCode.ForeColor = $clrHint
    $grpFuture.Controls.Add($lblSiteCode)

    $txtSiteCode = New-Object System.Windows.Forms.TextBox
    $txtSiteCode.SetBounds(130, 25, 80, 24)
    $txtSiteCode.Enabled = $false
    $txtSiteCode.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $grpFuture.Controls.Add($txtSiteCode)

    $lblServer = New-Object System.Windows.Forms.Label
    $lblServer.Text = "Primary Server:"
    $lblServer.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblServer.Location = New-Object System.Drawing.Point(14, 60)
    $lblServer.AutoSize = $true
    $lblServer.ForeColor = $clrHint
    $grpFuture.Controls.Add($lblServer)

    $txtServer = New-Object System.Windows.Forms.TextBox
    $txtServer.SetBounds(130, 57, 220, 24)
    $txtServer.Enabled = $false
    $txtServer.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $grpFuture.Controls.Add($txtServer)

    # OK / Cancel
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = "OK"
    $btnOK.Size = New-Object System.Drawing.Size(90, 32)
    $btnOK.Location = New-Object System.Drawing.Point(208, 196)
    $btnOK.DialogResult = [System.Windows.Forms.DialogResult]::OK
    Set-ModernButtonStyle -Button $btnOK -BackColor $clrAccent
    $dlg.Controls.Add($btnOK)
    $dlg.AcceptButton = $btnOK

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Size = New-Object System.Drawing.Size(90, 32)
    $btnCancel.Location = New-Object System.Drawing.Point(306, 196)
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $btnCancel.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $btnCancel.FlatAppearance.BorderColor = $clrSepLine
    $btnCancel.ForeColor = $clrText
    $btnCancel.BackColor = $clrFormBg
    $dlg.Controls.Add($btnCancel)
    $dlg.CancelButton = $btnCancel

    if ($dlg.ShowDialog($form) -eq [System.Windows.Forms.DialogResult]::OK) {
        $darkChanged = ($chkDark.Checked -ne $script:Prefs.DarkMode)
        $script:Prefs.DarkMode = $chkDark.Checked
        Save-LatPreferences -Prefs $script:Prefs

        if ($darkChanged) {
            $restart = [System.Windows.Forms.MessageBox]::Show(
                "Theme change requires a restart. Restart now?",
                "Restart Required",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($restart -eq [System.Windows.Forms.DialogResult]::Yes) {
                Start-Process powershell -ArgumentList @('-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
                $form.Close()
            }
        }
    }

    $dlg.Dispose()
}

function Show-AboutDialog {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "About Log Analyzer Tool"
    $dlg.Size = New-Object System.Drawing.Size(460, 380)
    $dlg.MinimumSize = $dlg.Size
    $dlg.MaximumSize = $dlg.Size
    $dlg.StartPosition = "CenterParent"
    $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false
    $dlg.ShowInTaskbar = $false
    $dlg.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
    $dlg.BackColor = $clrFormBg

    # Logo
    $pngPath = Join-Path $PSScriptRoot "log-analyzer.png"
    if (Test-Path -LiteralPath $pngPath) {
        $pic = New-Object System.Windows.Forms.PictureBox
        $pic.Size = New-Object System.Drawing.Size(96, 96)
        $pic.Location = New-Object System.Drawing.Point(172, 16)
        $pic.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::Zoom
        $pic.Image = [System.Drawing.Image]::FromFile($pngPath)
        $pic.BackColor = [System.Drawing.Color]::Transparent
        $dlg.Controls.Add($pic)
    }

    $lblAboutTitle = New-Object System.Windows.Forms.Label
    $lblAboutTitle.Text = "Configuration Manager LAT"
    $lblAboutTitle.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblAboutTitle.ForeColor = $clrAccent
    $lblAboutTitle.AutoSize = $true
    $lblAboutTitle.BackColor = $clrFormBg
    $lblAboutTitle.Location = New-Object System.Drawing.Point(100, 120)
    $dlg.Controls.Add($lblAboutTitle)

    $lblVersion = New-Object System.Windows.Forms.Label
    $lblVersion.Text = "Log Analyzer Tool v1.0.0"
    $lblVersion.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblVersion.ForeColor = $clrText
    $lblVersion.AutoSize = $true
    $lblVersion.BackColor = $clrFormBg
    $lblVersion.Location = New-Object System.Drawing.Point(138, 150)
    $dlg.Controls.Add($lblVersion)

    $lblDesc = New-Object System.Windows.Forms.Label
    $lblDesc.Text = ("Retrieves, parses, and translates Configuration Manager" +
        " client logs from remote devices via ADMIN`$ share." +
        " Detects error codes, 3010 exit code masking, and common root causes" +
        " including firewall blocks, DNS failures, and MPP corruption.")
    $lblDesc.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $lblDesc.ForeColor = $clrText
    $lblDesc.SetBounds(30, 180, 390, 80)
    $lblDesc.BackColor = $clrFormBg
    $lblDesc.TextAlign = [System.Drawing.ContentAlignment]::TopCenter
    $dlg.Controls.Add($lblDesc)

    $lblCopyright = New-Object System.Windows.Forms.Label
    $lblCopyright.Text = "(c) 2026 - All rights reserved"
    $lblCopyright.Font = New-Object System.Drawing.Font("Segoe UI", 8.5, [System.Drawing.FontStyle]::Italic)
    $lblCopyright.ForeColor = $clrHint
    $lblCopyright.AutoSize = $true
    $lblCopyright.BackColor = $clrFormBg
    $lblCopyright.Location = New-Object System.Drawing.Point(142, 270)
    $dlg.Controls.Add($lblCopyright)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "OK"
    $btnClose.Size = New-Object System.Drawing.Size(90, 32)
    $btnClose.Location = New-Object System.Drawing.Point(175, 300)
    $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::OK
    Set-ModernButtonStyle -Button $btnClose -BackColor $clrAccent
    $dlg.Controls.Add($btnClose)
    $dlg.AcceptButton = $btnClose

    [void]$dlg.ShowDialog($form)
    $dlg.Dispose()
}

# ---------------------------------------------------------------------------
# Form
# ---------------------------------------------------------------------------

$form = New-Object System.Windows.Forms.Form
$form.Text = "Log Analyzer Tool"
$form.StartPosition = "CenterScreen"
$form.Size = New-Object System.Drawing.Size(1280, 820)
$form.MinimumSize = New-Object System.Drawing.Size(1000, 700)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$form.BackColor = $clrFormBg
$icoPath = Join-Path $PSScriptRoot "log-analyzer.ico"
if (Test-Path -LiteralPath $icoPath) {
    $form.Icon = New-Object System.Drawing.Icon($icoPath)
} else {
    $form.Icon = [System.Drawing.SystemIcons]::Application
}

# ---------------------------------------------------------------------------
# Menu bar
# ---------------------------------------------------------------------------

# Menu strip is created here but added to the form after all other controls
# (see "Finalize menu strip" section below) so dock Z-order is correct.
$menuStrip = New-Object System.Windows.Forms.MenuStrip
$menuStrip.Dock = [System.Windows.Forms.DockStyle]::Top
$menuStrip.BackColor = $clrPanelBg
$menuStrip.ForeColor = $clrText
$menuStrip.RenderMode = [System.Windows.Forms.ToolStripRenderMode]::System

$mnuFile = New-Object System.Windows.Forms.ToolStripMenuItem("&File")
$mnuFilePrefs = New-Object System.Windows.Forms.ToolStripMenuItem("&Preferences...")
$mnuFilePrefs.Add_Click({ Show-PreferencesDialog })
$mnuFileSep = New-Object System.Windows.Forms.ToolStripSeparator
$mnuFileExit = New-Object System.Windows.Forms.ToolStripMenuItem("E&xit")
$mnuFileExit.Add_Click({ $form.Close() })
[void]$mnuFile.DropDownItems.Add($mnuFilePrefs)
[void]$mnuFile.DropDownItems.Add($mnuFileSep)
[void]$mnuFile.DropDownItems.Add($mnuFileExit)

$mnuHelp = New-Object System.Windows.Forms.ToolStripMenuItem("&Help")
$mnuHelpAbout = New-Object System.Windows.Forms.ToolStripMenuItem("&About...")
$mnuHelpAbout.Add_Click({ Show-AboutDialog })
[void]$mnuHelp.DropDownItems.Add($mnuHelpAbout)

[void]$menuStrip.Items.Add($mnuFile)
[void]$menuStrip.Items.Add($mnuHelp)
$form.MainMenuStrip = $menuStrip

# ---------------------------------------------------------------------------
# StatusStrip (Dock:Bottom - add FIRST so it stays at very bottom)
# ---------------------------------------------------------------------------

$status = New-Object System.Windows.Forms.StatusStrip
$status.BackColor = if ($script:Prefs.DarkMode) { [System.Drawing.Color]::FromArgb(45, 45, 45) } else { [System.Drawing.Color]::FromArgb(240, 240, 240) }
$status.ForeColor = $clrText
$status.Dock = [System.Windows.Forms.DockStyle]::Bottom
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = "Ready."
$statusLabel.ForeColor = $clrText
$status.Items.Add($statusLabel) | Out-Null
$form.Controls.Add($status)

# ---------------------------------------------------------------------------
# Log console panel (Dock:Bottom)
# ---------------------------------------------------------------------------

$pnlLog = New-Object System.Windows.Forms.Panel
$pnlLog.Dock = [System.Windows.Forms.DockStyle]::Bottom
$pnlLog.Height = 95
$pnlLog.Padding = New-Object System.Windows.Forms.Padding(12, 4, 12, 6)
$pnlLog.BackColor = $clrFormBg
$form.Controls.Add($pnlLog)

$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Multiline = $true
$txtLog.ReadOnly = $true
$txtLog.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtLog.BackColor = $clrLogBg
$txtLog.ForeColor = $clrLogFg
$txtLog.WordWrap = $true
$txtLog.Dock = [System.Windows.Forms.DockStyle]::Fill
$txtLog.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$pnlLog.Controls.Add($txtLog)

# ---------------------------------------------------------------------------
# Button panel (Dock:Bottom)
# ---------------------------------------------------------------------------

$pnlButtons = New-Object System.Windows.Forms.Panel
$pnlButtons.Dock = [System.Windows.Forms.DockStyle]::Bottom
$pnlButtons.Height = 53
$pnlButtons.Padding = New-Object System.Windows.Forms.Padding(12, 7, 12, 4)
$pnlButtons.BackColor = $clrFormBg
$form.Controls.Add($pnlButtons)

# 1px separator line at top of button panel (inside, not form-level)
$pnlSepButtons = New-Object System.Windows.Forms.Panel
$pnlSepButtons.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlSepButtons.Height = 1
$pnlSepButtons.BackColor = $clrSepLine
$pnlButtons.Controls.Add($pnlSepButtons)

$flowButtons = New-Object System.Windows.Forms.FlowLayoutPanel
$flowButtons.Dock = [System.Windows.Forms.DockStyle]::Fill
$flowButtons.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$flowButtons.WrapContents = $false
$flowButtons.BackColor = $clrFormBg
$pnlButtons.Controls.Add($flowButtons)

$btnExportCsv = New-Object System.Windows.Forms.Button
$btnExportCsv.Text = "Export CSV"
$btnExportCsv.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$btnExportCsv.Size = New-Object System.Drawing.Size(140, 38)
$btnExportCsv.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
Set-ModernButtonStyle -Button $btnExportCsv -BackColor ([System.Drawing.Color]::FromArgb(34, 139, 34))
$flowButtons.Controls.Add($btnExportCsv)

$btnExportHtml = New-Object System.Windows.Forms.Button
$btnExportHtml.Text = "Export HTML"
$btnExportHtml.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$btnExportHtml.Size = New-Object System.Drawing.Size(140, 38)
$btnExportHtml.Margin = New-Object System.Windows.Forms.Padding(0, 0, 10, 0)
Set-ModernButtonStyle -Button $btnExportHtml -BackColor ([System.Drawing.Color]::FromArgb(217, 95, 2))
$flowButtons.Controls.Add($btnExportHtml)

$btnCopySummary = New-Object System.Windows.Forms.Button
$btnCopySummary.Text = "Copy Summary"
$btnCopySummary.Font = New-Object System.Drawing.Font("Segoe UI", 9.5, [System.Drawing.FontStyle]::Bold)
$btnCopySummary.Size = New-Object System.Drawing.Size(160, 38)
$btnCopySummary.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
Set-ModernButtonStyle -Button $btnCopySummary -BackColor ([System.Drawing.Color]::FromArgb(100, 60, 160))
$flowButtons.Controls.Add($btnCopySummary)

# ---------------------------------------------------------------------------
# Header panel (Dock:Top)
# ---------------------------------------------------------------------------

$pnlHeader = New-Object System.Windows.Forms.Panel
$pnlHeader.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlHeader.Height = 60
$pnlHeader.BackColor = $clrAccent
$pnlHeader.Padding = New-Object System.Windows.Forms.Padding(16, 0, 16, 0)
$form.Controls.Add($pnlHeader)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.Text = "Configuration Manager LAT"
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 17, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = [System.Drawing.Color]::White
$lblTitle.AutoSize = $true
$lblTitle.BackColor = [System.Drawing.Color]::Transparent
$lblTitle.Location = New-Object System.Drawing.Point(16, 8)
$pnlHeader.Controls.Add($lblTitle)

$lblSubtitle = New-Object System.Windows.Forms.Label
$lblSubtitle.Text = "Retrieve, parse, and translate MECM client logs"
$lblSubtitle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblSubtitle.ForeColor = $clrSubtitle
$lblSubtitle.AutoSize = $true
$lblSubtitle.BackColor = [System.Drawing.Color]::Transparent
$lblSubtitle.Location = New-Object System.Drawing.Point(18, 36)
$pnlHeader.Controls.Add($lblSubtitle)

# ---------------------------------------------------------------------------
# Input panel (Dock:Top) - Devices, Scope, Time
# ---------------------------------------------------------------------------

$pnlInput = New-Object System.Windows.Forms.Panel
$pnlInput.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlInput.Height = 140
$pnlInput.BackColor = $clrPanelBg
$pnlInput.Padding = New-Object System.Windows.Forms.Padding(12, 10, 12, 6)
$form.Controls.Add($pnlInput)

# Use TableLayoutPanel for 3-column input area
$tblInput = New-Object System.Windows.Forms.TableLayoutPanel
$tblInput.Dock = [System.Windows.Forms.DockStyle]::Fill
$tblInput.ColumnCount = 3
$tblInput.RowCount = 1
[void]$tblInput.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 50)))
[void]$tblInput.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 30)))
[void]$tblInput.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 20)))
[void]$tblInput.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$tblInput.BackColor = $clrPanelBg
$pnlInput.Controls.Add($tblInput)

# -- Column 0: Devices GroupBox
$grpDevices = New-Object System.Windows.Forms.GroupBox
$grpDevices.Text = "Device(s)"
$grpDevices.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$grpDevices.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpDevices.BackColor = $clrPanelBg
$grpDevices.ForeColor = $clrText
$grpDevices.Margin = New-Object System.Windows.Forms.Padding(4)
$grpDevices.Padding = New-Object System.Windows.Forms.Padding(8, 4, 8, 4)
$tblInput.Controls.Add($grpDevices, 0, 0)

$txtDevices = New-Object System.Windows.Forms.TextBox
$txtDevices.Multiline = $true
$txtDevices.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
$txtDevices.Font = New-Object System.Drawing.Font("Consolas", 9.5)
$txtDevices.AcceptsReturn = $true
$txtDevices.Dock = [System.Windows.Forms.DockStyle]::Fill
$txtDevices.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtDevices.BackColor = $clrDetailBg
$txtDevices.ForeColor = $clrText
$grpDevices.Controls.Add($txtDevices)

$lblDevicesHint = New-Object System.Windows.Forms.Label
$lblDevicesHint.Text = "One per line, or comma-separated"
$lblDevicesHint.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblDevicesHint.ForeColor = $clrHint
$lblDevicesHint.Dock = [System.Windows.Forms.DockStyle]::Bottom
$lblDevicesHint.Height = 18
$lblDevicesHint.BackColor = $clrPanelBg
$grpDevices.Controls.Add($lblDevicesHint)

# -- Column 1: Scope GroupBox
$grpScope = New-Object System.Windows.Forms.GroupBox
$grpScope.Text = "Analysis Scope"
$grpScope.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$grpScope.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpScope.BackColor = $clrPanelBg
$grpScope.ForeColor = $clrText
$grpScope.Margin = New-Object System.Windows.Forms.Padding(4)
$grpScope.Padding = New-Object System.Windows.Forms.Padding(10, 6, 10, 6)
$tblInput.Controls.Add($grpScope, 1, 0)

$flowScope = New-Object System.Windows.Forms.FlowLayoutPanel
$flowScope.Dock = [System.Windows.Forms.DockStyle]::Fill
$flowScope.FlowDirection = [System.Windows.Forms.FlowDirection]::TopDown
$flowScope.WrapContents = $false
$flowScope.BackColor = $clrPanelBg
$grpScope.Controls.Add($flowScope)

$radAll = New-Object System.Windows.Forms.RadioButton
$radAll.Text = "All Logs"
$radAll.Checked = $true
$radAll.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$radAll.AutoSize = $true
$radAll.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)
$flowScope.Controls.Add($radAll)

$radApp = New-Object System.Windows.Forms.RadioButton
$radApp.Text = "App Deployment"
$radApp.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$radApp.AutoSize = $true
$radApp.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)
$flowScope.Controls.Add($radApp)

$radUpdates = New-Object System.Windows.Forms.RadioButton
$radUpdates.Text = "Software Updates"
$radUpdates.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$radUpdates.AutoSize = $true
$radUpdates.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)
$flowScope.Controls.Add($radUpdates)

$radClient = New-Object System.Windows.Forms.RadioButton
$radClient.Text = "Client Install"
$radClient.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$radClient.AutoSize = $true
$radClient.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)
$flowScope.Controls.Add($radClient)

# -- Column 2: Time Filter GroupBox
$grpTime = New-Object System.Windows.Forms.GroupBox
$grpTime.Text = "Time Filter"
$grpTime.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$grpTime.Dock = [System.Windows.Forms.DockStyle]::Fill
$grpTime.BackColor = $clrPanelBg
$grpTime.ForeColor = $clrText
$grpTime.Margin = New-Object System.Windows.Forms.Padding(4)
$grpTime.Padding = New-Object System.Windows.Forms.Padding(10, 10, 10, 6)
$tblInput.Controls.Add($grpTime, 2, 0)

$flowTime = New-Object System.Windows.Forms.FlowLayoutPanel
$flowTime.Dock = [System.Windows.Forms.DockStyle]::Top
$flowTime.Height = 34
$flowTime.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$flowTime.WrapContents = $false
$flowTime.BackColor = $clrPanelBg
$grpTime.Controls.Add($flowTime)

$lblLastHours = New-Object System.Windows.Forms.Label
$lblLastHours.Text = "Last"
$lblLastHours.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$lblLastHours.AutoSize = $true
$lblLastHours.Margin = New-Object System.Windows.Forms.Padding(0, 5, 4, 0)
$lblLastHours.BackColor = $clrPanelBg
$flowTime.Controls.Add($lblLastHours)

$txtHours = New-Object System.Windows.Forms.TextBox
$txtHours.Text = "24"
$txtHours.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$txtHours.Width = 50
$txtHours.MaxLength = 5
$txtHours.Margin = New-Object System.Windows.Forms.Padding(0, 2, 4, 0)
$txtHours.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtHours.BackColor = $clrDetailBg
$txtHours.ForeColor = $clrText
$flowTime.Controls.Add($txtHours)

$lblHoursUnit = New-Object System.Windows.Forms.Label
$lblHoursUnit.Text = "hours"
$lblHoursUnit.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$lblHoursUnit.AutoSize = $true
$lblHoursUnit.Margin = New-Object System.Windows.Forms.Padding(0, 5, 0, 0)
$lblHoursUnit.BackColor = $clrPanelBg
$flowTime.Controls.Add($lblHoursUnit)

# Separator line below input
$pnlSep1 = New-Object System.Windows.Forms.Panel
$pnlSep1.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlSep1.Height = 1
$pnlSep1.BackColor = $clrSepLine
$form.Controls.Add($pnlSep1)

# ---------------------------------------------------------------------------
# Filter bar (Dock:Top) - Show Info, text filter, Analyze button
# ---------------------------------------------------------------------------

$pnlFilter = New-Object System.Windows.Forms.Panel
$pnlFilter.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlFilter.Height = 44
$pnlFilter.BackColor = $clrPanelBg
$pnlFilter.Padding = New-Object System.Windows.Forms.Padding(12, 6, 12, 6)
$form.Controls.Add($pnlFilter)

$flowFilter = New-Object System.Windows.Forms.FlowLayoutPanel
$flowFilter.Dock = [System.Windows.Forms.DockStyle]::Fill
$flowFilter.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$flowFilter.WrapContents = $false
$flowFilter.BackColor = $clrPanelBg
$pnlFilter.Controls.Add($flowFilter)

$chkShowInfo = New-Object System.Windows.Forms.CheckBox
$chkShowInfo.Text = "Show Info entries"
$chkShowInfo.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$chkShowInfo.AutoSize = $true
$chkShowInfo.Margin = New-Object System.Windows.Forms.Padding(4, 5, 16, 0)
$chkShowInfo.BackColor = $clrPanelBg
$chkShowInfo.ForeColor = $clrText
$flowFilter.Controls.Add($chkShowInfo)

$lblFilter = New-Object System.Windows.Forms.Label
$lblFilter.Text = "Filter:"
$lblFilter.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblFilter.AutoSize = $true
$lblFilter.Margin = New-Object System.Windows.Forms.Padding(0, 6, 4, 0)
$lblFilter.BackColor = $clrPanelBg
$lblFilter.ForeColor = $clrText
$flowFilter.Controls.Add($lblFilter)

$txtFilter = New-Object System.Windows.Forms.TextBox
$txtFilter.Font = New-Object System.Drawing.Font("Segoe UI", 9.5)
$txtFilter.Width = 260
$txtFilter.Margin = New-Object System.Windows.Forms.Padding(0, 2, 20, 0)
$txtFilter.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtFilter.BackColor = $clrDetailBg
$txtFilter.ForeColor = $clrText
$flowFilter.Controls.Add($txtFilter)

$btnAnalyze = New-Object System.Windows.Forms.Button
$btnAnalyze.Text = "Analyze"
$btnAnalyze.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnAnalyze.Size = New-Object System.Drawing.Size(130, 30)
$btnAnalyze.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 0)
Set-ModernButtonStyle -Button $btnAnalyze -BackColor $clrAccent
$flowFilter.Controls.Add($btnAnalyze)

# Separator line below filter
$pnlSep2 = New-Object System.Windows.Forms.Panel
$pnlSep2.Dock = [System.Windows.Forms.DockStyle]::Top
$pnlSep2.Height = 1
$pnlSep2.BackColor = $clrSepLine
$form.Controls.Add($pnlSep2)

# ---------------------------------------------------------------------------
# Center area: SplitContainer with Grid (top) + Detail (bottom) - Dock:Fill
# ---------------------------------------------------------------------------

$splitMain = New-Object System.Windows.Forms.SplitContainer
$splitMain.Dock = [System.Windows.Forms.DockStyle]::Fill
$splitMain.Orientation = [System.Windows.Forms.Orientation]::Horizontal
$splitMain.SplitterDistance = 379
$splitMain.SplitterWidth = 6
$splitMain.BackColor = $clrSepLine
$splitMain.Panel1.BackColor = $clrPanelBg
$splitMain.Panel2.BackColor = $clrPanelBg
$splitMain.Panel1MinSize = 100
$splitMain.Panel2MinSize = 80
$form.Controls.Add($splitMain)

# -- Grid in Panel1
$grid = New-Object System.Windows.Forms.DataGridView
$grid.Dock = [System.Windows.Forms.DockStyle]::Fill
$grid.ReadOnly = $true
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false
$grid.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$grid.MultiSelect = $false
$grid.AutoGenerateColumns = $false
$grid.RowHeadersVisible = $false
$grid.BackgroundColor = $clrPanelBg
$grid.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$grid.CellBorderStyle = [System.Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
$grid.GridColor = $clrGridLine
$grid.ColumnHeadersDefaultCellStyle.BackColor = $clrAccent
$grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$grid.ColumnHeadersDefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$grid.ColumnHeadersDefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(4)
$grid.ColumnHeadersHeightSizeMode = [System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
$grid.ColumnHeadersHeight = 34
$grid.EnableHeadersVisualStyles = $false
$grid.DefaultCellStyle.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$grid.DefaultCellStyle.ForeColor = $clrGridText
$grid.DefaultCellStyle.BackColor = $clrPanelBg
$grid.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(2)
$grid.RowTemplate.Height = 28
$grid.AlternatingRowsDefaultCellStyle.BackColor = $clrGridAlt

Enable-DoubleBuffer -Control $grid
$splitMain.Panel1.Controls.Add($grid)

# Grid columns
$colDevice = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDevice.Name = "Device"; $colDevice.HeaderText = "Device"; $colDevice.DataPropertyName = "Device"; $colDevice.Width = 120

$colLogFile = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colLogFile.Name = "LogFile"; $colLogFile.HeaderText = "Log File"; $colLogFile.DataPropertyName = "LogFile"; $colLogFile.Width = 130

$colSeverity = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colSeverity.Name = "Severity"; $colSeverity.HeaderText = "Severity"; $colSeverity.DataPropertyName = "Severity"; $colSeverity.Width = 70

$colDateTime = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colDateTime.Name = "DateTime"; $colDateTime.HeaderText = "Date/Time"; $colDateTime.DataPropertyName = "TimeStr"; $colDateTime.Width = 140

$colComponent = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colComponent.Name = "Component"; $colComponent.HeaderText = "Component"; $colComponent.DataPropertyName = "Component"; $colComponent.Width = 120

$colErrorCode = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colErrorCode.Name = "ErrorCode"; $colErrorCode.HeaderText = "Error Code"; $colErrorCode.DataPropertyName = "ErrorCode"; $colErrorCode.Width = 100

$colTranslation = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colTranslation.Name = "Translation"; $colTranslation.HeaderText = "Translation"; $colTranslation.DataPropertyName = "Translation"; $colTranslation.Width = 250

$colMessage = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colMessage.Name = "Message"; $colMessage.HeaderText = "Message"; $colMessage.DataPropertyName = "Message"; $colMessage.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill

$grid.Columns.AddRange([System.Windows.Forms.DataGridViewColumn[]]@($colDevice, $colLogFile, $colSeverity, $colDateTime, $colComponent, $colErrorCode, $colTranslation, $colMessage))

# Data model
$dt = New-Object System.Data.DataTable
[void]$dt.Columns.Add("Device", [string])
[void]$dt.Columns.Add("LogFile", [string])
[void]$dt.Columns.Add("Severity", [string])
[void]$dt.Columns.Add("SeverityInt", [int])
[void]$dt.Columns.Add("DateTime", [datetime])
[void]$dt.Columns.Add("TimeStr", [string])
[void]$dt.Columns.Add("Component", [string])
[void]$dt.Columns.Add("ErrorCode", [string])
[void]$dt.Columns.Add("Translation", [string])
[void]$dt.Columns.Add("Message", [string])
[void]$dt.Columns.Add("FullMessage", [string])
[void]$dt.Columns.Add("Resolution", [string])
[void]$dt.Columns.Add("LogsToCheck", [string])

$grid.DataSource = $dt

# Severity color coding
$grid.Add_RowPrePaint({
    param($s, $e)
    try {
        if ($e.RowIndex -ge 0 -and $e.RowIndex -lt $dt.Rows.Count) {
            $severity = [string]$dt.Rows[$e.RowIndex]["Severity"]
            switch ($severity) {
                'Error'   { $s.Rows[$e.RowIndex].DefaultCellStyle.ForeColor = $clrErrText }
                'Warning' { $s.Rows[$e.RowIndex].DefaultCellStyle.ForeColor = $clrWarnText }
                default   { $s.Rows[$e.RowIndex].DefaultCellStyle.ForeColor = $clrGridText }
            }
        }
    } catch {}
})

# -- Detail panel in Panel2
$pnlDetailWrap = New-Object System.Windows.Forms.Panel
$pnlDetailWrap.Dock = [System.Windows.Forms.DockStyle]::Fill
$pnlDetailWrap.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 8)
$pnlDetailWrap.BackColor = $clrPanelBg
$splitMain.Panel2.Controls.Add($pnlDetailWrap)

$lblDetailTitle = New-Object System.Windows.Forms.Label
$lblDetailTitle.Text = "Entry Detail"
$lblDetailTitle.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblDetailTitle.Dock = [System.Windows.Forms.DockStyle]::Top
$lblDetailTitle.Height = 20
$lblDetailTitle.ForeColor = $clrHint
$lblDetailTitle.BackColor = $clrPanelBg
$pnlDetailWrap.Controls.Add($lblDetailTitle)

$txtDetail = New-Object System.Windows.Forms.RichTextBox
$txtDetail.ReadOnly = $true
$txtDetail.Font = New-Object System.Drawing.Font("Consolas", 9)
$txtDetail.BackColor = $clrDetailBg
$txtDetail.ForeColor = $clrText
$txtDetail.WordWrap = $true
$txtDetail.Dock = [System.Windows.Forms.DockStyle]::Fill
$txtDetail.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
$txtDetail.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$pnlDetailWrap.Controls.Add($txtDetail)
# Ensure textbox fills below the label (add label last so dock order is correct)
$txtDetail.BringToFront()

# Update detail on selection change
$grid.Add_SelectionChanged({
    if ($grid.SelectedRows.Count -eq 0) { $txtDetail.Text = ''; return }

    $rowIdx = $grid.SelectedRows[0].Index
    if ($rowIdx -lt 0 -or $rowIdx -ge $dt.Rows.Count) { $txtDetail.Text = ''; return }

    $row = $dt.Rows[$rowIdx]
    $lines = @()
    $lines += "Device:      $($row['Device'])"
    $lines += "Log File:    $($row['LogFile'])"
    $lines += "Severity:    $($row['Severity'])"
    $lines += "Date/Time:   $($row['TimeStr'])"
    $lines += "Component:   $($row['Component'])"
    $lines += ""

    $fullMsg = [string]$row['FullMessage']
    if (-not [string]::IsNullOrWhiteSpace($fullMsg)) {
        $lines += "Message:"
        $lines += $fullMsg
        $lines += ""
    }

    $ec = [string]$row['ErrorCode']
    if (-not [string]::IsNullOrWhiteSpace($ec)) {
        $lines += "Error Code:  $ec"
    }

    $trans = [string]$row['Translation']
    if (-not [string]::IsNullOrWhiteSpace($trans)) {
        $lines += "Translation: $trans"
    }

    $res = [string]$row['Resolution']
    if (-not [string]::IsNullOrWhiteSpace($res)) {
        $lines += ""
        $lines += "Resolution:  $res"
    }

    $logs = [string]$row['LogsToCheck']
    if (-not [string]::IsNullOrWhiteSpace($logs)) {
        $lines += "Check Logs:  $logs"
    }

    $txtDetail.Text = ($lines -join "`r`n")
})

# ---------------------------------------------------------------------------
# Finalize dock Z-order
# WinForms docks from BACK (index 0) to FRONT (highest index).
# Back = outermost (claims edge first).  Front = innermost (fills remaining).
#   - menuStrip (Top) at the very BACK so it is outermost top edge
#   - splitMain (Fill) at the very FRONT so it fills remaining space
# ---------------------------------------------------------------------------

$form.Controls.Add($menuStrip)
$menuStrip.SendToBack()
$splitMain.BringToFront()

# ---------------------------------------------------------------------------
# Window state persistence
# ---------------------------------------------------------------------------

$form.Add_Shown({ Restore-WindowState })
$form.Add_FormClosing({ Save-WindowState })

# ---------------------------------------------------------------------------
# Analysis state (stores results for export)
# ---------------------------------------------------------------------------

$script:AnalysisResults = @()

# ---------------------------------------------------------------------------
# Button events
# ---------------------------------------------------------------------------

$btnAnalyze.Add_Click({
    $deviceText = $txtDevices.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($deviceText)) {
        Add-LogLine -TextBox $txtLog -Message "Please enter at least one hostname."
        $statusLabel.Text = "No devices specified."
        return
    }

    # Parse time filter
    $sinceDate = $null
    $hoursText = $txtHours.Text.Trim()
    if ($hoursText -match '^\d+$') {
        $sinceDate = (Get-Date).AddHours(-[int]$hoursText)
    }

    # Resolve devices
    $devices = Resolve-DeviceList -InputText $deviceText
    if ($devices.Count -eq 0) {
        Add-LogLine -TextBox $txtLog -Message "No valid hostnames found."
        $statusLabel.Text = "No valid hostnames."
        return
    }

    # Determine scope
    $categories = @()
    if ($radApp.Checked)     { $categories = @('AppDeployment') }
    if ($radUpdates.Checked) { $categories = @('SoftwareUpdates') }
    if ($radClient.Checked)  { $categories = @('ClientInstall') }
    # radAll = empty array = all categories

    # Disable buttons during analysis
    $btnAnalyze.Enabled    = $false
    $btnExportCsv.Enabled  = $false
    $btnExportHtml.Enabled = $false
    $btnCopySummary.Enabled = $false
    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor

    # Clear previous results
    $dt.Clear()
    $txtDetail.Text = ''
    $script:AnalysisResults = @()

    $stagingRoot = Join-Path $env:TEMP "LogAnalyzer"

    Add-LogLine -TextBox $txtLog -Message "Starting analysis of $($devices.Count) device(s)..."
    $statusLabel.Text = "Analyzing..."
    [System.Windows.Forms.Application]::DoEvents()

    foreach ($hostname in $devices) {
        Add-LogLine -TextBox $txtLog -Message "Testing access to $hostname..."
        [System.Windows.Forms.Application]::DoEvents()

        $accessResult = Test-AdminShareAccess -Hostname $hostname
        if (-not $accessResult.Accessible) {
            Add-LogLine -TextBox $txtLog -Message "FAILED: Cannot access $hostname - $($accessResult.ErrorMessage)"
            continue
        }

        Add-LogLine -TextBox $txtLog -Message "Copying logs from $hostname..."
        [System.Windows.Forms.Application]::DoEvents()

        $copyParams = @{
            Hostname         = $hostname
            LocalStagingRoot = $stagingRoot
        }
        if ($categories.Count -gt 0) { $copyParams['Categories'] = $categories }
        $copyResults = Copy-RemoteLogFiles @copyParams

        $copied = @($copyResults | Where-Object { $_.CopySuccess })
        $failed = @($copyResults | Where-Object { -not $_.CopySuccess })
        Add-LogLine -TextBox $txtLog -Message "Copied $($copied.Count) log(s), $($failed.Count) failed."

        if ($copied.Count -eq 0) {
            Add-LogLine -TextBox $txtLog -Message "No logs retrieved from $hostname."
            continue
        }

        $logFolder = Join-Path $stagingRoot $hostname

        # Run analysis engines based on scope
        $results = @()

        if ($radAll.Checked -or $radApp.Checked) {
            Add-LogLine -TextBox $txtLog -Message "Analyzing app deployment logs for $hostname..."
            [System.Windows.Forms.Application]::DoEvents()
            $appResult = Invoke-AppDeploymentAnalysis -LogFolder $logFolder -Hostname $hostname -Since $sinceDate
            $results += $appResult
        }

        if ($radAll.Checked -or $radUpdates.Checked) {
            Add-LogLine -TextBox $txtLog -Message "Analyzing software update logs for $hostname..."
            [System.Windows.Forms.Application]::DoEvents()
            $updateResult = Invoke-SoftwareUpdateAnalysis -LogFolder $logFolder -Hostname $hostname -Since $sinceDate
            $results += $updateResult
        }

        if ($radAll.Checked -or $radClient.Checked) {
            Add-LogLine -TextBox $txtLog -Message "Analyzing client install logs for $hostname..."
            [System.Windows.Forms.Application]::DoEvents()
            $clientResult = Invoke-ClientInstallAnalysis -LogFolder $logFolder -Hostname $hostname -Since $sinceDate
            $results += $clientResult
        }

        # Populate grid from results
        foreach ($result in $results) {
            $script:AnalysisResults += $result

            $entries = if ($result.AllEntries) { $result.AllEntries } else { @() }
            $errorCount   = if ($result.Errors) { $result.Errors.Count } else { 0 }
            $warningCount = if ($result.Warnings) { $result.Warnings.Count } else { 0 }

            Add-LogLine -TextBox $txtLog -Message "$hostname [$($result.AnalysisType)]: $($entries.Count) entries, $errorCount error(s), $warningCount warning(s)"

            foreach ($entry in $entries) {
                $translation = ''
                $resolution  = ''
                $logsToCheck = ''

                if ($entry.ErrorTranslation -and $entry.ErrorTranslation.Found) {
                    $translation = $entry.ErrorTranslation.Message
                    $resolution  = $entry.ErrorTranslation.Resolution
                    if ($entry.ErrorTranslation.LogsToCheck) {
                        $logsToCheck = ($entry.ErrorTranslation.LogsToCheck -join ', ')
                    }
                }

                $msgTruncated = $entry.Message
                if ($msgTruncated.Length -gt 300) {
                    $msgTruncated = $msgTruncated.Substring(0, 300) + '...'
                }

                $newRow = $dt.NewRow()
                $newRow["Device"]      = $hostname
                $newRow["LogFile"]     = $entry.LogFile
                $newRow["Severity"]    = $entry.Severity
                $newRow["SeverityInt"] = $entry.Type
                $newRow["DateTime"]    = $entry.DateTime
                $newRow["TimeStr"]     = $entry.DateTime.ToString('yyyy-MM-dd HH:mm:ss')
                $newRow["Component"]   = $entry.Component
                $newRow["ErrorCode"]   = if ($entry.ErrorCode) { $entry.ErrorCode } else { '' }
                $newRow["Translation"] = $translation
                $newRow["Message"]     = $msgTruncated
                $newRow["FullMessage"] = $entry.Message
                $newRow["Resolution"]  = $resolution
                $newRow["LogsToCheck"] = $logsToCheck
                $dt.Rows.Add($newRow)
            }
        }

        [System.Windows.Forms.Application]::DoEvents()
    }

    # Apply default filter (hide Info unless checkbox is checked)
    if (-not $chkShowInfo.Checked) {
        $dt.DefaultView.RowFilter = "Severity <> 'Info'"
    }

    $totalErrors   = ($script:AnalysisResults | ForEach-Object { if ($_.Errors) { $_.Errors.Count } else { 0 } } | Measure-Object -Sum).Sum
    $totalWarnings = ($script:AnalysisResults | ForEach-Object { if ($_.Warnings) { $_.Warnings.Count } else { 0 } } | Measure-Object -Sum).Sum

    Add-LogLine -TextBox $txtLog -Message "Analysis complete. $totalErrors error(s), $totalWarnings warning(s) across $($devices.Count) device(s)."
    $statusLabel.Text = "Done: $totalErrors error(s), $totalWarnings warning(s)"

    # Re-enable buttons
    $btnAnalyze.Enabled    = $true
    $btnExportCsv.Enabled  = $true
    $btnExportHtml.Enabled = $true
    $btnCopySummary.Enabled = $true
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
})

# Show Info checkbox toggle
$chkShowInfo.Add_CheckedChanged({
    if ($chkShowInfo.Checked) {
        $dt.DefaultView.RowFilter = ""
    } else {
        $dt.DefaultView.RowFilter = "Severity <> 'Info'"
    }
})

# Text filter
$txtFilter.Add_TextChanged({
    $filterText = $txtFilter.Text.Trim()
    $baseFilter = if (-not $chkShowInfo.Checked) { "Severity <> 'Info'" } else { "" }

    if ([string]::IsNullOrWhiteSpace($filterText)) {
        $dt.DefaultView.RowFilter = $baseFilter
    } else {
        $escaped = $filterText.Replace("'", "''")
        $msgFilter = "Message LIKE '*$escaped*' OR ErrorCode LIKE '*$escaped*' OR Translation LIKE '*$escaped*' OR Component LIKE '*$escaped*'"
        if ($baseFilter) {
            $dt.DefaultView.RowFilter = "($baseFilter) AND ($msgFilter)"
        } else {
            $dt.DefaultView.RowFilter = $msgFilter
        }
    }
})

# Export CSV
$btnExportCsv.Add_Click({
    if ($script:AnalysisResults.Count -eq 0) {
        Add-LogLine -TextBox $txtLog -Message "No results to export."
        return
    }

    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "CSV Files (*.csv)|*.csv"
    $sfd.FileName = "LogAnalysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $sfd.InitialDirectory = Join-Path $PSScriptRoot "Reports"

    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Export-AnalysisCsv -Results $script:AnalysisResults -OutputPath $sfd.FileName
        Add-LogLine -TextBox $txtLog -Message "CSV exported to $($sfd.FileName)"
    }
})

# Export HTML
$btnExportHtml.Add_Click({
    if ($script:AnalysisResults.Count -eq 0) {
        Add-LogLine -TextBox $txtLog -Message "No results to export."
        return
    }

    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter = "HTML Files (*.html)|*.html"
    $sfd.FileName = "LogAnalysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    $sfd.InitialDirectory = Join-Path $PSScriptRoot "Reports"

    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Export-AnalysisHtml -Results $script:AnalysisResults -OutputPath $sfd.FileName
        Add-LogLine -TextBox $txtLog -Message "HTML report exported to $($sfd.FileName)"
    }
})

# Copy summary
$btnCopySummary.Add_Click({
    if ($script:AnalysisResults.Count -eq 0) {
        Add-LogLine -TextBox $txtLog -Message "No results to copy."
        return
    }

    $summary = New-AnalysisSummary -Results $script:AnalysisResults
    [System.Windows.Forms.Clipboard]::SetText($summary)
    Add-LogLine -TextBox $txtLog -Message "Summary copied to clipboard."
    $statusLabel.Text = "Summary copied to clipboard."
})

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------

Add-LogLine -TextBox $txtLog -Message "LogAnalyzerTool ready. Enter device hostname(s) and click Analyze."
[System.Windows.Forms.Application]::Run($form)
