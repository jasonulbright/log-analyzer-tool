# Changelog

All notable changes to the Log Analyzer Tool (LAT) are documented in this file.

## [1.2.2] - 2026-03-04

### Fixed
- Dark mode restart now captures script path at function scope (`$scriptFile = Join-Path $PSScriptRoot ...`) instead of using `$PSCommandPath` which resolves to empty inside event handler scriptblocks

---

## [1.2.1] - 2026-03-03

### Changed
- Replaced `lightmode.png` screenshot with `screenshot.png`

---

## [1.2.0] - 2026-02-27

### Added

- **Dual-transport log retrieval**: Configurable via File > Preferences
  - **ADMIN$ share** (default): existing behavior, works for most environments
  - **PowerShell Remoting**: retrieves log file bytes over WinRM sessions -- no C$/ADMIN$ share access needed. For environments where SentinelOne or similar EDR blocks administrative shares.
  - New module functions: `Test-PSRemoteAccess`, `Copy-RemoteLogFilesPSRemote`

- **Evidence saving**: When an evidence path is configured in Preferences, log files are copied to `\\share\hostname - YYMMDD - userid\` after retrieval and before analysis. Serves dual purpose: alternative retrieval fallback and timestamped documentation for support tickets.
  - New module function: `Save-EvidenceCopy`
  - Evidence save failure is non-blocking -- analysis continues with a warning

- **Preferences dialog**: Replaced placeholder "MECM Connection (coming soon)" section with two active groups:
  - Log Retrieval: radio buttons for ADMIN$ share vs PowerShell Remoting
  - Evidence Saving: path textbox with Browse button

### Changed

- Module version bumped to 1.1.0, manifest exports increased from 22 to 25 functions

## [1.1.0] - 2026-02-26

### Fixed

- **Dock Z-order**: Top panels (header, input, filter) now display in correct
  visual order via explicit `BringToFront()` sequencing
- **Fill control sizing**: `splitMain.BringToFront()` ensures the grid/detail
  area fills only the remaining space after all edge-docked panels
- **Entry Detail scrolling**: Switched from TextBox to RichTextBox for reliable
  vertical scrollbar behavior
- **Detail panel border**: Bottom border no longer clipped behind button panel

### Improved

- **Dark mode theming**
  - Custom `DarkToolStripRenderer` suppresses light borders/gradients on
    MenuStrip and StatusStrip
  - Themed input borders via wrapper panels (replaces system FixedSingle)
  - Flat-styled GroupBoxes with dim ForeColor for subtle borders
  - RadioButtons and CheckBox use muted ForeColor (170,170,170)
  - Grid selection highlight uses dark blue (38,79,120) instead of system bright
  - Column header borders use themed GridColor
  - Scrollbars hidden on Devices input and log console in dark mode
- **Log noise filtering**: All 14 log files across all 3 analysis engines now
  filtered to warnings and errors at parse time (`TypeFilter = @(2,3)`),
  eliminating Info-level chatter (BITS progress, file copies, download status)
- **Splitter persistence**: Grid/detail split position saved and restored in
  `LogAnalyzer.windowstate.json`
- **Button panel**: 1px separator line at top for visual definition; increased
  spacing between separator and export buttons

### Added

- `README.md` with feature overview, project structure, and quick start
- `CHANGELOG.md`
- `LICENSE` (GPL-3.0)
- `.gitignore` for runtime files (Logs/, Reports/, preferences, window state)

## [1.0.0] - 2026-02-25

### Added

- **GUI application** (`start-loganalyzer.ps1`) with WinForms interface
  - Header panel with title and subtitle
  - Device input (multi-line, comma-separated)
  - Analysis scope selector (All Logs, App Deployment, Software Updates, Client Install)
  - Time filter (last N hours)
  - Real-time text filter across message, error code, translation, and component
  - Info-level entry toggle
  - DataGridView with severity color coding and alternating row colors
  - Detail panel showing full entry context, translation, resolution, and recommended logs
  - Live log console with timestamped progress messages
  - Status bar with summary counts

- **Dark mode** with full theme support (13 color variables, light/dark)
  - Configurable via File > Preferences
  - Persisted in `LogAnalyzer.prefs.json`

- **Menu bar** with File (Preferences, Exit) and Help (About) menus

- **Window state persistence** across sessions (`LogAnalyzer.windowstate.json`)

- **Core module** (`LogAnalyzerCommon.psm1`) with 22 exported functions
  - CMTrace log parser supporting XML-style and legacy formats
  - Multi-line message handling and timezone normalization
  - Rotated log file support (`.lo_`)

- **3 analysis engines**
  - App Deployment: AppEnforce, AppDiscovery, CAS, ContentTransferManager, LocationServices
  - Software Updates: WUAHandler, UpdatesDeployment, UpdatesHandler, UpdatesStore
  - Client Install: ccmsetup, client.msi, MicrosoftPolicyPlatformSetup.msi

- **Error code translation** with 100+ codes across 6 JSON databases
  - MECM-specific codes (26 entries)
  - Windows HRESULT codes (30 entries)
  - Windows Update Agent codes (27 entries)
  - BITS transfer errors
  - CCMSetup errors
  - MSI installer errors
  - Each entry includes message, resolution, and recommended logs

- **Root cause detection**
  - Firewall/port block testing (ports 80, 443, 10123, 8530, 8531 via async TCP)
  - DNS resolution validation
  - Domain join verification via WMI
  - Microsoft Policy Platform corruption detection (MOF compile failures)

- **3010 reboot masking detection**
  - Extracts MSI exit code from client.msi.log
  - Compares exit timestamp to last reboot time (CIM with WMI fallback)
  - Reports reboot completed vs. still pending

- **Export and reporting**
  - CSV export with full column set
  - HTML export with styled report, color-coded severity, root cause alerts, and recommendations
  - Copy Summary to clipboard (plain-text format for email/tickets)

- **Remote log retrieval** via ADMIN$ share
  - Device list resolution (one per line or comma-separated)
  - Admin share access validation
  - Scoped log file discovery and copy

- **Logging** with timestamped session logs in `Logs/` folder
