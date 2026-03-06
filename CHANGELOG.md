# Changelog

All notable changes to the Log Analyzer Tool (LAT) are documented in this file.

## [1.6.0] - 2026-03-05

### Added

- **Multi-log timeline merge** (`Merge-LogTimeline`): When multiple analysis engines run (e.g., "All Logs"), entries from all engines are combined into a single chronological timeline and re-clustered across engine boundaries. This reveals causal relationships between log files -- e.g., a LocationServices DP failure at 14:10 and a ccmsetup abort at 14:13 are now grouped as a single "Content access failure" event instead of appearing as separate per-engine events.
  - Entries sorted chronologically across all log files
  - Cross-engine event clustering via `Group-LogEvents` re-run on merged data
  - Log console reports merge summary ("timeline merged: N entries, M events")
  - Per-engine summaries still logged before merge for individual engine visibility
  - LogFile provenance preserved on each entry for source identification
  - 12 Pester tests covering empty input, single-result pass-through, two-engine merge, three-engine merge, cross-engine clustering, signature-based naming, time-gap separation, re-clustering overwrite, custom GapSeconds, LogFile preservation, and large volume (300 entries from 3 engines)

### Changed

- Module version bumped to 1.5.0, manifest exports increased from 30 to 31 functions
- Grid population restructured: entries populated from merged timeline instead of per-engine results

---

## [1.5.0] - 2026-03-05

### Added

- **Event clustering** (`Group-LogEvents`): Groups related log entries into named event clusters by time proximity. Entries within 120 seconds of each other (configurable via `GapSeconds`) are grouped into a single event, named using signature-based event templates or the dominant component.
  - 10 event templates covering content access, app deployment, update scan, client install, WMI, certificate, DNS, access, reboot, and policy failures
  - Component-friendly fallback naming (e.g., "Update scan activity", "Content access activity") when no signatures match
  - Event outcome derived from worst severity in cluster (Error > Warning > Info)
  - Detail panel shows "Event Cluster" section with event name, ID, outcome, and entry count
  - Text filter searches event names (type "content" or "certificate" to find matching clusters)
  - Event definitions stored in extensible JSON database (`EventDB/event-definitions.json`)
  - 28 Pester tests covering pass-through, time-gap clustering, custom gap, sorting, naming (signature-based and component fallback), outcome determination, sequential IDs, entry counts, large volume (200 entries), and all 10 event template mappings

### Changed

- Module version bumped to 1.4.0, manifest exports increased from 28 to 30 functions

---

## [1.4.0] - 2026-03-05

### Added

- **Signature detection** (`Invoke-SignatureDetection`): Pattern-matches log entry message text against a knowledge base of 20 known-bad MECM log patterns. Identifies issues like DP unreachable, content download failures, WSUS scan failures, WMI corruption, certificate issues, pending reboots, and more -- without needing explicit error codes.
  - Distinct from error code translation: signatures read the message text itself, catching issues that don't produce numeric error codes
  - Component-aware filtering: signatures can target specific log components or match any component
  - Pre-compiled regexes for performance
  - Signature database (`SignatureDB/log-signatures.json`) with 20 patterns across 6 categories: Content (4), AppDeployment (3), SoftwareUpdates (3), ClientInstall (3), Infrastructure (7)
  - Each signature provides: issue name, explanation, suggested resolution, and related logs
  - Detail panel shows "Signature Match" section with issue name, ID, explanation, and suggested action
  - Signature resolutions feed into per-engine recommendation lists
  - Text filter searches signature names (type "WSUS" or "certificate" to find matching entries)
  - 21 Pester tests covering all 20 signatures, component filtering, pass-through, and multi-entry handling

### Changed

- Module version bumped to 1.3.0, manifest exports increased from 26 to 28 functions

---

## [1.3.0] - 2026-03-05

### Added

- **Duplicate collapse** (`Compress-LogEntries`): Consecutive log entries sharing the same normalized message template, component, and severity are collapsed into a single entry with repeat count and time span. Reduces grid noise by 80-95% in typical MECM logs.
  - Message normalization strips GUIDs, IP addresses, hex values, UNC paths, local paths, and standalone numbers so entries differing only in variable data collapse together
  - Grid message prefixed with `[Nx, HH:mm:ss - HH:mm:ss]` for collapsed entries
  - Detail panel shows "Repeated: N times (span)" when entry has repeats
  - Configurable `MinRepeatCount` threshold (default 2)
  - Integrated into all 3 analysis engines (App Deployment, Software Updates, Client Install)
  - 15 Pester tests covering pass-through, basic collapse, normalization (GUIDs, IPs, hex, UNC, local paths, numbers), interleaved sequences, threshold, and large volume (200 entries)

### Changed

- Module version bumped to 1.2.0, manifest exports increased from 25 to 26 functions

---

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
