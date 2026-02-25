# Changelog

All notable changes to the Log Analyzer Tool (LAT) are documented in this file.

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
