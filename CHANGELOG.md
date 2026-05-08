# Changelog

All notable changes to Log Analyzer Tool are documented in this
file.

## [1.0.0] - 2026-05-02

Log Analyzer Tool (LAT) is a rule-driven triage shell for MECM client
logs, built for engineers and admins who know which log to pull. Drop
a log file, get a verdict + evidence + fix grounded in a rule the
engine fired. Capture a new triage as a reusable rule via the built-in
authoring wizard.

### Platform

- Windows 10 / 11 / Server with PowerShell 5.1
- WPF shell, MahApps.Metro themed (Dark.Steel / Light.Blue)
- Self-contained: no NuGet, no npm, no external runtime.  MahApps,
  ControlzEx, Xaml.Behaviors vendored in `Lib/`.

### Decision engine

- **Rule schema** defined in `Rules/Schema/rule.schema.json`.  Each
  rule carries id, scope, confidence, when.all/any/none conditions,
  causal order, verdict, fix, evidence, and references.
- **Condition types**: signature hit, error code hit (optionally
  component-scoped), probe result, cluster name, component regex,
  timeGap between two signatures.
- **Ranker**: score = confidence * specificity, tie-broken by
  specificity, confidence, then rule id ascending.
- **Baseline** of ~100 rules covers the common MECM failure modes
  across App deployment, Software Update, Client Install, and
  cross-scope failure families.
- **Local overlay** under `%LOCALAPPDATA%\LogAnalyzer\rules\`.
  USER rules override SYSTEM rules with the same id.

### Sidebar modules

- **Triage**: pick one or more log files, get a verdict card with
  the top rule, alternate verdicts, evidence lines, and fix text.
  Copy Fix puts the fix on the clipboard.  Every triage persists
  as an incident bundle under `%LOCALAPPDATA%\LogAnalyzer\incidents`
  for later replay.
- **History**: stored-incident browser.  Re-analyze a bundle
  against the current rulebase and see a diff of which rules
  added / removed / retained vs. the original triage.  FIFO
  retention, default cap 50.
- **Rules** (KB browser): read-only browser over the loaded
  rulebase.  Filter by scope, source (SYSTEM / USER), or free-text
  search over id + verdict.  Detail pane shows the full rule
  structure.
- **Wizard**: standalone wizard launcher.  Pick any stored
  incident from the dropdown and open the authoring dialog
  against it.  Refresh rescans the incident dir.
- **Settings**: rulebase paths, incident root, current counts split
  SYSTEM / USER, Reload (bust the cache and rescan overlay on
  disk), Trim (apply FIFO retention now), Open-folder buttons for
  each path.

### Authoring wizard

- Invoked from Triage's "Capture as Rule..." button on the verdict
  card, or from the Wizard sidebar module against any stored
  incident.
- Seeds a draft from the current ParseResult + EvalResult:
  conditions pre-filled from matched signatures + error codes +
  probes + clusters; evidence shortlist pre-filled from flagged
  log entries; scope inferred from the dominant signature family.
- Editable fields: rule id (readonly), scope combo, confidence
  slider, verdict multiline, fix multiline, evidence checkbox
  list.
- **Save** writes a schema-valid JSON to the local overlay.  Rule
  fires immediately on the next triage (or after Settings ->
  Reload).
- **Export patch** emits a git-applicable unified diff targeting
  `Rules/Baseline/<scope>/<id>.json` for upstream contribution.
  Patch body also copies to clipboard.
- **Preview** runs the draft against the current incident and
  stored history, reports which fire and which miss.
- Save and Export patch are both non-terminal -- the dialog stays
  open so the author can iterate on a draft without losing state.
  Close exits explicitly.

### Log parsing

- `ConvertFrom-CMTraceLog` parses both XML-style and legacy
  CMTrace formats.  Handles multi-line messages, rotated `.lo_`
  files, timezone normalization.
- `Read-LATLogFileShared` opens log files with
  `FileShare.ReadWrite` so LAT can read logs the SMS Agent Host
  is actively writing to.  Drop the file picker on
  `\\<hostname>\c$\Windows\CCM\Logs\` to triage a live client
  without copying logs locally.
- `Invoke-SignatureDetection` matches 20 known-bad patterns
  against message text, component-aware.
- `Compress-LogEntries` collapses duplicate rows.
- `Group-LogEvents` + `Merge-LogTimeline` support cross-file event
  clustering for multi-log triages.

### Stack

- PowerShell 5.1 + WPF + MahApps.Metro
- No external network calls.  No telemetry.
- Offline-capable: baseline ships with the build; overlay is local
  disk; incident bundles are local disk.

### Scope

LAT v1.0 is for engineers and admins with existing MECM log
knowledge.  A helpdesk-facing consumption tool (hostname +
symptom entry, automated SMB log retrieval, markdown-rendered fix
with inline images, one-click ticket output) is planned as a
separate web-stack product.  The rulebase in this repo is the
intended content source for both tools.
