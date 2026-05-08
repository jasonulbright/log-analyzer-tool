# Session 10 shell smoke tests. Parse every XAML file in the project and
# verify the launcher can build the window in -TestMode on an STA thread.
# Runtime WPF construction requires STA; Pester hosts run MTA by default,
# so we invoke the launcher via a fresh powershell.exe -Sta child process
# and check exit status + stdout.

Describe 'WPF shell (Session 10)' {

    BeforeAll {
        $script:RepoRoot       = Resolve-Path (Join-Path $PSScriptRoot '..')
        $script:LauncherPs1    = Join-Path $script:RepoRoot 'start-loganalyzer-wpf.ps1'
        $script:MainWindowXaml = Join-Path $script:RepoRoot 'MainWindow.xaml'
        $script:ModuleRoot     = Join-Path $script:RepoRoot 'Modules'

        function Get-ModuleXamlFiles {
            Get-ChildItem -Path $script:ModuleRoot -Recurse -Filter '*.xaml' -ErrorAction SilentlyContinue
        }

        function Test-XamlFileParses {
            param([string]$Path)
            $raw = Get-Content -LiteralPath $Path -Raw
            # x:Class removal matches the launcher's runtime behavior.
            $raw = $raw -replace 'x:Class="[^"]+"', ''
            try {
                [void][xml]$raw
                return $true
            } catch {
                Write-Host "XML parse error in $Path`: $($_.Exception.Message)"
                return $false
            }
        }
    }

    Context 'Repository layout' {

        It 'vendors the three MahApps DLLs under Lib/' {
            $libDir = Join-Path $script:RepoRoot 'Lib'
            Test-Path (Join-Path $libDir 'MahApps.Metro.dll')            | Should -BeTrue
            Test-Path (Join-Path $libDir 'ControlzEx.dll')               | Should -BeTrue
            Test-Path (Join-Path $libDir 'Microsoft.Xaml.Behaviors.dll') | Should -BeTrue
        }

        It 'has MainWindow.xaml at repo root' {
            Test-Path $script:MainWindowXaml | Should -BeTrue
        }

        It 'has a launcher script at the repo root' {
            Test-Path $script:LauncherPs1 | Should -BeTrue
        }

        It 'has five module folders (Triage, History, KB, Wizard, Settings)' {
            foreach ($m in 'Triage','History','KB','Wizard','Settings') {
                Test-Path (Join-Path $script:ModuleRoot $m) | Should -BeTrue -Because "module folder $m"
            }
        }

        It 'every module folder ships a matching <Name>.xaml' {
            foreach ($m in 'Triage','History','KB','Wizard','Settings') {
                Test-Path (Join-Path $script:ModuleRoot "$m\$m.xaml") | Should -BeTrue -Because "$m.xaml"
            }
        }

        It 'every module folder ships module.json with EntryScript + InitFunction' {
            foreach ($m in 'Triage','History','KB','Wizard','Settings') {
                $manifestPath = Join-Path $script:ModuleRoot "$m\module.json"
                Test-Path $manifestPath | Should -BeTrue -Because "$m/module.json"
                $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
                $manifest.EntryScript  | Should -Not -BeNullOrEmpty -Because "$m EntryScript"
                $manifest.InitFunction | Should -Not -BeNullOrEmpty -Because "$m InitFunction"
                Test-Path (Join-Path $script:ModuleRoot "$m\$($manifest.EntryScript)") |
                    Should -BeTrue -Because "$m EntryScript present on disk"
            }
        }

        It 'every module entry script defines its advertised InitFunction' {
            foreach ($m in 'Triage','History','KB','Wizard','Settings') {
                $manifest = Get-Content (Join-Path $script:ModuleRoot "$m\module.json") -Raw -Encoding UTF8 | ConvertFrom-Json
                $entry = Join-Path $script:ModuleRoot "$m\$($manifest.EntryScript)"
                $raw   = Get-Content $entry -Raw -Encoding UTF8
                # Shallow match: file declares a `function <InitFunction>` somewhere. Fast and catches typos.
                $raw | Should -Match ("function\s+" + [regex]::Escape($manifest.InitFunction))
            }
        }
    }

    Context 'XAML syntactic validity' {

        It 'MainWindow.xaml parses as XML' {
            Test-XamlFileParses -Path $script:MainWindowXaml | Should -BeTrue
        }

        It 'every module XAML parses as XML' {
            $failures = New-Object System.Collections.Generic.List[string]
            foreach ($f in Get-ModuleXamlFiles) {
                if (-not (Test-XamlFileParses -Path $f.FullName)) {
                    $failures.Add($f.FullName)
                }
            }
            $failures.Count | Should -Be 0
        }
    }

    Context 'Launcher script' {

        It 'parses under the PowerShell parser (no syntax errors)' {
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($script:LauncherPs1, [ref]$null, [ref]$errors)
            if ($errors.Count -gt 0) {
                foreach ($e in $errors) {
                    Write-Host "  $($e.Message) at line $($e.Extent.StartLineNumber)"
                }
            }
            $errors.Count | Should -Be 0
        }

        It '-TestMode builds the window in an STA child process' {
            # Spin up a fresh STA powershell.exe so WPF types can initialize
            # without Pester's MTA host getting in the way. The launcher
            # echoes True/False to stdout in TestMode.
            $stdout = & powershell.exe -NoProfile -Sta -ExecutionPolicy Bypass -File $script:LauncherPs1 -TestMode 2>&1
            $stdout -join "`n" | Out-Null  # capture but don't emit for Pester output cleanliness
            $LASTEXITCODE | Should -Be 0 -Because "launcher in TestMode (STA) should exit 0; stdout: $($stdout -join ' | ')"
        }
    }

    Context 'Handler scope discipline (PS51-WPF-003 regression guard)' {
        # Script-scope LAT functions that, if called bare inside a
        # .GetNewClosure()'d event handler body, throw
        # CommandNotFoundException at click time because GetNewClosure
        # in flat .ps1 strips script-scope function lookup. Any such
        # call must go through a local scriptblock wrapper per
        # PS51-WPF-006 / Rule 8. This guard catches the bug class with
        # a cheap grep before a user ever clicks the handler.
        BeforeAll {
            $script:ScriptScopeFuncs = @(
                'Load-LATModule'
                'Set-LATTheme'
                'New-LATParseResultFromLogFiles'
                'Invoke-RuleEvaluator'
                'New-LATVerdictCardVM'
                'New-LATEmptyVerdictCardVM'
                'New-LATIncident'
                'New-LATRuleDraft'
                'Save-LATRuleDraft'
                'Get-LATRules'
                'Get-LATLoadedRules'
                'Get-LATModuleManifest'
                'Apply-LATVerdictCardVM'
                # Session 11c additions
                'Show-LATRuleWizardDialog'
                'Get-LATDraftPreview'
                'Format-LATDraftPreviewTable'
                'Export-LATRulePatch'
                # Session 12 additions
                'Get-LATIncidentList'
                'Get-LATIncidentRoot'
                'Get-LATLocalOverlayRoot'
                'Import-LATIncident'
                'Invoke-LATIncidentReplay'
                'Trim-LATIncidents'
                'New-LATKBRuleVM'
                'Format-LATKBRuleDetail'
                'New-LATHistoryRowVM'
                'Format-LATReplayDiff'
                'New-LATWizardIncidentRowVM'
            )
            $script:HandlerFiles = @(
                $script:LauncherPs1
                Join-Path $script:ModuleRoot 'Triage\Triage.ps1'
                Join-Path $script:ModuleRoot 'Wizard\WizardDialog.ps1'
                # Session 12 additions
                Join-Path $script:ModuleRoot 'KB\KB.ps1'
                Join-Path $script:ModuleRoot 'History\History.ps1'
                Join-Path $script:ModuleRoot 'Settings\Settings.ps1'
                Join-Path $script:ModuleRoot 'Wizard\Wizard.ps1'
            )
        }

        It 'no GetNewClosure''d body calls a script-scope LAT function bare' {
            # AST-based detection: find every `{...}.GetNewClosure()`
            # invocation and scan its scriptblock body for bare calls
            # to known script-scope LAT functions.  Using the AST
            # instead of a body regex because balanced-brace matching
            # with lazy regex spans wrapper/handler boundaries and
            # produces false positives (observed 2026-04-24).
            $violations = New-Object System.Collections.Generic.List[string]
            foreach ($file in $script:HandlerFiles) {
                if (-not (Test-Path -LiteralPath $file)) { continue }
                $tokens = $null; $errors = $null
                $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errors)
                $invocations = $fileAst.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and
                    $n.Member -and $n.Member.Value -eq 'GetNewClosure'
                }, $true)
                foreach ($inv in $invocations) {
                    $target = $inv.Expression
                    if ($target -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst]) { continue }
                    # Commands inside the closured scriptblock. Member
                    # accesses ($obj.Foo) are not CommandAst, so this
                    # naturally excludes them.
                    $commands = $target.ScriptBlock.FindAll({
                        param($n)
                        $n -is [System.Management.Automation.Language.CommandAst]
                    }, $true)
                    foreach ($cmd in $commands) {
                        $nameAst = $cmd.CommandElements[0]
                        if ($nameAst -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { continue }
                        $called = [string]$nameAst.Value
                        # Strip any `script:` qualifier so the scan
                        # still catches `script:Foo` as a violation.
                        if ($called.StartsWith('script:', [System.StringComparison]::OrdinalIgnoreCase)) {
                            $called = $called.Substring('script:'.Length)
                        }
                        if ($script:ScriptScopeFuncs -contains $called) {
                            $violations.Add(('{0}:{1}: bare call to {2} inside a GetNewClosure''d block' -f ([System.IO.Path]::GetFileName($file)), $cmd.Extent.StartLineNumber, $called))
                        }
                    }
                }
            }
            $violations.Count | Should -Be 0 -Because ("Script-scope function calls must go through local scriptblock wrappers per PS51-WPF-003 / PS51-WPF-006. Violations:`n  " + ($violations -join "`n  "))
        }

        It 'Triage.ps1 no longer defines a script-scope Apply-LATVerdictCardVM function' {
            # Session 11b replaced this with a local $applyVMSb scriptblock.
            # A regression that re-adds it would silently pass the static
            # guard above (since the guard scans handler bodies, not factory
            # bodies) while re-introducing the bug the moment a handler
            # calls into it.
            $triagePath = Join-Path $script:ModuleRoot 'Triage\Triage.ps1'
            $raw = Get-Content -LiteralPath $triagePath -Raw
            $raw | Should -Not -Match 'function\s+script:Apply-LATVerdictCardVM'
        }

        It 'launcher Get-LATLoadedRules passes both -BaselinePath AND -LocalPath to Get-LATRules' {
            # Regression guard: without -LocalPath, rules saved by the
            # wizard to %LOCALAPPDATA%\LogAnalyzer\rules are silently
            # ignored at evaluator time, and the user sees no change on
            # relaunch.  Observed during 11c interactive verification.
            $raw = Get-Content -LiteralPath $script:LauncherPs1 -Raw
            if ($raw -notmatch 'function\s+Get-LATLoadedRules\s*\{(?<body>[\s\S]*?)\n\}') {
                throw 'Could not locate Get-LATLoadedRules in the launcher.'
            }
            $body = $matches['body']
            $body | Should -Match 'Get-LATRules\b[\s\S]+-BaselinePath' -Because "Get-LATLoadedRules must pass the baseline"
            $body | Should -Match 'Get-LATRules\b[\s\S]+-LocalPath'    -Because "Get-LATLoadedRules must also pass the local overlay so saved rules load on relaunch"
        }

        It 'WizardDialog.ps1 dialog-internal handlers are NOT GetNewClosure''d (PS51-WPF-004)' {
            # Show-LATRuleWizardDialog blocks on ShowDialog() while its
            # button handlers fire, so lexical parent scope reaches every
            # local var AND script-scope function.  .GetNewClosure() on
            # those handlers would strip that reachability for a strict
            # net loss (per PS51-WPF-004).  A regression that adds
            # GetNewClosure to any Add_Click / Add_Toggled /
            # Add_ValueChanged in this file should fail the guard.
            $dlgPath = Join-Path $script:ModuleRoot 'Wizard\WizardDialog.ps1'
            $raw = Get-Content -LiteralPath $dlgPath -Raw
            $raw | Should -Not -Match '\.Add_\w+\(\{[\s\S]*?\}\.GetNewClosure\(\)\)'
        }
    }
}
