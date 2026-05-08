# LATTriageVM.ps1
#
# Pure ViewModel builders for the Triage module. No WPF dependencies.
# Triage.ps1 calls these to translate an EvalResult into shapes the XAML
# bindings can consume directly, which keeps the UI glue thin and keeps
# this logic unit-testable without a WPF host.

Set-StrictMode -Version Latest

function New-LATEmptyVerdictCardVM {
    <#
    .SYNOPSIS
        Placeholder VM for the verdict card when no incident is loaded.
    #>
    return [pscustomobject]@{
        HasVerdict           = $false
        RuleId               = 'no-incident-loaded'
        Scope                = ''
        Headline             = 'No verdict yet. Drop a log bundle to analyze.'
        Confidence           = 0
        ConfidencePercent    = 0
        ConfidenceText       = '--'
        Fix                  = ''
        Evidence             = @()
        AlternateVerdicts    = @()
        ActionButtonsEnabled = $false
    }
}

function New-LATVerdictCardVM {
    <#
    .SYNOPSIS
        Translate an EvalResult into a verdict card ViewModel.
    .PARAMETER EvalResult
        Output of Invoke-RuleEvaluator.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $EvalResult
    )
    $verdicts = @()
    if ($EvalResult) { $verdicts = @(Get-LATArrayProperty $EvalResult 'Verdicts') }
    if ($verdicts.Count -eq 0) {
        $alt = @()
        $ev  = New-LATEmptyVerdictCardVM
        $ev.Headline   = 'No rule matched. Capture a new rule from this triage to start growing your KB.'
        $ev.RuleId     = '(no match)'
        $ev.ActionButtonsEnabled = $true
        return $ev
    }

    $top = $verdicts[0]
    $conf = [int](Get-LATProperty $top 'Confidence' 0)
    $confPct = [math]::Max(0, [math]::Min(100, $conf))

    $evidenceRaw = @(Get-LATArrayProperty $top 'EvidenceLines')
    $evidence = foreach ($e in $evidenceRaw) {
        [pscustomobject]@{
            Component = [string](Get-LATProperty $e 'Component' '')
            Message   = [string](Get-LATProperty $e 'Message' '')
        }
    }

    $alternates = @()
    if ($verdicts.Count -gt 1) {
        $alternates = for ($i = 1; $i -lt $verdicts.Count; $i++) {
            $v = $verdicts[$i]
            [pscustomobject]@{
                RuleId     = [string](Get-LATProperty $v 'RuleId' '')
                Verdict    = [string](Get-LATProperty $v 'Verdict' '')
                Confidence = "{0}%" -f ([int](Get-LATProperty $v 'Confidence' 0))
            }
        }
    }

    return [pscustomobject]@{
        HasVerdict           = $true
        RuleId               = [string](Get-LATProperty $top 'RuleId' '')
        Scope                = [string](Get-LATProperty $top 'Scope' '')
        Headline             = [string](Get-LATProperty $top 'Verdict' '')
        Confidence           = $conf
        ConfidencePercent    = $confPct
        ConfidenceText       = "{0}%" -f $confPct
        Fix                  = [string](Get-LATProperty $top 'Fix' '')
        Evidence             = @($evidence)
        AlternateVerdicts    = @($alternates)
        ActionButtonsEnabled = $true
    }
}

function New-LATParseResultFromLogFiles {
    <#
    .SYNOPSIS
        Adapter: run the existing LogAnalyzerCommon parse + signature
        detection pipeline across a set of log files and compose a
        ParseResult for the evaluator.
    .DESCRIPTION
        Requires LogAnalyzerCommon to be imported in the caller's scope
        (ConvertFrom-CMTraceLog, Invoke-SignatureDetection,
        Import-SignatureDatabase). This function stays free of WPF so it
        is callable from Pester + headless tooling.
    .PARAMETER Paths
        Array of log file paths.
    .PARAMETER SignatureDbPath
        Path to SignatureDB/log-signatures.json. Defaults to the repo's
        bundled one via $PSScriptRoot navigation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string[]]$Paths,
        [string]$SignatureDbPath = $null
    )
    if (-not $SignatureDbPath) {
        $SignatureDbPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'SignatureDB\log-signatures.json'
    }
    if (Test-Path $SignatureDbPath) {
        $null = Import-SignatureDatabase -Path $SignatureDbPath
    }
    $entries = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Paths) {
        if (-not (Test-Path $p)) { continue }
        $parsed = @(ConvertFrom-CMTraceLog -Path $p -ErrorAction SilentlyContinue)
        foreach ($e in $parsed) { $entries.Add($e) }
    }
    $withSigs = @(Invoke-SignatureDetection -Entries $entries.ToArray())
    return New-LATParseResult -Entries $withSigs
}
