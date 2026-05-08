# LATIncident.ps1
#
# Incident storage and history replay for LAT decision engine.
#
# After an analysis run the triage module calls New-LATIncident to snapshot
# the ParseResult + matches (+ optional source log files) into a compressed
# zip under %LOCALAPPDATA%\LogAnalyzer\incidents. The wizard's preview
# step (Session 8) replays draft rules against these stored incidents; the
# History module (Session 12) browses them directly.
#
# Bundle format (schemaVersion 1):
#   incident-<UTC-timestamp>-<shortguid>.zip
#     +-- manifest.json       # metadata (timestamp, counts, top verdict)
#     +-- parse-result.json   # ParseResult (entries serialized; datetime ISO)
#     +-- matches.json        # Verdicts + AllMatches + EvaluatedCount
#     +-- logs/*              # optional copies of source log files
#
# Retention: FIFO, default 50. Older incidents are deleted on every write.
# Incident root is overridable for tests via -IncidentRoot parameter.

Set-StrictMode -Version Latest

$script:LATIncident_SchemaVersion = 1
$script:LATIncident_DefaultRetention = 50

function Get-LATIncidentRoot {
    <#
    .SYNOPSIS
        Default incident storage path. Tests override via -IncidentRoot.
    #>
    param([string]$Override)
    if ($Override) { return $Override }
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = Join-Path $env:USERPROFILE 'AppData\Local' }
    return Join-Path $base 'LogAnalyzer\incidents'
}

function Get-LATProperty2 {
    # Duplicate of Get-LATProperty in Invoke-RuleEvaluator.ps1 so this file
    # dot-sources cleanly on its own. Renamed to avoid collision when both
    # are loaded together.
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    return $prop.Value
}

function ConvertTo-LATIncidentEntry {
    # Project a parsed log entry to the stable on-disk shape. DateTimes
    # written as ISO-8601 strings so PS 5.1 / PS 7 / C# port all round-trip.
    param($Entry)
    $dt = Get-LATProperty2 $Entry 'DateTime'
    $dtStr = if ($dt -is [datetime]) { $dt.ToString('o') } else { $null }
    [pscustomobject]@{
        DateTime    = $dtStr
        Component   = (Get-LATProperty2 $Entry 'Component' '')
        Message     = (Get-LATProperty2 $Entry 'Message' '')
        LogFile     = (Get-LATProperty2 $Entry 'LogFile' '')
        SignatureId = (Get-LATProperty2 $Entry 'SignatureId' $null)
        ErrorCode   = (Get-LATProperty2 $Entry 'ErrorCode' $null)
        Severity    = (Get-LATProperty2 $Entry 'Severity' $null)
    }
}

function ConvertFrom-LATIncidentEntry {
    param($Entry)
    $dt = $null
    $dtStr = Get-LATProperty2 $Entry 'DateTime'
    if ($dtStr) {
        try { $dt = [datetime]::Parse($dtStr, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) }
        catch { $dt = $null }
    }
    [pscustomobject]@{
        DateTime    = $dt
        Component   = (Get-LATProperty2 $Entry 'Component' '')
        Message     = (Get-LATProperty2 $Entry 'Message' '')
        LogFile     = (Get-LATProperty2 $Entry 'LogFile' '')
        SignatureId = (Get-LATProperty2 $Entry 'SignatureId' $null)
        ErrorCode   = (Get-LATProperty2 $Entry 'ErrorCode' $null)
        Severity    = (Get-LATProperty2 $Entry 'Severity' $null)
    }
}

function New-LATIncident {
    <#
    .SYNOPSIS
        Snapshot a triage session to disk as a compressed incident bundle.
    .PARAMETER ParseResult
        Output of New-LATParseResult (or the parse pipeline).
    .PARAMETER EvalResult
        Output of Invoke-RuleEvaluator.
    .PARAMETER Label
        Optional short label (e.g. device name or ticket id).
    .PARAMETER LogFiles
        Optional array of source .log paths to embed in the bundle.
    .PARAMETER Retention
        FIFO retention cap. Default 50.
    .PARAMETER IncidentRoot
        Override storage directory (tests).
    .OUTPUTS
        [string] path to the written .zip.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $ParseResult,
        [Parameter(Mandatory)] $EvalResult,
        [string]$Label = '',
        [string[]]$LogFiles = @(),
        [int]$Retention = $script:LATIncident_DefaultRetention,
        [string]$IncidentRoot
    )
    $root = Get-LATIncidentRoot -Override $IncidentRoot
    if (-not (Test-Path $root)) {
        $null = New-Item -ItemType Directory -Path $root -Force
    }

    $nowUtc = [datetime]::UtcNow
    $stamp  = $nowUtc.ToString('yyyyMMdd-HHmmss')
    $short  = [guid]::NewGuid().ToString().Substring(0, 8)
    $zipPath = Join-Path $root "incident-$stamp-$short.zip"

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-incident-" + $short)
    $null = New-Item -ItemType Directory -Path $tempRoot -Force
    try {
        $entriesProjected = @($ParseResult.Entries | ForEach-Object { ConvertTo-LATIncidentEntry -Entry $_ })
        $parseOnDisk = [pscustomobject]@{
            Entries           = $entriesProjected
            MatchedSignatures = @($ParseResult.MatchedSignatures)
            ErrorCodes        = @($ParseResult.ErrorCodes)
            Probes            = @($ParseResult.Probes)
            Clusters          = @($ParseResult.Clusters)
        }

        $top = $null
        $topArr = @($EvalResult.Verdicts)
        if ($topArr.Count -gt 0) { $top = $topArr[0].RuleId }

        $manifest = [pscustomobject]@{
            schemaVersion      = $script:LATIncident_SchemaVersion
            timestamp          = $nowUtc.ToString('o')
            label              = $Label
            topVerdictRuleId   = $top
            matchedRuleCount   = @($EvalResult.AllMatches).Count
            evaluatedRuleCount = $EvalResult.EvaluatedCount
            entryCount         = $entriesProjected.Count
            logFiles           = @(($LogFiles | ForEach-Object { Split-Path $_ -Leaf }))
        }

        $manifest    | ConvertTo-Json -Depth 6  | Set-Content -Path (Join-Path $tempRoot 'manifest.json')    -Encoding UTF8
        $parseOnDisk | ConvertTo-Json -Depth 12 | Set-Content -Path (Join-Path $tempRoot 'parse-result.json') -Encoding UTF8
        $EvalResult  | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $tempRoot 'matches.json')      -Encoding UTF8

        if ($LogFiles.Count -gt 0) {
            $logsDir = Join-Path $tempRoot 'logs'
            $null = New-Item -ItemType Directory -Path $logsDir -Force
            foreach ($lf in $LogFiles) {
                if (Test-Path $lf) {
                    Copy-Item -Path $lf -Destination $logsDir -Force
                }
            }
        }

        Compress-Archive -Path (Join-Path $tempRoot '*') -DestinationPath $zipPath -Force
    } finally {
        Remove-Item -Path $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    if ($Retention -gt 0) {
        $null = Trim-LATIncidents -Retention $Retention -IncidentRoot $root
    }

    return $zipPath
}

function Get-LATIncidentList {
    <#
    .SYNOPSIS
        List stored incidents, newest first.
    #>
    [CmdletBinding()]
    param(
        [int]$Top = 0,
        [string]$IncidentRoot
    )
    $root = Get-LATIncidentRoot -Override $IncidentRoot
    if (-not (Test-Path $root)) { return @() }
    $items = Get-ChildItem -Path $root -Filter 'incident-*.zip' -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTimeUtc -Descending
    if ($Top -gt 0) { $items = $items | Select-Object -First $Top }
    return @($items)
}

function Trim-LATIncidents {
    <#
    .SYNOPSIS
        Enforce FIFO retention. Deletes the oldest bundles when the count
        exceeds the retention cap. Safe to call repeatedly.
    #>
    [CmdletBinding()]
    param(
        [int]$Retention = $script:LATIncident_DefaultRetention,
        [string]$IncidentRoot
    )
    $all = @(Get-LATIncidentList -IncidentRoot $IncidentRoot)
    if ($all.Count -le $Retention) { return 0 }
    $doomed = $all | Select-Object -Skip $Retention
    $deleted = 0
    foreach ($d in $doomed) {
        Remove-Item -Path $d.FullName -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $d.FullName)) { $deleted++ }
    }
    return $deleted
}

function Import-LATIncident {
    <#
    .SYNOPSIS
        Rehydrate a stored incident bundle into ParseResult + EvalResult.
    .DESCRIPTION
        Expand the zip to a temp dir, parse manifest + parse-result +
        matches, reconstruct DateTime values on entries, and return a
        composite object. Rejects unknown schemaVersion.
    .OUTPUTS
        PSCustomObject @{ Manifest; ParseResult; EvalResult; LogDir }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path
    )
    if (-not (Test-Path $Path)) { throw "Incident bundle not found: $Path" }
    $short = [guid]::NewGuid().ToString().Substring(0, 8)
    $extractRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-incident-extract-" + $short)
    $null = New-Item -ItemType Directory -Path $extractRoot -Force
    Expand-Archive -Path $Path -DestinationPath $extractRoot -Force

    $manifestPath = Join-Path $extractRoot 'manifest.json'
    $parsePath    = Join-Path $extractRoot 'parse-result.json'
    $matchPath    = Join-Path $extractRoot 'matches.json'
    if (-not (Test-Path $manifestPath)) { throw "Bundle is missing manifest.json: $Path" }

    $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $sv = Get-LATProperty2 $manifest 'schemaVersion' 0
    if ($sv -ne $script:LATIncident_SchemaVersion) {
        throw "Bundle schemaVersion $sv is not supported by this build (expected $($script:LATIncident_SchemaVersion))."
    }

    $parseRaw = $null
    if (Test-Path $parsePath) {
        $parseRaw = Get-Content $parsePath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    $evalRaw = $null
    if (Test-Path $matchPath) {
        $evalRaw = Get-Content $matchPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    $entries = @()
    if ($parseRaw -and (Get-LATProperty2 $parseRaw 'Entries')) {
        $entries = @($parseRaw.Entries | ForEach-Object { ConvertFrom-LATIncidentEntry -Entry $_ })
    }

    $parseResult = [pscustomobject]@{
        Entries           = $entries
        MatchedSignatures = @(Get-LATProperty2 $parseRaw 'MatchedSignatures' @())
        ErrorCodes        = @(Get-LATProperty2 $parseRaw 'ErrorCodes' @())
        Probes            = @(Get-LATProperty2 $parseRaw 'Probes' @())
        Clusters          = @(Get-LATProperty2 $parseRaw 'Clusters' @())
    }

    $logDir = Join-Path $extractRoot 'logs'
    if (-not (Test-Path $logDir)) { $logDir = $null }

    return [pscustomobject]@{
        Manifest    = $manifest
        ParseResult = $parseResult
        EvalResult  = $evalRaw
        LogDir      = $logDir
        ExtractRoot = $extractRoot
    }
}

function Invoke-LATIncidentReplay {
    <#
    .SYNOPSIS
        Re-evaluate a stored incident against a (possibly updated) rulebase
        and compare to the originally stored verdicts.
    .PARAMETER Path
        Path to an incident .zip.
    .PARAMETER Rules
        Current rulebase (output of Get-LATRules).
    .OUTPUTS
        PSCustomObject @{ Original; Replay; Diff } where Diff.*
        summarizes changes: verdicts added, removed, score-shifted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] $Rules,
        [int]$TopN = 3
    )
    $bundle = Import-LATIncident -Path $Path
    $replay = Invoke-RuleEvaluator -ParseResult $bundle.ParseResult -Rules $Rules -TopN $TopN

    $origIds   = @()
    $origMatch = @(Get-LATProperty2 $bundle.EvalResult 'AllMatches' @())
    if ($origMatch.Count -gt 0) { $origIds = @($origMatch | ForEach-Object { $_.RuleId }) }
    $newIds  = @($replay.AllMatches | ForEach-Object { $_.RuleId })

    $added    = @($newIds  | Where-Object { $origIds -notcontains $_ })
    $removed  = @($origIds | Where-Object { $newIds -notcontains $_ })
    $retained = @($newIds  | Where-Object { $origIds -contains $_ })

    return [pscustomobject]@{
        Original = $bundle.EvalResult
        Replay   = $replay
        Diff     = [pscustomobject]@{
            AddedRuleIds    = $added
            RemovedRuleIds  = $removed
            RetainedRuleIds = $retained
        }
        Manifest = $bundle.Manifest
    }
}
