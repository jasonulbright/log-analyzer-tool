<#
.SYNOPSIS
    Core module for LogAnalyzerTool (LAT).

.DESCRIPTION
    Import this module to get:
      - Structured logging (Initialize-Logging, Write-Log)
      - Device list resolution (Resolve-DeviceList)
      - ADMIN$ share log retrieval (Test-AdminShareAccess, Get-RemoteLogFiles, Copy-RemoteLogFiles)
      - CMTrace log parsing (ConvertFrom-CMTraceLog)
      - Error code translation (Import-ErrorCodeDatabase, Resolve-ErrorCode)
      - Analysis engines (Invoke-AppDeploymentAnalysis, Invoke-SoftwareUpdateAnalysis, Invoke-ClientInstallAnalysis)
      - 3010 exit code masking detection (Get-ClientMsiExitCode, Get-LastRebootTime, Test-3010RebootPending)
      - Root cause detection (Test-FirewallBlock, Test-DomainJoined, Test-DnsResolution, Test-MppCorruption)
      - Export (Export-AnalysisCsv, Export-AnalysisHtml, New-AnalysisSummary)

.EXAMPLE
    Import-Module "$PSScriptRoot\Module\LogAnalyzerCommon.psd1" -Force
    Initialize-Logging -LogPath "C:\temp\lat.log"

    $entries = ConvertFrom-CMTraceLog -Path "\\SERVER01\C$\Windows\CCM\Logs\AppEnforce.log"
    $entries | Where-Object { $_.Type -eq 3 } | Format-Table DateTime, Component, Message
#>

# ---------------------------------------------------------------------------
# Module-scoped state
# ---------------------------------------------------------------------------

$script:__LogAnalyzerLogPath = $null
$script:ErrorCodeDB          = @{}

# ---------------------------------------------------------------------------
# Known MECM log files and their categories
# ---------------------------------------------------------------------------

$script:KnownLogs = [ordered]@{
    # App Deployment (c:\windows\ccm\logs\)
    'AppEnforce'              = @{ Path = 'CCM\Logs'; Category = 'AppDeployment';    Description = 'Install/uninstall execution results' }
    'AppDiscovery'            = @{ Path = 'CCM\Logs'; Category = 'AppDeployment';    Description = 'Detection method evaluation' }
    'CAS'                     = @{ Path = 'CCM\Logs'; Category = 'AppDeployment';    Description = 'Content access and download' }
    'ContentTransferManager'  = @{ Path = 'CCM\Logs'; Category = 'AppDeployment';    Description = 'BITS/content transfer operations' }
    'LocationServices'        = @{ Path = 'CCM\Logs'; Category = 'AppDeployment';    Description = 'DP and boundary resolution' }

    # Software Updates (c:\windows\ccm\logs\)
    'WUAHandler'              = @{ Path = 'CCM\Logs'; Category = 'SoftwareUpdates';  Description = 'Update scan and compliance' }
    'UpdatesDeployment'       = @{ Path = 'CCM\Logs'; Category = 'SoftwareUpdates';  Description = 'Update enforcement and installation' }
    'UpdatesHandler'          = @{ Path = 'CCM\Logs'; Category = 'SoftwareUpdates';  Description = 'Update applicability evaluation' }
    'UpdatesStore'            = @{ Path = 'CCM\Logs'; Category = 'SoftwareUpdates';  Description = 'Update scan result caching' }

    # Client Infrastructure (c:\windows\ccm\logs\)
    'PolicyAgent'             = @{ Path = 'CCM\Logs'; Category = 'ClientInfra';      Description = 'Policy retrieval and evaluation' }
    'ClientLocation'          = @{ Path = 'CCM\Logs'; Category = 'ClientInfra';      Description = 'Site assignment and MP/DP resolution' }

    # CCM Client Installation (c:\windows\ccmsetup\logs\)
    'ccmsetup'                         = @{ Path = 'ccmsetup\Logs'; Category = 'ClientInstall'; Description = 'Client install/upgrade orchestration' }
    'client.msi'                       = @{ Path = 'ccmsetup\Logs'; Category = 'ClientInstall'; Description = 'MSI install result (source of truth for 3010)' }
    'MicrosoftPolicyPlatformSetup.msi' = @{ Path = 'ccmsetup\Logs'; Category = 'ClientInstall'; Description = 'MPP prerequisite install' }
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Initialize-Logging {
    param([string]$LogPath)

    $script:__LogAnalyzerLogPath = $LogPath

    if ($LogPath) {
        $parentDir = Split-Path -Path $LogPath -Parent
        if ($parentDir -and -not (Test-Path -LiteralPath $parentDir)) {
            New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
        }

        $header = "[{0}] [INFO ] === Log initialized ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        Set-Content -LiteralPath $LogPath -Value $header -Encoding UTF8
    }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped, severity-tagged log message.

    .DESCRIPTION
        INFO  -> Write-Host (stdout)
        WARN  -> Write-Host (stdout)
        ERROR -> Write-Host (stdout) + $host.UI.WriteErrorLine (stderr)

        -Quiet suppresses all console output but still writes to the log file.
    #>
    param(
        [AllowEmptyString()]
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO',

        [switch]$Quiet
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $formatted = "[{0}] [{1,-5}] {2}" -f $timestamp, $Level, $Message

    if (-not $Quiet) {
        Write-Host $formatted

        if ($Level -eq 'ERROR') {
            $host.UI.WriteErrorLine($formatted)
        }
    }

    if ($script:__LogAnalyzerLogPath) {
        Add-Content -LiteralPath $script:__LogAnalyzerLogPath -Value $formatted -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# Device Resolution
# ---------------------------------------------------------------------------

function Resolve-DeviceList {
    <#
    .SYNOPSIS
        Resolves input to a list of device hostnames.

    .DESCRIPTION
        Accepts a single hostname, comma-separated list, newline-separated list,
        or a ConfigMgr collection name (-IsCollection). Returns [string[]] of
        unique hostnames, sorted alphabetically.

        The -IsCollection switch is the ONLY code path that requires the
        ConfigurationManager PowerShell module.

    .EXAMPLE
        Resolve-DeviceList -InputText "SERVER01, SERVER02, SERVER03"
        Resolve-DeviceList -InputText "Workstations - Pilot" -IsCollection -SiteCode "MCM"
    #>
    param(
        [Parameter(Mandatory)]
        [string]$InputText,

        [string]$SiteCode,

        [switch]$IsCollection
    )

    if ($IsCollection) {
        Write-Log "Resolving collection members for: $InputText"

        if (-not $SiteCode) {
            throw "SiteCode is required when using -IsCollection."
        }

        try {
            if (-not (Get-Module ConfigurationManager -ErrorAction SilentlyContinue)) {
                $cmModule = Join-Path $env:SMS_ADMIN_UI_PATH '..\ConfigurationManager.psd1'
                if (Test-Path $cmModule) {
                    Import-Module $cmModule -ErrorAction Stop
                } else {
                    throw "ConfigurationManager module not found at expected path."
                }
            }

            $originalLocation = Get-Location
            Set-Location "${SiteCode}:" -ErrorAction Stop

            $members = Get-CMCollectionMember -CollectionName $InputText -ErrorAction Stop |
                Select-Object -ExpandProperty Name

            Set-Location $originalLocation

            if (-not $members -or $members.Count -eq 0) {
                Write-Log "No members found in collection: $InputText" -Level WARN
                return @()
            }

            $sorted = $members | Sort-Object -Unique
            Write-Log "Resolved $($sorted.Count) devices from collection: $InputText"
            return $sorted
        }
        catch {
            if ($originalLocation) {
                Set-Location $originalLocation -ErrorAction SilentlyContinue
            }
            throw "Failed to resolve collection '$InputText': $($_.Exception.Message)"
        }
    }

    # Split on comma, semicolon, or newline; trim whitespace; remove empty
    $devices = $InputText -split '[,;\r\n]+' |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' } |
        Sort-Object -Unique

    if ($devices.Count -eq 0) {
        Write-Log "No hostnames found in input text." -Level WARN
        return @()
    }

    Write-Log "Resolved $($devices.Count) device(s) from input text."
    return $devices
}

# ---------------------------------------------------------------------------
# Log Retrieval
# ---------------------------------------------------------------------------

function Test-AdminShareAccess {
    <#
    .SYNOPSIS
        Tests whether ADMIN$ share is accessible on a remote device.

    .OUTPUTS
        [pscustomobject] with Hostname, Accessible, ErrorMessage
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )

    $ccmPath   = "\\$Hostname\C`$\Windows\CCM\Logs"
    $setupPath = "\\$Hostname\C`$\Windows\ccmsetup\Logs"

    $result = [pscustomobject]@{
        Hostname     = $Hostname
        Accessible   = $false
        CcmLogs      = $false
        SetupLogs    = $false
        ErrorMessage = $null
    }

    try {
        $result.CcmLogs   = Test-Path -LiteralPath $ccmPath -ErrorAction Stop
        $result.SetupLogs = Test-Path -LiteralPath $setupPath -ErrorAction Stop
        $result.Accessible = $result.CcmLogs -or $result.SetupLogs

        if (-not $result.Accessible) {
            $result.ErrorMessage = "Neither CCM\Logs nor ccmsetup\Logs found on $Hostname"
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
    }

    return $result
}

function Get-RemoteLogFiles {
    <#
    .SYNOPSIS
        Enumerates available log files on a remote device via ADMIN$ share.

    .OUTPUTS
        [pscustomobject[]] with Name, UNCPath, SizeKB, LastModified, Category
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,

        [string[]]$LogNames,

        [string[]]$Categories
    )

    $results = @()
    $windowsRoot = "\\$Hostname\C`$\Windows"

    foreach ($logName in $script:KnownLogs.Keys) {
        $meta = $script:KnownLogs[$logName]

        # Filter by log names if specified
        if ($LogNames -and $logName -notin $LogNames) { continue }

        # Filter by category if specified
        if ($Categories -and $meta.Category -notin $Categories) { continue }

        $logDir  = Join-Path $windowsRoot $meta.Path
        $logFile = Join-Path $logDir "$logName.log"

        if (Test-Path -LiteralPath $logFile -ErrorAction SilentlyContinue) {
            $fi = Get-Item -LiteralPath $logFile -ErrorAction SilentlyContinue
            if ($fi) {
                $results += [pscustomobject]@{
                    Name         = $logName
                    FileName     = "$logName.log"
                    UNCPath      = $logFile
                    SizeKB       = [math]::Round($fi.Length / 1KB, 1)
                    LastModified = $fi.LastWriteTime
                    Category     = $meta.Category
                    Description  = $meta.Description
                }
            }
        }
    }

    return $results
}

function Copy-RemoteLogFiles {
    <#
    .SYNOPSIS
        Copies log files from remote device to local staging directory.

    .DESCRIPTION
        Creates a per-device subfolder under LocalStagingRoot and copies
        matching log files from the ADMIN$ share.

    .OUTPUTS
        [pscustomobject[]] with LogName, LocalPath, SourceUNC, CopySuccess, Error
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Hostname,

        [Parameter(Mandatory)]
        [string]$LocalStagingRoot,

        [string[]]$LogNames,

        [string[]]$Categories,

        [switch]$IncludeRotated
    )

    $deviceFolder = Join-Path $LocalStagingRoot $Hostname
    if (-not (Test-Path -LiteralPath $deviceFolder)) {
        New-Item -ItemType Directory -Path $deviceFolder -Force | Out-Null
    }

    $remoteLogs = Get-RemoteLogFiles -Hostname $Hostname -LogNames $LogNames -Categories $Categories
    $results = @()

    foreach ($log in $remoteLogs) {
        $destPath = Join-Path $deviceFolder $log.FileName
        $entry = [pscustomobject]@{
            LogName     = $log.Name
            LocalPath   = $destPath
            SourceUNC   = $log.UNCPath
            CopySuccess = $false
            Error       = $null
            Category    = $log.Category
        }

        try {
            Copy-Item -LiteralPath $log.UNCPath -Destination $destPath -Force -ErrorAction Stop
            $entry.CopySuccess = $true

            # Copy rotated logs (.lo_) if requested
            if ($IncludeRotated) {
                $rotatedPattern = Join-Path (Split-Path $log.UNCPath -Parent) "$($log.Name).lo_"
                if (Test-Path -LiteralPath $rotatedPattern -ErrorAction SilentlyContinue) {
                    $rotatedDest = Join-Path $deviceFolder "$($log.Name).lo_"
                    Copy-Item -LiteralPath $rotatedPattern -Destination $rotatedDest -Force -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            $entry.Error = $_.Exception.Message
        }

        $results += $entry
    }

    return $results
}

# ---------------------------------------------------------------------------
# CMTrace Log Parsing
# ---------------------------------------------------------------------------

function ConvertFrom-CMTraceLog {
    <#
    .SYNOPSIS
        Parses a CMTrace-format log file into structured objects.

    .DESCRIPTION
        Reads a log file and returns an array of structured log entry objects.
        Supports both XML-style CMTrace format and legacy CMTrace format.
        Handles multi-line messages (continuation lines without LOG markers).

        Uses [System.IO.File]::ReadAllText() + [regex]::Matches() for
        performance on large log files (AppEnforce.log can be 1MB+).

    .EXAMPLE
        $entries = ConvertFrom-CMTraceLog -Path "C:\temp\AppEnforce.log"
        $entries | Where-Object { $_.Type -eq 3 } | Format-Table DateTime, Component, Message

    .EXAMPLE
        $entries = ConvertFrom-CMTraceLog -Path $path -After (Get-Date).AddHours(-24) -TypeFilter 2,3
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [datetime]$After,

        [datetime]$Before,

        [int[]]$TypeFilter,

        [string]$MessageFilter
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "Log file not found: $Path" -Level WARN
        return @()
    }

    $logFileName = Split-Path $Path -Leaf

    try {
        $rawContent = [System.IO.File]::ReadAllText($Path)
    }
    catch {
        Write-Log "Failed to read log file $Path - $($_.Exception.Message)" -Level ERROR
        return @()
    }

    if ([string]::IsNullOrWhiteSpace($rawContent)) {
        Write-Log "Log file is empty: $Path" -Level WARN
        return @()
    }

    # CMTrace XML-style pattern
    $cmtracePattern = '<!\[LOG\[(?<Message>.*?)\]LOG\]!>' +
        '<time="(?<Time>[^"]+)"\s+' +
        'date="(?<Date>[^"]+)"\s+' +
        'component="(?<Component>[^"]*?)"\s+' +
        'context="(?<Context>[^"]*?)"\s+' +
        'type="(?<Type>\d)"\s+' +
        'thread="(?<Thread>[^"]*?)"\s+' +
        'file="(?<File>[^"]*?)">'

    # Legacy pattern: message $$<component><date time+/-tz><thread=tid>
    $legacyPattern = '(?<Message>.+?)\s+\$\$<(?<Component>[^>]+)>' +
        '<(?<Date>\d{1,2}-\d{1,2}-\d{4})\s+(?<Time>\d{1,2}:\d{2}:\d{2}\.\d+)' +
        '(?<TZSign>[+-])(?<TZOffset>\d+)>' +
        '<thread=(?<Thread>\d+)(?:\s+\([^)]*\))?>'

    $severityMap = @{ 1 = 'Info'; 2 = 'Warning'; 3 = 'Error' }
    $results = [System.Collections.ArrayList]::new()

    # Try CMTrace pattern first
    $matches = [regex]::Matches($rawContent, $cmtracePattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)

    if ($matches.Count -gt 0) {
        $lineNumber = 0
        foreach ($m in $matches) {
            $lineNumber++

            $msg       = $m.Groups['Message'].Value
            $timeStr   = $m.Groups['Time'].Value
            $dateStr   = $m.Groups['Date'].Value
            $component = $m.Groups['Component'].Value
            $context   = $m.Groups['Context'].Value
            $typeInt   = [int]$m.Groups['Type'].Value
            $thread    = $m.Groups['Thread'].Value
            $file      = $m.Groups['File'].Value

            # Parse datetime - time format is "HH:mm:ss.ffffff+/-TZOffset"
            $cleanTime = $timeStr -replace '[+-]\d+$', ''
            $dtString  = "$dateStr $cleanTime"

            $parsedDT = $null
            $formats  = @('M-d-yyyy HH:mm:ss.ffffff', 'M-d-yyyy HH:mm:ss.fff', 'M-d-yyyy HH:mm:ss')
            foreach ($fmt in $formats) {
                $tempDT = [datetime]::MinValue
                if ([datetime]::TryParseExact($dtString, $fmt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$tempDT)) {
                    $parsedDT = $tempDT
                    break
                }
            }

            if ($null -eq $parsedDT) {
                # Last resort - try generic parse
                try { $parsedDT = [datetime]::Parse("$dateStr $cleanTime") }
                catch { $parsedDT = [datetime]::MinValue }
            }

            # Apply filters
            if ($After -and $parsedDT -lt $After) { continue }
            if ($Before -and $parsedDT -gt $Before) { continue }
            if ($TypeFilter -and $typeInt -notin $TypeFilter) { continue }
            if ($MessageFilter -and $msg -notmatch $MessageFilter) { continue }

            $severity = if ($severityMap.ContainsKey($typeInt)) { $severityMap[$typeInt] } else { 'Unknown' }

            [void]$results.Add([pscustomobject]@{
                Message    = $msg
                DateTime   = $parsedDT
                Component  = $component
                Context    = $context
                Type       = $typeInt
                Severity   = $severity
                Thread     = $thread
                File       = $file
                LineNumber = $lineNumber
                LogFile    = $logFileName
            })
        }
    }
    else {
        # Try legacy pattern
        $legacyMatches = [regex]::Matches($rawContent, $legacyPattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)

        if ($legacyMatches.Count -gt 0) {
            $lineNumber = 0
            foreach ($m in $legacyMatches) {
                $lineNumber++

                $msg       = $m.Groups['Message'].Value.Trim()
                $dateStr   = $m.Groups['Date'].Value
                $timeStr   = $m.Groups['Time'].Value
                $component = $m.Groups['Component'].Value
                $thread    = $m.Groups['Thread'].Value

                $cleanTime = $timeStr -replace '\.\d+$', ''
                $parsedDT  = $null
                try { $parsedDT = [datetime]::Parse("$dateStr $cleanTime") }
                catch { $parsedDT = [datetime]::MinValue }

                # Legacy format has no explicit type - infer from message content
                $typeInt = 1
                if ($msg -match '(?i)(error|fail|exception|0x8)') { $typeInt = 3 }
                elseif ($msg -match '(?i)(warn|caution)') { $typeInt = 2 }

                if ($After -and $parsedDT -lt $After) { continue }
                if ($Before -and $parsedDT -gt $Before) { continue }
                if ($TypeFilter -and $typeInt -notin $TypeFilter) { continue }
                if ($MessageFilter -and $msg -notmatch $MessageFilter) { continue }

                $severity = if ($severityMap.ContainsKey($typeInt)) { $severityMap[$typeInt] } else { 'Unknown' }

                [void]$results.Add([pscustomobject]@{
                    Message    = $msg
                    DateTime   = $parsedDT
                    Component  = $component
                    Context    = ''
                    Type       = $typeInt
                    Severity   = $severity
                    Thread     = $thread
                    File       = ''
                    LineNumber = $lineNumber
                    LogFile    = $logFileName
                })
            }
        }
        else {
            Write-Log "No CMTrace or legacy entries matched in: $logFileName" -Level WARN
        }
    }

    Write-Log "Parsed $($results.Count) entries from $logFileName"
    return $results.ToArray()
}

# ---------------------------------------------------------------------------
# Error Code Translation
# ---------------------------------------------------------------------------

function Import-ErrorCodeDatabase {
    <#
    .SYNOPSIS
        Loads all error code JSON files into a unified lookup hashtable.

    .DESCRIPTION
        Reads all JSON files from the ErrorCodes folder and merges into
        $script:ErrorCodeDB keyed by both hex and decimal representations.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ErrorCodesRoot
    )

    $script:ErrorCodeDB = @{}

    if (-not (Test-Path -LiteralPath $ErrorCodesRoot)) {
        Write-Log "ErrorCodes folder not found: $ErrorCodesRoot" -Level WARN
        return
    }

    $jsonFiles = Get-ChildItem -Path $ErrorCodesRoot -Filter '*.json' -ErrorAction SilentlyContinue
    $totalCodes = 0

    foreach ($jsonFile in $jsonFiles) {
        try {
            $entries = Get-Content -LiteralPath $jsonFile.FullName -Raw -ErrorAction Stop |
                ConvertFrom-Json -ErrorAction Stop

            foreach ($entry in $entries) {
                $obj = [pscustomobject]@{
                    Code       = $entry.Code
                    Decimal    = $entry.Decimal
                    Source     = $entry.Source
                    Message    = $entry.Message
                    Resolution = $entry.Resolution
                    LogsToCheck = $entry.LogsToCheck
                }

                # Index by hex code
                if ($entry.Code) {
                    $script:ErrorCodeDB[$entry.Code.ToUpper()] = $obj
                }

                # Index by decimal
                if ($entry.Decimal) {
                    $script:ErrorCodeDB[$entry.Decimal] = $obj
                }

                $totalCodes++
            }
        }
        catch {
            Write-Log "Failed to load error codes from $($jsonFile.Name): $($_.Exception.Message)" -Level WARN
        }
    }

    Write-Log "Loaded $totalCodes error codes from $($jsonFiles.Count) file(s)."
}

function Resolve-ErrorCode {
    <#
    .SYNOPSIS
        Translates an error code to a human-readable description.

    .DESCRIPTION
        Accepts decimal, hex (0x...), or negative-decimal MECM codes.
        Normalizes to all known representations and looks up in database.
        Falls back to Win32 error code lookup via [System.ComponentModel.Win32Exception].

    .OUTPUTS
        [pscustomobject] with Code, HexCode, Source, Message, Resolution, LogsToCheck, Found
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ErrorCode
    )

    $code = $ErrorCode.Trim()
    $hexCode    = $null
    $decCode    = $null

    # Normalize representations
    if ($code -match '^0x[0-9A-Fa-f]+$') {
        $hexCode = $code.ToUpper()
        try {
            $decCode = [string][int64]("$code")
        } catch {}
    }
    elseif ($code -match '^-?\d+$') {
        $decCode = $code
        try {
            if ([long]$code -lt 0) {
                $hexCode = '0x' + ([uint32]([int]$code)).ToString('X8')
            } else {
                $hexCode = '0x' + ([int64]$code).ToString('X')
            }
        } catch {}
    }

    # Look up in database
    $found = $null
    if ($hexCode -and $script:ErrorCodeDB.ContainsKey($hexCode)) {
        $found = $script:ErrorCodeDB[$hexCode]
    }
    elseif ($decCode -and $script:ErrorCodeDB.ContainsKey($decCode)) {
        $found = $script:ErrorCodeDB[$decCode]
    }

    if ($found) {
        return [pscustomobject]@{
            Code        = $code
            HexCode     = if ($hexCode) { $hexCode } else { $found.Code }
            Source      = $found.Source
            Message     = $found.Message
            Resolution  = $found.Resolution
            LogsToCheck = $found.LogsToCheck
            Found       = $true
        }
    }

    # Fallback: Win32 exception
    $win32Msg = $null
    try {
        $intCode = [int]$code
        $win32Msg = ([System.ComponentModel.Win32Exception]::new($intCode)).Message
    } catch {}

    return [pscustomobject]@{
        Code        = $code
        HexCode     = $hexCode
        Source      = if ($win32Msg) { 'Win32' } else { 'Unknown' }
        Message     = if ($win32Msg) { $win32Msg } else { "Unknown error code: $code" }
        Resolution  = $null
        LogsToCheck = $null
        Found       = [bool]$win32Msg
    }
}

function Find-LogErrors {
    <#
    .SYNOPSIS
        Scans parsed log entries for errors, warnings, and known error code patterns.

    .DESCRIPTION
        Takes an array of parsed log entries (from ConvertFrom-CMTraceLog) and:
        1. Filters to Type 2 (Warning) and Type 3 (Error)
        2. Extracts error codes from message text via regex
        3. Resolves each error code via Resolve-ErrorCode
        4. Returns enriched error objects with translations

    .OUTPUTS
        [pscustomobject[]] with original log entry properties PLUS ErrorCode, ErrorTranslation
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject[]]$LogEntries,

        [switch]$ErrorsOnly,

        [switch]$IncludeInfo
    )

    # Error code extraction patterns
    $hexPattern    = '(0x[0-9A-Fa-f]{4,8})'
    $decPattern    = '(?:error\s*(?:code)?|exit\s*code|return\s*(?:value|code))\s*[=:]\s*(-?\d{2,10})'
    $msiPattern    = 'return value\s+(\d+)'

    $results = [System.Collections.ArrayList]::new()

    foreach ($entry in $LogEntries) {
        # Filter by severity
        if ($ErrorsOnly -and $entry.Type -ne 3) { continue }
        if (-not $IncludeInfo -and $entry.Type -eq 1) {
            # For Info entries, only include if they contain an error code
            $hasCode = $entry.Message -match $hexPattern -or
                       $entry.Message -match $decPattern -or
                       $entry.Message -match $msiPattern
            if (-not $hasCode) { continue }
        }

        # Extract error codes from message
        $errorCodes = @()

        $hexMatches = [regex]::Matches($entry.Message, $hexPattern)
        foreach ($hm in $hexMatches) {
            $errorCodes += $hm.Groups[1].Value
        }

        $decMatches = [regex]::Matches($entry.Message, $decPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($dm in $decMatches) {
            $errorCodes += $dm.Groups[1].Value
        }

        $msiMatches = [regex]::Matches($entry.Message, $msiPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($mm in $msiMatches) {
            $val = $mm.Groups[1].Value
            # Only include non-zero MSI return values as "errors"
            if ($val -ne '0') {
                $errorCodes += $val
            }
        }

        $errorCodes = $errorCodes | Select-Object -Unique

        # Resolve each error code
        $translations = @()
        foreach ($ec in $errorCodes) {
            $translations += Resolve-ErrorCode -ErrorCode $ec
        }

        $primaryCode = if ($errorCodes.Count -gt 0) { $errorCodes[0] } else { $null }
        $primaryTranslation = if ($translations.Count -gt 0) { $translations[0] } else { $null }

        [void]$results.Add([pscustomobject]@{
            Message          = $entry.Message
            DateTime         = $entry.DateTime
            Component        = $entry.Component
            Context          = $entry.Context
            Type             = $entry.Type
            Severity         = $entry.Severity
            Thread           = $entry.Thread
            LogFile          = $entry.LogFile
            LineNumber       = $entry.LineNumber
            ErrorCode        = $primaryCode
            ErrorTranslation = $primaryTranslation
            AllErrorCodes    = $errorCodes
            AllTranslations  = $translations
        })
    }

    return $results.ToArray()
}

# ---------------------------------------------------------------------------
# 3010 Exit Code Masking Detection
# ---------------------------------------------------------------------------

function Get-ClientMsiExitCode {
    <#
    .SYNOPSIS
        Extracts the real MSI exit code from client.msi.log.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ClientMsiLogPath
    )

    if (-not (Test-Path -LiteralPath $ClientMsiLogPath)) {
        return [pscustomobject]@{ ExitCode = $null; Timestamp = $null; Found = $false }
    }

    try {
        $content = [System.IO.File]::ReadAllText($ClientMsiLogPath)
    }
    catch {
        return [pscustomobject]@{ ExitCode = $null; Timestamp = $null; Found = $false }
    }

    # Look for the final return value line (MSI logs end with this)
    # Pattern: "MainEngineThread is returning X" or "return value X"
    $returnPattern = '(?:MainEngineThread is returning|return value)\s+(\d+)'
    $allMatches = [regex]::Matches($content, $returnPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    if ($allMatches.Count -gt 0) {
        # Use the LAST match (final exit code)
        $lastMatch = $allMatches[$allMatches.Count - 1]
        $exitCode  = [int]$lastMatch.Groups[1].Value

        # Try to extract timestamp from nearby CMTrace-format wrapper
        $tsPattern = 'date="(?<Date>[^"]+)"\s+.*?time="(?<Time>[^"]+)"'
        $startPos  = [math]::Max(0, $lastMatch.Index - 500)
        $segment   = $content.Substring($startPos, [math]::Min(600, $content.Length - $startPos))
        $tsMatch   = [regex]::Match($segment, $tsPattern)

        $timestamp = $null
        if ($tsMatch.Success) {
            try {
                $dateStr  = $tsMatch.Groups['Date'].Value
                $timeStr  = ($tsMatch.Groups['Time'].Value) -replace '[+-]\d+$', ''
                $timestamp = [datetime]::Parse("$dateStr $timeStr")
            } catch {}
        }

        # If no CMTrace timestamp, use file last write time
        if ($null -eq $timestamp) {
            $timestamp = (Get-Item -LiteralPath $ClientMsiLogPath).LastWriteTime
        }

        return [pscustomobject]@{
            ExitCode  = $exitCode
            Timestamp = $timestamp
            Found     = $true
        }
    }

    return [pscustomobject]@{ ExitCode = $null; Timestamp = $null; Found = $false }
}

function Get-LastRebootTime {
    <#
    .SYNOPSIS
        Gets the last reboot time for a remote device.
        Primary: WMI. Fallback: MECM data.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )

    # Try WMI first
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Hostname -ErrorAction Stop
        if ($os.LastBootUpTime) {
            return [pscustomobject]@{
                LastRebootTime = $os.LastBootUpTime
                Source         = 'WMI'
                Success        = $true
            }
        }
    }
    catch {
        Write-Log "WMI reboot query failed for $Hostname - $($_.Exception.Message)" -Level WARN
    }

    # Fallback: try legacy WMI
    try {
        $wmi = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Hostname -ErrorAction Stop
        if ($wmi.LastBootUpTime) {
            $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($wmi.LastBootUpTime)
            return [pscustomobject]@{
                LastRebootTime = $bootTime
                Source         = 'WMI-Legacy'
                Success        = $true
            }
        }
    }
    catch {
        Write-Log "Legacy WMI reboot query also failed for $Hostname" -Level WARN
    }

    return [pscustomobject]@{
        LastRebootTime = $null
        Source         = 'None'
        Success        = $false
    }
}

function Test-3010RebootPending {
    <#
    .SYNOPSIS
        Determines if a 3010 from client.msi.log is still pending reboot.

    .DESCRIPTION
        1. Gets real MSI exit code from client.msi.log
        2. If not 3010, returns not-pending
        3. Gets last reboot time for the device
        4. Compares 3010 timestamp against last reboot
        5. If rebooted AFTER 3010 -> not pending
        6. If NOT rebooted after 3010 -> pending reboot
    #>
    param(
        [Parameter(Mandatory)]
        [string]$ClientMsiLogPath,

        [Parameter(Mandatory)]
        [string]$Hostname
    )

    $msiResult = Get-ClientMsiExitCode -ClientMsiLogPath $ClientMsiLogPath

    if (-not $msiResult.Found) {
        return [pscustomobject]@{
            MsiExitCode   = $null
            MsiTimestamp  = $null
            LastReboot    = $null
            RebootPending = $false
            Explanation   = 'Could not determine MSI exit code from client.msi.log'
        }
    }

    if ($msiResult.ExitCode -ne 3010) {
        return [pscustomobject]@{
            MsiExitCode   = $msiResult.ExitCode
            MsiTimestamp  = $msiResult.Timestamp
            LastReboot    = $null
            RebootPending = $false
            Explanation   = "MSI exit code is $($msiResult.ExitCode), not 3010 - no reboot required."
        }
    }

    # Exit code IS 3010 - check if server has rebooted since
    $rebootResult = Get-LastRebootTime -Hostname $Hostname

    if (-not $rebootResult.Success) {
        return [pscustomobject]@{
            MsiExitCode   = 3010
            MsiTimestamp  = $msiResult.Timestamp
            LastReboot    = $null
            RebootPending = $true
            Explanation   = "MSI returned 3010 at $($msiResult.Timestamp) but could not determine last reboot time. Assume reboot pending."
        }
    }

    $rebooted = $rebootResult.LastRebootTime -gt $msiResult.Timestamp

    if ($rebooted) {
        return [pscustomobject]@{
            MsiExitCode   = 3010
            MsiTimestamp  = $msiResult.Timestamp
            LastReboot    = $rebootResult.LastRebootTime
            RebootPending = $false
            Explanation   = "MSI returned 3010 at $($msiResult.Timestamp) but server rebooted at $($rebootResult.LastRebootTime). Reboot completed."
        }
    }

    return [pscustomobject]@{
        MsiExitCode   = 3010
        MsiTimestamp  = $msiResult.Timestamp
        LastReboot    = $rebootResult.LastRebootTime
        RebootPending = $true
        Explanation   = "MSI returned 3010 at $($msiResult.Timestamp). Server last rebooted at $($rebootResult.LastRebootTime) which is BEFORE the 3010. Reboot is still pending."
    }
}

# ---------------------------------------------------------------------------
# Root Cause Detection
# ---------------------------------------------------------------------------

function Test-FirewallBlock {
    <#
    .SYNOPSIS
        Checks log entries and connectivity for firewall/port issues.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject[]]$LogEntries,

        [string]$Hostname
    )

    $evidence = @()

    # Check log patterns
    $firewallPatterns = @(
        'Failed to send'
        'connection timed out'
        '0x800706BA'
        'RPC server is unavailable'
        'BITS.*error.*connection'
        'Failed to connect to'
        'No reply from'
        'The network path was not found'
        '0x80070035'
    )

    foreach ($entry in $LogEntries) {
        foreach ($pattern in $firewallPatterns) {
            if ($entry.Message -match $pattern) {
                $evidence += "[$($entry.LogFile)] $($entry.DateTime): $($entry.Message.Substring(0, [math]::Min(200, $entry.Message.Length)))"
                break
            }
        }
    }

    # Test common MECM ports if hostname provided
    $blockedPorts = @()
    if ($Hostname) {
        $ports = @(80, 443, 10123, 8530, 8531)
        foreach ($port in $ports) {
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $connect = $tcp.BeginConnect($Hostname, $port, $null, $null)
                $wait = $connect.AsyncWaitHandle.WaitOne(2000, $false)
                if (-not $wait -or -not $tcp.Connected) {
                    $blockedPorts += $port
                }
                $tcp.Close()
            }
            catch {
                $blockedPorts += $port
            }
        }
    }

    return [pscustomobject]@{
        Detected     = ($evidence.Count -gt 0) -or ($blockedPorts.Count -gt 0)
        Evidence     = $evidence
        BlockedPorts = $blockedPorts
    }
}

function Test-DomainJoined {
    <#
    .SYNOPSIS
        Checks if a device is domain-joined via WMI.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )

    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $Hostname -ErrorAction Stop
        return [pscustomobject]@{
            DomainJoined = $cs.PartOfDomain
            Domain       = $cs.Domain
            Source       = 'WMI'
        }
    }
    catch {
        return [pscustomobject]@{
            DomainJoined = $null
            Domain       = $null
            Source       = "WMI query failed: $($_.Exception.Message)"
        }
    }
}

function Test-DnsResolution {
    <#
    .SYNOPSIS
        Tests whether the device can be resolved in DNS.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )

    try {
        $dns = Resolve-DnsName -Name $Hostname -ErrorAction Stop
        $ip  = ($dns | Where-Object { $_.QueryType -eq 'A' -or $_.QueryType -eq 'AAAA' } | Select-Object -First 1).IPAddress

        return [pscustomobject]@{
            Resolvable = $true
            IPAddress  = $ip
            Error      = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Resolvable = $false
            IPAddress  = $null
            Error      = $_.Exception.Message
        }
    }
}

function Test-MppCorruption {
    <#
    .SYNOPSIS
        Checks MPP MSI log for MOF compile failures.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$MppLogPath
    )

    if (-not (Test-Path -LiteralPath $MppLogPath)) {
        return [pscustomobject]@{ Detected = $false; Evidence = @() }
    }

    try {
        $content = [System.IO.File]::ReadAllText($MppLogPath)
    }
    catch {
        return [pscustomobject]@{ Detected = $false; Evidence = @() }
    }

    $evidence = @()
    $mppPatterns = @(
        'mofcomp.*fail'
        'failed to compile'
        'MOF compile'
        'error.*1603.*PolicyPlatform'
        'CustomAction.*MofCompile.*returned actual error code 1603'
    )

    foreach ($pattern in $mppPatterns) {
        $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        foreach ($m in $matches) {
            $start = [math]::Max(0, $m.Index - 50)
            $len   = [math]::Min(300, $content.Length - $start)
            $evidence += $content.Substring($start, $len).Trim()
        }
    }

    return [pscustomobject]@{
        Detected = ($evidence.Count -gt 0)
        Evidence = ($evidence | Select-Object -Unique)
    }
}

# ---------------------------------------------------------------------------
# Analysis Engines
# ---------------------------------------------------------------------------

function Invoke-AppDeploymentAnalysis {
    <#
    .SYNOPSIS
        Analyzes application deployment logs for a device.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$LogFolder,

        [string]$Hostname,

        [datetime]$Since
    )

    $appLogs = @('AppEnforce', 'AppDiscovery', 'CAS', 'ContentTransferManager', 'LocationServices')
    $allEntries = @()

    foreach ($logName in $appLogs) {
        $logPath = Join-Path $LogFolder "$logName.log"
        if (Test-Path -LiteralPath $logPath) {
            $params = @{ Path = $logPath }
            if ($Since) { $params['After'] = $Since }
            $allEntries += ConvertFrom-CMTraceLog @params
        }
    }

    if ($allEntries.Count -eq 0) {
        return [pscustomobject]@{
            Hostname        = $Hostname
            AnalysisType    = 'AppDeployment'
            Timestamp       = Get-Date
            TotalEntries    = 0
            Errors          = @()
            Warnings        = @()
            Summary         = "No application deployment log entries found."
            Recommendations = @()
        }
    }

    $enriched = Find-LogErrors -LogEntries $allEntries -IncludeInfo
    $errors   = @($enriched | Where-Object { $_.Type -eq 3 })
    $warnings = @($enriched | Where-Object { $_.Type -eq 2 })

    $recommendations = @()
    if ($errors.Count -gt 0) {
        foreach ($err in $errors) {
            if ($err.ErrorTranslation -and $err.ErrorTranslation.Resolution) {
                $recommendations += $err.ErrorTranslation.Resolution
            }
        }
        $recommendations = @($recommendations | Select-Object -Unique)
    }

    $summaryLines = @(
        "Application Deployment Analysis for $Hostname"
        "Total log entries: $($allEntries.Count)"
        "Errors: $($errors.Count)"
        "Warnings: $($warnings.Count)"
    )
    if ($errors.Count -gt 0) {
        $latest = $errors | Sort-Object DateTime -Descending | Select-Object -First 1
        $summaryLines += "Most recent error: [$($latest.LogFile)] $($latest.ErrorCode) - $($latest.Message.Substring(0, [math]::Min(150, $latest.Message.Length)))"
    }

    return [pscustomobject]@{
        Hostname        = $Hostname
        AnalysisType    = 'AppDeployment'
        Timestamp       = Get-Date
        TotalEntries    = $allEntries.Count
        Errors          = $errors
        Warnings        = $warnings
        AllEntries      = $enriched
        Summary         = ($summaryLines -join "`r`n")
        Recommendations = $recommendations
    }
}

function Invoke-SoftwareUpdateAnalysis {
    <#
    .SYNOPSIS
        Analyzes software update logs for a device.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$LogFolder,

        [string]$Hostname,

        [datetime]$Since
    )

    $updateLogs = @('WUAHandler', 'UpdatesDeployment', 'UpdatesHandler', 'UpdatesStore')
    $allEntries = @()

    foreach ($logName in $updateLogs) {
        $logPath = Join-Path $LogFolder "$logName.log"
        if (Test-Path -LiteralPath $logPath) {
            $params = @{ Path = $logPath }
            if ($Since) { $params['After'] = $Since }
            $allEntries += ConvertFrom-CMTraceLog @params
        }
    }

    if ($allEntries.Count -eq 0) {
        return [pscustomobject]@{
            Hostname        = $Hostname
            AnalysisType    = 'SoftwareUpdates'
            Timestamp       = Get-Date
            TotalEntries    = 0
            Errors          = @()
            Warnings        = @()
            Summary         = "No software update log entries found."
            Recommendations = @()
        }
    }

    $enriched = Find-LogErrors -LogEntries $allEntries -IncludeInfo
    $errors   = @($enriched | Where-Object { $_.Type -eq 3 })
    $warnings = @($enriched | Where-Object { $_.Type -eq 2 })

    $recommendations = @()
    foreach ($err in $errors) {
        if ($err.ErrorTranslation -and $err.ErrorTranslation.Resolution) {
            $recommendations += $err.ErrorTranslation.Resolution
        }
    }
    $recommendations = @($recommendations | Select-Object -Unique)

    $summaryLines = @(
        "Software Update Analysis for $Hostname"
        "Total log entries: $($allEntries.Count)"
        "Errors: $($errors.Count)"
        "Warnings: $($warnings.Count)"
    )

    return [pscustomobject]@{
        Hostname        = $Hostname
        AnalysisType    = 'SoftwareUpdates'
        Timestamp       = Get-Date
        TotalEntries    = $allEntries.Count
        Errors          = $errors
        Warnings        = $warnings
        AllEntries      = $enriched
        Summary         = ($summaryLines -join "`r`n")
        Recommendations = $recommendations
    }
}

function Invoke-ClientInstallAnalysis {
    <#
    .SYNOPSIS
        Analyzes CCM client installation logs for a device.
        Includes 3010 masking detection and root cause analysis.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$LogFolder,

        [string]$Hostname,

        [datetime]$Since
    )

    $clientLogs = @('ccmsetup', 'client.msi', 'MicrosoftPolicyPlatformSetup.msi')
    $allEntries = @()

    foreach ($logName in $clientLogs) {
        $logPath = Join-Path $LogFolder "$logName.log"
        if (Test-Path -LiteralPath $logPath) {
            $params = @{ Path = $logPath }
            if ($Since) { $params['After'] = $Since }
            $allEntries += ConvertFrom-CMTraceLog @params
        }
    }

    $enriched = Find-LogErrors -LogEntries $allEntries -IncludeInfo
    $errors   = @($enriched | Where-Object { $_.Type -eq 3 })
    $warnings = @($enriched | Where-Object { $_.Type -eq 2 })

    # 3010 detection
    $clientMsiPath = Join-Path $LogFolder "client.msi.log"
    $rebootCheck   = $null
    if ($Hostname -and (Test-Path -LiteralPath $clientMsiPath)) {
        $rebootCheck = Test-3010RebootPending -ClientMsiLogPath $clientMsiPath -Hostname $Hostname
    }

    # Root cause detection
    $rootCauses = @()

    # Firewall check
    $firewallResult = Test-FirewallBlock -LogEntries $allEntries -Hostname $Hostname
    if ($firewallResult.Detected) {
        $rootCauses += [pscustomobject]@{
            Cause    = 'Firewall / Port Block'
            Details  = "Blocked ports: $($firewallResult.BlockedPorts -join ', ')"
            Evidence = $firewallResult.Evidence
        }
    }

    # MPP corruption check
    $mppPath = Join-Path $LogFolder "MicrosoftPolicyPlatformSetup.msi.log"
    if (Test-Path -LiteralPath $mppPath) {
        $mppResult = Test-MppCorruption -MppLogPath $mppPath
        if ($mppResult.Detected) {
            $rootCauses += [pscustomobject]@{
                Cause    = 'Corrupt Microsoft Policy Platform'
                Details  = 'MOF compile failure detected. Requires: uninstall MPP via registry uninstall string, remove ccmsetup retry task from Task Scheduler, then re-run ccmsetup.'
                Evidence = $mppResult.Evidence
            }
        }
    }

    # DNS and domain checks (only if hostname provided and errors suggest connectivity issues)
    if ($Hostname) {
        $dnsResult = Test-DnsResolution -Hostname $Hostname
        if (-not $dnsResult.Resolvable) {
            $rootCauses += [pscustomobject]@{
                Cause    = 'DNS Resolution Failure'
                Details  = "Server not registered in DNS (Infoblox): $($dnsResult.Error)"
                Evidence = @()
            }
        }

        $domainResult = Test-DomainJoined -Hostname $Hostname
        if ($domainResult.DomainJoined -eq $false) {
            $rootCauses += [pscustomobject]@{
                Cause    = 'Server Not Domain Joined'
                Details  = "Server is not a member of any domain."
                Evidence = @()
            }
        }
    }

    $recommendations = @()
    foreach ($rc in $rootCauses) {
        $recommendations += "$($rc.Cause): $($rc.Details)"
    }
    foreach ($err in $errors) {
        if ($err.ErrorTranslation -and $err.ErrorTranslation.Resolution) {
            $recommendations += $err.ErrorTranslation.Resolution
        }
    }
    $recommendations = @($recommendations | Select-Object -Unique)

    $summaryLines = @(
        "Client Installation Analysis for $Hostname"
        "Total log entries: $($allEntries.Count)"
        "Errors: $($errors.Count)"
        "Warnings: $($warnings.Count)"
    )
    if ($rebootCheck) {
        $summaryLines += "3010 Reboot Status: $($rebootCheck.Explanation)"
    }
    if ($rootCauses.Count -gt 0) {
        $summaryLines += "Root Causes Detected: $($rootCauses.Count)"
        foreach ($rc in $rootCauses) {
            $summaryLines += "  - $($rc.Cause)"
        }
    }

    return [pscustomobject]@{
        Hostname        = $Hostname
        AnalysisType    = 'ClientInstall'
        Timestamp       = Get-Date
        TotalEntries    = $allEntries.Count
        Errors          = $errors
        Warnings        = $warnings
        AllEntries      = $enriched
        RebootCheck     = $rebootCheck
        RootCauses      = $rootCauses
        Summary         = ($summaryLines -join "`r`n")
        Recommendations = $recommendations
    }
}

function Test-RebootPending {
    <#
    .SYNOPSIS
        Convenience wrapper - checks if a device has a pending reboot
        from CCM client install.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$LogFolder,

        [Parameter(Mandatory)]
        [string]$Hostname
    )

    $clientMsiPath = Join-Path $LogFolder "client.msi.log"
    if (-not (Test-Path -LiteralPath $clientMsiPath)) {
        return [pscustomobject]@{
            RebootPending = $false
            Explanation   = "client.msi.log not found in $LogFolder"
        }
    }

    return Test-3010RebootPending -ClientMsiLogPath $clientMsiPath -Hostname $Hostname
}

# ---------------------------------------------------------------------------
# Export / Reporting
# ---------------------------------------------------------------------------

function Export-AnalysisCsv {
    <#
    .SYNOPSIS
        Exports analysis results to a CSV file.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $rows = @()
    foreach ($result in $Results) {
        $entries = if ($result.AllEntries) { $result.AllEntries } else { @() }
        foreach ($entry in $entries) {
            $translation = ''
            if ($entry.ErrorTranslation -and $entry.ErrorTranslation.Message) {
                $translation = $entry.ErrorTranslation.Message
            }

            $rows += [pscustomobject]@{
                Device      = $result.Hostname
                LogFile     = $entry.LogFile
                Severity    = $entry.Severity
                DateTime    = $entry.DateTime
                Component   = $entry.Component
                ErrorCode   = $entry.ErrorCode
                Translation = $translation
                Message     = $entry.Message
            }
        }
    }

    if ($rows.Count -gt 0) {
        $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($rows.Count) rows to $OutputPath"
    } else {
        Write-Log "No data to export." -Level WARN
    }
}

function Export-AnalysisHtml {
    <#
    .SYNOPSIS
        Exports analysis results to a styled, self-contained HTML report.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject[]]$Results,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [string]$ReportTitle = 'MECM Log Analysis Report'
    )

    $css = @(
        'body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }'
        'h1 { color: #0078D4; }'
        'h2 { color: #333; border-bottom: 2px solid #0078D4; padding-bottom: 5px; }'
        '.summary { background: #fff; padding: 15px; border-radius: 6px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }'
        '.summary-stat { display: inline-block; margin-right: 30px; }'
        '.stat-value { font-size: 24px; font-weight: bold; }'
        '.stat-label { font-size: 12px; color: #666; }'
        '.error-count { color: #B00020; }'
        '.warning-count { color: #B86E00; }'
        'table { border-collapse: collapse; width: 100%; background: #fff; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }'
        'th { background: #0078D4; color: #fff; padding: 10px; text-align: left; font-size: 13px; }'
        'td { padding: 8px 10px; border-bottom: 1px solid #eee; font-size: 13px; }'
        'tr:nth-child(even) { background: #f8fafc; }'
        '.severity-error { color: #B00020; font-weight: bold; }'
        '.severity-warning { color: #B86E00; }'
        '.severity-info { color: #666; }'
        '.recommendation { background: #FFF3CD; padding: 10px; border-left: 4px solid #FFC107; margin: 5px 0; }'
        '.root-cause { background: #F8D7DA; padding: 10px; border-left: 4px solid #DC3545; margin: 5px 0; }'
        '.reboot-pending { background: #FFE0B2; padding: 10px; border-left: 4px solid #FF9800; margin: 5px 0; }'
        '.timestamp { color: #999; font-size: 12px; }'
    ) -join "`r`n"

    $bodyParts = @()
    $bodyParts += "<h1>$ReportTitle</h1>"
    $bodyParts += "<p class='timestamp'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>"

    foreach ($result in $Results) {
        $bodyParts += "<h2>$($result.Hostname) - $($result.AnalysisType)</h2>"

        # Summary box
        $errorCount   = if ($result.Errors)   { $result.Errors.Count }   else { 0 }
        $warningCount = if ($result.Warnings) { $result.Warnings.Count } else { 0 }

        $bodyParts += "<div class='summary'>"
        $bodyParts += "<div class='summary-stat'><div class='stat-value'>$($result.TotalEntries)</div><div class='stat-label'>Total Entries</div></div>"
        $bodyParts += "<div class='summary-stat'><div class='stat-value error-count'>$errorCount</div><div class='stat-label'>Errors</div></div>"
        $bodyParts += "<div class='summary-stat'><div class='stat-value warning-count'>$warningCount</div><div class='stat-label'>Warnings</div></div>"
        $bodyParts += "</div>"

        # Root causes
        if ($result.RootCauses -and $result.RootCauses.Count -gt 0) {
            foreach ($rc in $result.RootCauses) {
                $bodyParts += "<div class='root-cause'><strong>Root Cause: $($rc.Cause)</strong><br/>$($rc.Details)</div>"
            }
        }

        # Reboot check
        if ($result.RebootCheck -and $result.RebootCheck.RebootPending) {
            $bodyParts += "<div class='reboot-pending'><strong>Reboot Pending</strong><br/>$($result.RebootCheck.Explanation)</div>"
        }

        # Recommendations
        if ($result.Recommendations -and $result.Recommendations.Count -gt 0) {
            foreach ($rec in $result.Recommendations) {
                $bodyParts += "<div class='recommendation'>$rec</div>"
            }
        }

        # Error/warning table
        $entries = @()
        if ($result.AllEntries) {
            $entries = @($result.AllEntries | Where-Object { $_.Type -ge 2 } | Sort-Object DateTime -Descending)
        }

        if ($entries.Count -gt 0) {
            $bodyParts += "<table>"
            $bodyParts += "<tr><th>Time</th><th>Log</th><th>Severity</th><th>Component</th><th>Error Code</th><th>Translation</th><th>Message</th></tr>"

            foreach ($entry in $entries) {
                $severityClass = "severity-$($entry.Severity.ToLower())"
                $translation   = ''
                if ($entry.ErrorTranslation -and $entry.ErrorTranslation.Message) {
                    $translation = [System.Web.HttpUtility]::HtmlEncode($entry.ErrorTranslation.Message)
                }
                $safeMsg = [System.Web.HttpUtility]::HtmlEncode($entry.Message)
                if ($safeMsg.Length -gt 300) { $safeMsg = $safeMsg.Substring(0, 300) + '...' }

                $bodyParts += "<tr>"
                $bodyParts += "<td>$($entry.DateTime.ToString('yyyy-MM-dd HH:mm:ss'))</td>"
                $bodyParts += "<td>$($entry.LogFile)</td>"
                $bodyParts += "<td class='$severityClass'>$($entry.Severity)</td>"
                $bodyParts += "<td>$($entry.Component)</td>"
                $bodyParts += "<td>$($entry.ErrorCode)</td>"
                $bodyParts += "<td>$translation</td>"
                $bodyParts += "<td>$safeMsg</td>"
                $bodyParts += "</tr>"
            }

            $bodyParts += "</table>"
        }
    }

    $html = @(
        '<!DOCTYPE html>'
        '<html><head>'
        '<meta charset="utf-8">'
        "<title>$ReportTitle</title>"
        "<style>$css</style>"
        '</head><body>'
        ($bodyParts -join "`r`n")
        '</body></html>'
    ) -join "`r`n"

    Set-Content -LiteralPath $OutputPath -Value $html -Encoding UTF8
    Write-Log "HTML report exported to $OutputPath"
}

function New-AnalysisSummary {
    <#
    .SYNOPSIS
        Generates a plain-text summary suitable for pasting into tickets/email.
    #>
    param(
        [Parameter(Mandatory)]
        [pscustomobject[]]$Results
    )

    $lines = @()

    foreach ($result in $Results) {
        $lines += "=== DEVICE: $($result.Hostname) ==="
        $lines += "Analysis: $($result.AnalysisType)"

        $errorCount   = if ($result.Errors)   { $result.Errors.Count }   else { 0 }
        $warningCount = if ($result.Warnings) { $result.Warnings.Count } else { 0 }

        if ($errorCount -eq 0 -and $warningCount -eq 0) {
            $lines += "Status: NO ISSUES FOUND"
        } else {
            $lines += "Status: $errorCount error(s), $warningCount warning(s)"
        }

        # Most recent error
        if ($result.Errors -and $result.Errors.Count -gt 0) {
            $latest = $result.Errors | Sort-Object DateTime -Descending | Select-Object -First 1
            $msg = $latest.Message
            if ($msg.Length -gt 150) { $msg = $msg.Substring(0, 150) + '...' }
            $lines += "Most Recent Error: $($latest.ErrorCode) - $msg"

            if ($latest.ErrorTranslation -and $latest.ErrorTranslation.Message) {
                $lines += "Translation: $($latest.ErrorTranslation.Message)"
            }
            if ($latest.ErrorTranslation -and $latest.ErrorTranslation.Resolution) {
                $lines += "Recommended Action: $($latest.ErrorTranslation.Resolution)"
            }
        }

        # Reboot check
        if ($result.RebootCheck) {
            if ($result.RebootCheck.RebootPending) {
                $lines += "Reboot Pending: YES - $($result.RebootCheck.Explanation)"
            } else {
                $lines += "Reboot Pending: NO"
            }
        }

        # Root causes
        if ($result.RootCauses -and $result.RootCauses.Count -gt 0) {
            $lines += "Root Causes Detected:"
            foreach ($rc in $result.RootCauses) {
                $lines += "  - $($rc.Cause): $($rc.Details)"
            }
        }

        $lines += ""
    }

    return ($lines -join "`r`n")
}

# ---------------------------------------------------------------------------
# End of module
# ---------------------------------------------------------------------------

Export-ModuleMember -Function *
