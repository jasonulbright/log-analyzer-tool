@{
    RootModule        = 'LogAnalyzerCommon.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author            = 'Jason Ulbright'
    Description       = 'MECM log retrieval, CMTrace parsing, error code translation, and analysis.'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        # Logging
        'Initialize-Logging'
        'Write-Log'

        # Device resolution
        'Resolve-DeviceList'

        # Log retrieval
        'Test-AdminShareAccess'
        'Get-RemoteLogFiles'
        'Copy-RemoteLogFiles'

        # CMTrace parsing
        'ConvertFrom-CMTraceLog'

        # Error code translation
        'Import-ErrorCodeDatabase'
        'Resolve-ErrorCode'

        # Analysis engines
        'Invoke-AppDeploymentAnalysis'
        'Invoke-SoftwareUpdateAnalysis'
        'Invoke-ClientInstallAnalysis'
        'Find-LogErrors'
        'Test-RebootPending'

        # 3010 masking detection
        'Get-ClientMsiExitCode'
        'Get-LastRebootTime'
        'Test-3010RebootPending'

        # Root cause detection
        'Test-FirewallBlock'
        'Test-DomainJoined'
        'Test-DnsResolution'
        'Test-MppCorruption'

        # Export / reporting
        'Export-AnalysisCsv'
        'Export-AnalysisHtml'
        'New-AnalysisSummary'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
}
