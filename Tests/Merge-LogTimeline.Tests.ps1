Describe 'Merge-LogTimeline' {

    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..\Module\LogAnalyzerCommon.psd1') -Force

        function New-FakeEntry {
            param(
                [string]$Message = 'Test message',
                [datetime]$DateTime = (Get-Date '2026-03-04 14:10:00'),
                [string]$Component = 'LocationServices',
                [string]$Severity = 'Error',
                [int]$Type = 3,
                [string]$LogFile = 'LocationServices.log',
                [string]$SignatureId = $null,
                [string]$SignatureName = $null
            )
            [pscustomobject]@{
                Message              = $Message
                DateTime             = $DateTime
                Component            = $Component
                Context              = ''
                Type                 = $Type
                Severity             = $Severity
                Thread               = '1'
                LogFile              = $LogFile
                LineNumber           = 1
                ErrorCode            = $null
                ErrorTranslation     = $null
                AllErrorCodes        = @()
                AllTranslations      = @()
                RepeatCount          = 1
                RepeatSpan           = $null
                SignatureId          = $SignatureId
                SignatureName        = $SignatureName
                SignatureExplanation = $null
                SignatureResolution  = $null
                EventId              = $null
                EventName            = $null
                EventOutcome         = $null
                EventEntryCount      = $null
            }
        }

        function New-FakeResult {
            param(
                [string]$AnalysisType,
                [pscustomobject[]]$AllEntries = @()
            )
            [pscustomobject]@{
                AnalysisType = $AnalysisType
                AllEntries   = $AllEntries
                Errors       = @($AllEntries | Where-Object { $_.Type -eq 3 })
                Warnings     = @($AllEntries | Where-Object { $_.Type -eq 2 })
            }
        }
    }

    Context 'Pass-through cases' {

        It 'Returns empty array for empty results' {
            $result = @(Merge-LogTimeline -AnalysisResults @())
            $result.Count | Should -Be 0
        }

        It 'Returns empty array when all results have no entries' {
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries @()
            $r2 = New-FakeResult -AnalysisType 'SoftwareUpdates' -AllEntries @()
            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            $result.Count | Should -Be 0
        }

        It 'Passes through single-result entries with event properties' {
            $entries = @(
                New-FakeEntry -Message 'Msg1' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Msg2' -DateTime (Get-Date '2026-03-04 14:10:10')
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $entries
            $result = @(Merge-LogTimeline -AnalysisResults @($r1))
            $result.Count | Should -Be 2
            $result[0].EventId | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Cross-engine merging' {

        It 'Merges entries from two engines into chronological order' {
            $appEntries = @(
                New-FakeEntry -Message 'App error 1' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'AppEnforce' -LogFile 'AppEnforce.log'
                New-FakeEntry -Message 'App error 2' -DateTime (Get-Date '2026-03-04 14:10:20') -Component 'AppEnforce' -LogFile 'AppEnforce.log'
            )
            $clientEntries = @(
                New-FakeEntry -Message 'Client error 1' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'ccmsetup' -LogFile 'ccmsetup.log'
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $appEntries
            $r2 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $clientEntries

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            $result.Count | Should -Be 3
            # Chronological order
            $result[0].Message | Should -Be 'App error 1'
            $result[1].Message | Should -Be 'Client error 1'
            $result[2].Message | Should -Be 'App error 2'
        }

        It 'Clusters cross-engine entries within time gap into single event' {
            $appEntries = @(
                New-FakeEntry -Message 'DP lookup failed' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'LocationServices' -LogFile 'LocationServices.log' -SignatureId 'DP-001'
            )
            $clientEntries = @(
                New-FakeEntry -Message 'ccmsetup aborted' -DateTime (Get-Date '2026-03-04 14:10:30') -Component 'ccmsetup' -LogFile 'ccmsetup.log'
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $appEntries
            $r2 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $clientEntries

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            $result.Count | Should -Be 2
            # Both should be in the same event
            $result[0].EventId | Should -Not -BeNullOrEmpty
            $result[0].EventId | Should -Be $result[1].EventId
        }

        It 'Names cross-engine event from signature matches' {
            $appEntries = @(
                New-FakeEntry -Message 'DP failed' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'LocationServices' -LogFile 'LocationServices.log' -SignatureId 'DP-001'
                New-FakeEntry -Message 'Content not found' -DateTime (Get-Date '2026-03-04 14:10:05') -Component 'CAS' -LogFile 'CAS.log' -SignatureId 'DP-002'
            )
            $clientEntries = @(
                New-FakeEntry -Message 'Install failed' -DateTime (Get-Date '2026-03-04 14:10:15') -Component 'ccmsetup' -LogFile 'ccmsetup.log'
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $appEntries
            $r2 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $clientEntries

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            $result[0].EventName | Should -Be 'Content access failure'
        }

        It 'Keeps entries from different time windows in separate events' {
            $appEntries = @(
                New-FakeEntry -Message 'App error' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'AppEnforce' -LogFile 'AppEnforce.log'
            )
            $updateEntries = @(
                New-FakeEntry -Message 'Update error' -DateTime (Get-Date '2026-03-04 14:20:00') -Component 'WUAHandler' -LogFile 'WUAHandler.log'
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $appEntries
            $r2 = New-FakeResult -AnalysisType 'SoftwareUpdates' -AllEntries $updateEntries

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            $result.Count | Should -Be 2
            # Isolated singletons - no event grouping
            $result[0].EventId | Should -BeNullOrEmpty
            $result[1].EventId | Should -BeNullOrEmpty
        }
    }

    Context 'Three-engine merge' {

        It 'Merges all three engine types into one timeline' {
            $appEntries = @(
                New-FakeEntry -Message 'App msg' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'AppEnforce' -LogFile 'AppEnforce.log'
            )
            $updateEntries = @(
                New-FakeEntry -Message 'Update msg' -DateTime (Get-Date '2026-03-04 14:10:05') -Component 'WUAHandler' -LogFile 'WUAHandler.log'
            )
            $clientEntries = @(
                New-FakeEntry -Message 'Client msg' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'ccmsetup' -LogFile 'ccmsetup.log'
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $appEntries
            $r2 = New-FakeResult -AnalysisType 'SoftwareUpdates' -AllEntries $updateEntries
            $r3 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $clientEntries

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2, $r3))
            $result.Count | Should -Be 3
            # All in same event (within 120s)
            $result[0].EventId | Should -Be $result[1].EventId
            $result[1].EventId | Should -Be $result[2].EventId
            $result[0].EventEntryCount | Should -Be 3
        }

        It 'Preserves LogFile provenance after merge' {
            $appEntries = @(
                New-FakeEntry -Message 'From app' -DateTime (Get-Date '2026-03-04 14:10:00') -LogFile 'AppEnforce.log'
            )
            $clientEntries = @(
                New-FakeEntry -Message 'From client' -DateTime (Get-Date '2026-03-04 14:10:05') -LogFile 'ccmsetup.log'
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $appEntries
            $r2 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $clientEntries

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            $result[0].LogFile | Should -Be 'AppEnforce.log'
            $result[1].LogFile | Should -Be 'ccmsetup.log'
        }
    }

    Context 'Re-clustering overwrites per-engine event assignments' {

        It 'Overwrites pre-existing EventId from per-engine clustering' {
            $entries1 = @(
                New-FakeEntry -Message 'Msg1' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'AppEnforce' -LogFile 'AppEnforce.log'
                New-FakeEntry -Message 'Msg2' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'AppEnforce' -LogFile 'AppEnforce.log'
            )
            # Simulate per-engine clustering having assigned EventId
            $entries1[0] | Add-Member -NotePropertyName EventId -NotePropertyValue 'EVT-001' -Force
            $entries1[1] | Add-Member -NotePropertyName EventId -NotePropertyValue 'EVT-001' -Force

            $entries2 = @(
                New-FakeEntry -Message 'Msg3' -DateTime (Get-Date '2026-03-04 14:10:05') -Component 'ccmsetup' -LogFile 'ccmsetup.log'
            )
            $entries2[0] | Add-Member -NotePropertyName EventId -NotePropertyValue 'EVT-001' -Force

            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $entries1
            $r2 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $entries2

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            # All 3 should be in the same re-clustered event
            $result[0].EventId | Should -Be $result[1].EventId
            $result[1].EventId | Should -Be $result[2].EventId
            # Event ID should be freshly assigned (EVT-001 from the merge counter)
            $result[0].EventId | Should -Be 'EVT-001'
        }
    }

    Context 'GapSeconds passthrough' {

        It 'Respects custom GapSeconds for cross-engine clustering' {
            $appEntries = @(
                New-FakeEntry -Message 'App msg' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'AppEnforce' -LogFile 'AppEnforce.log'
            )
            $clientEntries = @(
                New-FakeEntry -Message 'Client msg' -DateTime (Get-Date '2026-03-04 14:10:15') -Component 'ccmsetup' -LogFile 'ccmsetup.log'
            )
            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $appEntries
            $r2 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $clientEntries

            # With 10s gap, they should be in separate events (singletons)
            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2) -GapSeconds 10)
            $result[0].EventId | Should -BeNullOrEmpty
            $result[1].EventId | Should -BeNullOrEmpty

            # With default 120s gap, they should be in the same event
            $result2 = @(Merge-LogTimeline -AnalysisResults @($r1, $r2))
            $result2[0].EventId | Should -Be $result2[1].EventId
        }
    }

    Context 'Large volume cross-engine' {

        It 'Handles 100 entries from each of 3 engines' {
            $base = Get-Date '2026-03-04 14:10:00'
            $app = @(0..99 | ForEach-Object { New-FakeEntry -Message "App $_" -DateTime $base.AddSeconds($_ * 3) -Component 'AppEnforce' -LogFile 'AppEnforce.log' })
            $upd = @(0..99 | ForEach-Object { New-FakeEntry -Message "Upd $_" -DateTime $base.AddSeconds($_ * 3 + 1) -Component 'WUAHandler' -LogFile 'WUAHandler.log' })
            $cli = @(0..99 | ForEach-Object { New-FakeEntry -Message "Cli $_" -DateTime $base.AddSeconds($_ * 3 + 2) -Component 'ccmsetup' -LogFile 'ccmsetup.log' })

            $r1 = New-FakeResult -AnalysisType 'AppDeployment' -AllEntries $app
            $r2 = New-FakeResult -AnalysisType 'SoftwareUpdates' -AllEntries $upd
            $r3 = New-FakeResult -AnalysisType 'ClientInstall' -AllEntries $cli

            $result = @(Merge-LogTimeline -AnalysisResults @($r1, $r2, $r3))
            $result.Count | Should -Be 300
            # Should be chronologically sorted
            for ($i = 1; $i -lt $result.Count; $i++) {
                $result[$i].DateTime | Should -BeGreaterOrEqual $result[$i - 1].DateTime
            }
        }
    }
}
