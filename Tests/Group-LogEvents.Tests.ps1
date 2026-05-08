Describe 'Group-LogEvents' {

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
            }
        }
    }

    Context 'Pass-through cases' {

        It 'Returns empty array for empty input' {
            $result = @(Group-LogEvents -Entries @())
            $result.Count | Should -Be 0
        }

        It 'Returns singleton with null event properties' {
            $entry = New-FakeEntry -Message 'Solo entry'
            $result = @(Group-LogEvents -Entries @($entry))
            $result.Count | Should -Be 1
            $result[0].EventId | Should -BeNullOrEmpty
            $result[0].EventName | Should -BeNullOrEmpty
            $result[0].EventOutcome | Should -BeNullOrEmpty
            $result[0].EventEntryCount | Should -BeNullOrEmpty
        }
    }

    Context 'Time-gap clustering' {

        It 'Groups entries within default gap (120s) into one event' {
            $entries = @(
                New-FakeEntry -Message 'First'  -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Second' -DateTime (Get-Date '2026-03-04 14:10:30')
                New-FakeEntry -Message 'Third'  -DateTime (Get-Date '2026-03-04 14:11:00')
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result.Count | Should -Be 3
            $result[0].EventId | Should -Not -BeNullOrEmpty
            $result[0].EventId | Should -Be $result[1].EventId
            $result[0].EventId | Should -Be $result[2].EventId
            $result[0].EventEntryCount | Should -Be 3
        }

        It 'Splits entries into separate events when gap exceeds threshold' {
            $entries = @(
                New-FakeEntry -Message 'Early 1' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Early 2' -DateTime (Get-Date '2026-03-04 14:10:30')
                New-FakeEntry -Message 'Late 1'  -DateTime (Get-Date '2026-03-04 14:15:00')
                New-FakeEntry -Message 'Late 2'  -DateTime (Get-Date '2026-03-04 14:15:30')
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result.Count | Should -Be 4
            $result[0].EventId | Should -Be $result[1].EventId
            $result[2].EventId | Should -Be $result[3].EventId
            $result[0].EventId | Should -Not -Be $result[2].EventId
        }

        It 'Respects custom GapSeconds parameter' {
            $entries = @(
                New-FakeEntry -Message 'A' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'B' -DateTime (Get-Date '2026-03-04 14:10:15')
                New-FakeEntry -Message 'C' -DateTime (Get-Date '2026-03-04 14:10:40')
            )
            # Gap of 25s between B and C; with GapSeconds=20 they should split
            $result = @(Group-LogEvents -Entries $entries -GapSeconds 20)
            $result[0].EventId | Should -Be $result[1].EventId
            $result[1].EventId | Should -Not -Be $result[2].EventId
        }

        It 'Sorts entries by DateTime before clustering' {
            $entries = @(
                New-FakeEntry -Message 'Out of order 3' -DateTime (Get-Date '2026-03-04 14:11:00')
                New-FakeEntry -Message 'Out of order 1' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Out of order 2' -DateTime (Get-Date '2026-03-04 14:10:30')
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].Message | Should -Be 'Out of order 1'
            $result[1].Message | Should -Be 'Out of order 2'
            $result[2].Message | Should -Be 'Out of order 3'
            $result[0].EventId | Should -Be $result[2].EventId
        }

        It 'Leaves isolated singleton between two clusters ungrouped' {
            $entries = @(
                New-FakeEntry -Message 'Cluster1-A' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'Cluster1-B' -DateTime (Get-Date '2026-03-04 14:10:30')
                New-FakeEntry -Message 'Isolated'   -DateTime (Get-Date '2026-03-04 14:15:00')
                New-FakeEntry -Message 'Cluster2-A' -DateTime (Get-Date '2026-03-04 14:20:00')
                New-FakeEntry -Message 'Cluster2-B' -DateTime (Get-Date '2026-03-04 14:20:30')
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventId | Should -Not -BeNullOrEmpty
            $result[2].EventId | Should -BeNullOrEmpty
            $result[3].EventId | Should -Not -BeNullOrEmpty
            $result[0].EventId | Should -Not -Be $result[3].EventId
        }
    }

    Context 'Event naming' {

        It 'Names event from signature template when signatures match' {
            $entries = @(
                New-FakeEntry -Message 'Failed to get DP locations' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'DP-001' -SignatureName 'Distribution point unreachable'
                New-FakeEntry -Message 'Content not found'          -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'DP-002' -SignatureName 'Content not found on DP'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Content access failure'
        }

        It 'Names event from app deployment signatures' {
            $entries = @(
                New-FakeEntry -Message 'Execution failed'     -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'AppEnforce' -SignatureId 'APP-002' -SignatureName 'Install command execution failed'
                New-FakeEntry -Message 'Detection returned false' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'AppDiscovery' -SignatureId 'APP-001' -SignatureName 'Application not detected after install'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Application deployment failure'
        }

        It 'Names event from update scan signatures' {
            $entries = @(
                New-FakeEntry -Message 'Scan failed' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'WUAHandler' -SignatureId 'WUA-001' -SignatureName 'WSUS scan failure'
                New-FakeEntry -Message 'Scan error'  -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'WUAHandler' -SignatureId 'WUA-002'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Update scan failure'
        }

        It 'Names event from client install signatures' {
            $entries = @(
                New-FakeEntry -Message 'ccmsetup failed' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'ccmsetup' -LogFile 'ccmsetup.log' -SignatureId 'CCM-001'
                New-FakeEntry -Message 'MSI error'       -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'ccmsetup' -LogFile 'ccmsetup.log' -SignatureId 'CCM-002'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Client installation failure'
        }

        It 'Falls back to dominant component name when no signatures match' {
            $entries = @(
                New-FakeEntry -Message 'Some warning'    -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'WUAHandler' -LogFile 'WUAHandler.log' -Severity 'Warning' -Type 2
                New-FakeEntry -Message 'Another warning' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'WUAHandler' -LogFile 'WUAHandler.log' -Severity 'Warning' -Type 2
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Update scan activity'
        }

        It 'Falls back to raw component name for unknown components' {
            $entries = @(
                New-FakeEntry -Message 'Custom msg 1' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'CustomComponent'
                New-FakeEntry -Message 'Custom msg 2' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'CustomComponent'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'CustomComponent activity'
        }

        It 'Uses dominant component when cluster has mixed components' {
            $entries = @(
                New-FakeEntry -Message 'Msg1' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'CAS'
                New-FakeEntry -Message 'Msg2' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'LocationServices'
                New-FakeEntry -Message 'Msg3' -DateTime (Get-Date '2026-03-04 14:10:20') -Component 'CAS'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Content access activity'
        }
    }

    Context 'Event outcome' {

        It 'Sets outcome to Error when cluster contains errors' {
            $entries = @(
                New-FakeEntry -Message 'Warning'    -DateTime (Get-Date '2026-03-04 14:10:00') -Severity 'Warning' -Type 2
                New-FakeEntry -Message 'Error here' -DateTime (Get-Date '2026-03-04 14:10:10') -Severity 'Error'   -Type 3
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventOutcome | Should -Be 'Error'
        }

        It 'Sets outcome to Warning when cluster is all warnings' {
            $entries = @(
                New-FakeEntry -Message 'Warn 1' -DateTime (Get-Date '2026-03-04 14:10:00') -Severity 'Warning' -Type 2
                New-FakeEntry -Message 'Warn 2' -DateTime (Get-Date '2026-03-04 14:10:10') -Severity 'Warning' -Type 2
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventOutcome | Should -Be 'Warning'
        }

        It 'Sets outcome to Info when cluster is all info entries' {
            $entries = @(
                New-FakeEntry -Message 'Info 1' -DateTime (Get-Date '2026-03-04 14:10:00') -Severity 'Info' -Type 1
                New-FakeEntry -Message 'Info 2' -DateTime (Get-Date '2026-03-04 14:10:10') -Severity 'Info' -Type 1
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventOutcome | Should -Be 'Info'
        }
    }

    Context 'Event ID and entry count' {

        It 'Assigns sequential event IDs' {
            $entries = @(
                New-FakeEntry -Message 'A1' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'A2' -DateTime (Get-Date '2026-03-04 14:10:10')
                New-FakeEntry -Message 'B1' -DateTime (Get-Date '2026-03-04 14:15:00')
                New-FakeEntry -Message 'B2' -DateTime (Get-Date '2026-03-04 14:15:10')
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventId | Should -Be 'EVT-001'
            $result[2].EventId | Should -Be 'EVT-002'
        }

        It 'Sets correct EventEntryCount for each cluster' {
            $entries = @(
                New-FakeEntry -Message 'A1' -DateTime (Get-Date '2026-03-04 14:10:00')
                New-FakeEntry -Message 'A2' -DateTime (Get-Date '2026-03-04 14:10:10')
                New-FakeEntry -Message 'A3' -DateTime (Get-Date '2026-03-04 14:10:20')
                New-FakeEntry -Message 'B1' -DateTime (Get-Date '2026-03-04 14:15:00')
                New-FakeEntry -Message 'B2' -DateTime (Get-Date '2026-03-04 14:15:10')
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventEntryCount | Should -Be 3
            $result[3].EventEntryCount | Should -Be 2
        }

        It 'All entries in a cluster share the same EventId, EventName, and EventOutcome' {
            $entries = @(
                New-FakeEntry -Message 'E1' -DateTime (Get-Date '2026-03-04 14:10:00') -Component 'CAS'
                New-FakeEntry -Message 'E2' -DateTime (Get-Date '2026-03-04 14:10:10') -Component 'LocationServices'
                New-FakeEntry -Message 'E3' -DateTime (Get-Date '2026-03-04 14:10:20') -Component 'CAS'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $ids      = $result | ForEach-Object { $_.EventId } | Select-Object -Unique
            $names    = $result | ForEach-Object { $_.EventName } | Select-Object -Unique
            $outcomes = $result | ForEach-Object { $_.EventOutcome } | Select-Object -Unique
            $ids.Count | Should -Be 1
            $names.Count | Should -Be 1
            $outcomes.Count | Should -Be 1
        }
    }

    Context 'Large volume' {

        It 'Handles 200 entries in a single cluster' {
            $base = Get-Date '2026-03-04 14:10:00'
            $entries = @(0..199 | ForEach-Object {
                New-FakeEntry -Message "Entry $_" -DateTime $base.AddSeconds($_ * 2) -Component 'WUAHandler'
            })
            $result = @(Group-LogEvents -Entries $entries)
            $result.Count | Should -Be 200
            $result[0].EventId | Should -Not -BeNullOrEmpty
            $result[0].EventEntryCount | Should -Be 200
            ($result | ForEach-Object { $_.EventId } | Select-Object -Unique).Count | Should -Be 1
        }
    }

    Context 'Signature template coverage' {

        It 'Maps WMI-001 to WMI repository corruption' {
            $entries = @(
                New-FakeEntry -Message 'WMI broken' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'WMI-001'
                New-FakeEntry -Message 'WMI error'  -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'WMI-001'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'WMI repository corruption'
        }

        It 'Maps CERT-001 to Certificate issue' {
            $entries = @(
                New-FakeEntry -Message 'Cert expired' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'CERT-001'
                New-FakeEntry -Message 'Cert error'   -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'CERT-001'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Certificate issue'
        }

        It 'Maps DNS-001 to DNS resolution failure' {
            $entries = @(
                New-FakeEntry -Message 'DNS fail 1' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'DNS-001'
                New-FakeEntry -Message 'DNS fail 2' -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'DNS-001'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'DNS resolution failure'
        }

        It 'Maps ACCESS-001 to Access denied' {
            $entries = @(
                New-FakeEntry -Message 'Access denied 1' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'ACCESS-001'
                New-FakeEntry -Message 'Access denied 2' -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'ACCESS-001'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Access denied'
        }

        It 'Maps REBOOT-001 to Pending reboot' {
            $entries = @(
                New-FakeEntry -Message 'Reboot pending 1' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'REBOOT-001'
                New-FakeEntry -Message 'Reboot pending 2' -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'REBOOT-001'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Pending reboot'
        }

        It 'Maps POLICY-001 to Policy processing failure' {
            $entries = @(
                New-FakeEntry -Message 'Policy fail 1' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'POLICY-001'
                New-FakeEntry -Message 'Policy fail 2' -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'POLICY-001'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Policy processing failure'
        }

        It 'Maps BITS-001 to Content access failure' {
            $entries = @(
                New-FakeEntry -Message 'BITS stuck 1' -DateTime (Get-Date '2026-03-04 14:10:00') -SignatureId 'BITS-001'
                New-FakeEntry -Message 'BITS stuck 2' -DateTime (Get-Date '2026-03-04 14:10:10') -SignatureId 'BITS-001'
            )
            $result = @(Group-LogEvents -Entries $entries)
            $result[0].EventName | Should -Be 'Content access failure'
        }
    }
}
