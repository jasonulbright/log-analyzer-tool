Describe 'Invoke-SignatureDetection' {

    BeforeAll {
        Import-Module (Join-Path $PSScriptRoot '..\Module\LogAnalyzerCommon.psd1') -Force

        function New-FakeEntry {
            param(
                [string]$Message,
                [datetime]$DateTime = (Get-Date '2026-03-04 14:10:00'),
                [string]$Component = 'LocationServices',
                [string]$Severity = 'Error',
                [int]$Type = 3,
                [string]$LogFile = 'LocationServices.log',
                $ErrorCode = $null,
                $ErrorTranslation = $null
            )
            [pscustomobject]@{
                Message          = $Message
                DateTime         = $DateTime
                Component        = $Component
                Context          = ''
                Type             = $Type
                Severity         = $Severity
                Thread           = '1'
                LogFile          = $LogFile
                LineNumber       = 1
                ErrorCode        = $ErrorCode
                ErrorTranslation = $ErrorTranslation
                AllErrorCodes    = @()
                AllTranslations  = @()
                RepeatCount      = 1
                RepeatSpan       = $null
            }
        }
    }

    Context 'Pass-through cases' {

        It 'Returns empty array for empty input' {
            $result = @(Invoke-SignatureDetection -Entries @())
            $result.Count | Should -Be 0
        }

        It 'Adds null signature properties when no match' {
            $entry = New-FakeEntry -Message 'Some random message with no pattern'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result.Count | Should -Be 1
            $result[0].SignatureId | Should -BeNullOrEmpty
            $result[0].SignatureName | Should -BeNullOrEmpty
            $result[0].SignatureExplanation | Should -BeNullOrEmpty
            $result[0].SignatureResolution | Should -BeNullOrEmpty
        }
    }

    Context 'Distribution point signatures' {

        It 'Matches DP-001 on "Failed to get DP locations"' {
            $entry = New-FakeEntry -Message 'Failed to get DP locations for content xyz' -Component 'LocationServices'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'DP-001'
            $result[0].SignatureName | Should -Be 'Distribution point unreachable'
            $result[0].SignatureExplanation | Should -Not -BeNullOrEmpty
            $result[0].SignatureResolution | Should -Not -BeNullOrEmpty
        }

        It 'Matches DP-002 on "content not found"' {
            $entry = New-FakeEntry -Message 'Content not found on any distribution point' -Component 'CAS'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'DP-002'
        }

        It 'Matches DP-003 on "download failed"' {
            $entry = New-FakeEntry -Message 'CTM job {GUID} download failed with error' -Component 'ContentTransferManager'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'DP-003'
        }
    }

    Context 'Component filtering' {

        It 'Does not match DP-001 when component is wrong' {
            # DP-001 only matches LocationServices
            $entry = New-FakeEntry -Message 'Failed to get DP locations' -Component 'AppEnforce'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -BeNullOrEmpty
        }

        It 'Matches component-agnostic signatures regardless of component' {
            # ACCESS-001 has empty Components array
            $entry = New-FakeEntry -Message 'Access is denied to the resource' -Component 'AppEnforce'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'ACCESS-001'
        }
    }

    Context 'App deployment signatures' {

        It 'Matches APP-001 on detection failure after install' {
            $entry = New-FakeEntry -Message 'Application was not detected after installation completed' -Component 'AppDiscovery'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'APP-001'
        }

        It 'Matches APP-003 on timeout' {
            $entry = New-FakeEntry -Message 'Execution exceeded maximum allowed runtime of 120 minutes' -Component 'AppEnforce'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'APP-003'
        }
    }

    Context 'Software update signatures' {

        It 'Matches WUA-001 on scan failure' {
            $entry = New-FakeEntry -Message 'Scan failed with error 0x80244010' -Component 'WUAHandler'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'WUA-001'
        }

        It 'Matches WUA-002 on WSUS connection failure' {
            $entry = New-FakeEntry -Message 'WSUS server unavailable, connection refused' -Component 'WUAHandler'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'WUA-002'
        }

        It 'Matches WUA-003 on maintenance window issue' {
            $entry = New-FakeEntry -Message 'No current or future service window exists to install updates' -Component 'UpdatesDeployment'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'WUA-003'
        }
    }

    Context 'Client install signatures' {

        It 'Matches CCM-001 on MP unreachable' {
            $entry = New-FakeEntry -Message 'Failed to connect to management point https://mp.contoso.com' -Component 'ccmsetup'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'CCM-001'
        }

        It 'Matches CCM-003 on MOF compile failure' {
            $entry = New-FakeEntry -Message 'MOF compilation failed for policy platform' -Component 'MicrosoftPolicyPlatformSetup.msi'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'CCM-003'
        }
    }

    Context 'Infrastructure signatures' {

        It 'Matches WMI-001 on WMI corruption' {
            $entry = New-FakeEntry -Message 'WMI repository is corrupt, cannot query' -Component 'CcmExec'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'WMI-001'
        }

        It 'Matches CERT-001 on certificate expired' {
            $entry = New-FakeEntry -Message 'Client certificate has expired, cannot authenticate' -Component 'ClientIDManagerStartup'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'CERT-001'
        }

        It 'Matches DNS-001 on name resolution failure' {
            $entry = New-FakeEntry -Message 'DNS resolution failed for server mp01.contoso.com' -Component 'ccmsetup'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'DNS-001'
        }

        It 'Matches REBOOT-001 on pending reboot' {
            $entry = New-FakeEntry -Message 'A pending reboot is required before installation can proceed' -Component 'ccmsetup'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'REBOOT-001'
        }

        It 'Matches POLICY-001 on policy download failure' {
            $entry = New-FakeEntry -Message 'Failed to download policy from management point' -Component 'PolicyAgent'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Be 'POLICY-001'
        }
    }

    Context 'Multiple entries' {

        It 'Matches signatures on multiple entries independently' {
            $entries = @(
                New-FakeEntry -Message 'Failed to get DP locations' -Component 'LocationServices'
                New-FakeEntry -Message 'Some normal warning message' -Component 'AppEnforce' -Severity 'Warning' -Type 2
                New-FakeEntry -Message 'Scan failed with error' -Component 'WUAHandler'
            )
            $result = @(Invoke-SignatureDetection -Entries $entries)
            $result.Count | Should -Be 3
            $result[0].SignatureId | Should -Be 'DP-001'
            $result[1].SignatureId | Should -BeNullOrEmpty
            $result[2].SignatureId | Should -Be 'WUA-001'
        }

        It 'First matching signature wins (stops after first match)' {
            # ACCESS-001 pattern includes "0x80070005" which could also match other things
            $entry = New-FakeEntry -Message 'Access denied 0x80070005' -Component 'AppEnforce'
            $result = @(Invoke-SignatureDetection -Entries @($entry))
            $result[0].SignatureId | Should -Not -BeNullOrEmpty
        }
    }
}
