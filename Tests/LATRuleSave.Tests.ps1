Describe 'LATRuleSave (Session 9)' {

    BeforeAll {
        $script:RepoRoot    = Resolve-Path (Join-Path $PSScriptRoot '..')
        $script:ValidatorPs = Join-Path $script:RepoRoot 'Module\Test-LATRule.ps1'
        $script:SavePs      = Join-Path $script:RepoRoot 'Module\LATRuleSave.ps1'
        $script:EvaluatorPs = Join-Path $script:RepoRoot 'Module\Invoke-RuleEvaluator.ps1'
        . $script:ValidatorPs
        . $script:EvaluatorPs
        . $script:SavePs

        function New-TempDir {
            $p = Join-Path ([System.IO.Path]::GetTempPath()) ("lat-save-" + [guid]::NewGuid().ToString('N').Substring(0,10))
            $null = New-Item -ItemType Directory -Path $p -Force
            return $p
        }

        function New-Draft {
            param(
                [string]$Id = "draft-unit-$([guid]::NewGuid().ToString('N').Substring(0,8))",
                [string]$Scope = 'ClientInstall',
                [int]   $Confidence = 75,
                [string]$Source = 'local',
                [object[]]$All = @([pscustomobject]@{ signature = 'CCM-001' })
            )
            [pscustomobject]@{
                id         = $Id
                scope      = $Scope
                confidence = $Confidence
                version    = '1.0'
                authoredAt = '2026-04-24'
                authoredBy = 'jason'
                source     = $Source
                when       = [pscustomobject]@{ all = $All; any = @(); none = @() }
                verdict    = 'A sufficiently long verdict sentence for schema validation purposes.'
                fix        = 'Apply the remediation steps described in the runbook and retry.'
                evidence   = @()
                references = @()
            }
        }
    }

    Context 'Save-LATRuleDraft' {

        It 'writes a schema-valid draft to the overlay directory' {
            $root = New-TempDir
            try {
                $d = New-Draft -Id 'draft-saveok-aaa1'
                $path = Save-LATRuleDraft -Rule $d -OverlayRoot $root
                Test-Path $path | Should -BeTrue
                $path | Should -Be (Join-Path $root 'draft-saveok-aaa1.json')
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'creates the overlay directory if it does not exist' {
            $parent = New-TempDir
            try {
                $root = Join-Path $parent 'nested-does-not-exist-yet'
                $d = New-Draft -Id 'draft-mkdir-aaa2'
                $null = Save-LATRuleDraft -Rule $d -OverlayRoot $root
                Test-Path $root | Should -BeTrue
            } finally {
                Remove-Item $parent -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'throws on schema-invalid drafts' {
            $root = New-TempDir
            try {
                $d = New-Draft -Id 'draft-bad-aaa3'
                $d.scope = 'NotARealScope'
                { Save-LATRuleDraft -Rule $d -OverlayRoot $root } | Should -Throw -ExpectedMessage '*schema-valid*'
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'forces source=local even when the draft was tagged baseline' {
            $root = New-TempDir
            try {
                $d = New-Draft -Id 'draft-srcforce-aaa4' -Source 'baseline'
                $path = Save-LATRuleDraft -Rule $d -OverlayRoot $root
                $written = Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json
                $written.source | Should -Be 'local'
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'refuses to overwrite without -Force' {
            $root = New-TempDir
            try {
                $d = New-Draft -Id 'draft-clobber-aaa5'
                $null = Save-LATRuleDraft -Rule $d -OverlayRoot $root
                { Save-LATRuleDraft -Rule $d -OverlayRoot $root } | Should -Throw -ExpectedMessage '*already exists*'
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It '-Force overwrites an existing file' {
            $root = New-TempDir
            try {
                $d = New-Draft -Id 'draft-force-aaa6' -Confidence 75
                $null = Save-LATRuleDraft -Rule $d -OverlayRoot $root
                $d.confidence = 90
                $path = Save-LATRuleDraft -Rule $d -OverlayRoot $root -Force
                (Get-Content $path -Raw -Encoding UTF8 | ConvertFrom-Json).confidence | Should -Be 90
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'saved file writes UTF-8 without BOM' {
            $root = New-TempDir
            try {
                $d = New-Draft -Id 'draft-utf8-aaa7'
                $path = Save-LATRuleDraft -Rule $d -OverlayRoot $root
                $bytes = [System.IO.File]::ReadAllBytes($path)
                # UTF-8 BOM is EF BB BF
                ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -BeFalse
            } finally {
                Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'saved file round-trips through Get-LATRules local overlay' {
            $overlay = New-TempDir
            $baseline = New-TempDir
            try {
                $d = New-Draft -Id 'draft-roundtrip-aaa8'
                $null = Save-LATRuleDraft -Rule $d -OverlayRoot $overlay
                $rules = @(Get-LATRules -BaselinePath $baseline -LocalPath $overlay -WarningAction SilentlyContinue)
                @($rules | Where-Object { $_.id -eq 'draft-roundtrip-aaa8' }).Count | Should -Be 1
                ($rules | Where-Object { $_.id -eq 'draft-roundtrip-aaa8' }).source | Should -Be 'local'
            } finally {
                Remove-Item $overlay -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item $baseline -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Export-LATRulePatch' {

        It 'writes a patch file into OutputDir' {
            $out = New-TempDir
            try {
                $d = New-Draft -Id 'draft-patchok-bbb1'
                $r = Export-LATRulePatch -Rule $d -OutputDir $out
                Test-Path $r.Path | Should -BeTrue
                $r.Path | Should -Be (Join-Path $out 'lat-submit-draft-patchok-bbb1.patch')
            } finally {
                Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'body targets Rules/Baseline/SCOPE/ID.json with forward slashes' {
            $out = New-TempDir
            try {
                $d = New-Draft -Id 'draft-patchpath-bbb2' -Scope 'SoftwareUpdate'
                $r = Export-LATRulePatch -Rule $d -OutputDir $out
                $r.TargetRepoPath | Should -Be 'Rules/Baseline/SoftwareUpdate/draft-patchpath-bbb2.json'
                $r.Body | Should -Match 'diff --git a/Rules/Baseline/SoftwareUpdate/draft-patchpath-bbb2\.json'
                $r.Body | Should -Match 'new file mode 100644'
                $r.Body | Should -Match '@@ -0,0 \+1,\d+ @@'
            } finally {
                Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'patch body forces source=baseline even when draft said local' {
            $out = New-TempDir
            try {
                $d = New-Draft -Id 'draft-srcforce-bbb3' -Source 'local'
                $r = Export-LATRulePatch -Rule $d -OutputDir $out
                $r.Body | Should -Match '"source":\s*"baseline"'
                # Caller's draft unchanged
                $d.source | Should -Be 'local'
            } finally {
                Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'throws on schema-invalid drafts' {
            $out = New-TempDir
            try {
                $d = New-Draft -Id 'draft-bad-bbb4'
                $d.scope = 'NotAScope'
                { Export-LATRulePatch -Rule $d -OutputDir $out } | Should -Throw -ExpectedMessage '*schema-valid*'
            } finally {
                Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'patch hunk line count matches plus-line count' {
            $out = New-TempDir
            try {
                $d = New-Draft -Id 'draft-linecount-bbb5'
                $r = Export-LATRulePatch -Rule $d -OutputDir $out
                if ($r.Body -notmatch '@@ -0,0 \+1,(\d+) @@') { throw "hunk header not found" }
                $expected = [int]$matches[1]
                # Count lines that start with '+' but exclude the '+++ b/...' header line
                $plusCount = 0
                foreach ($line in ($r.Body -split "`n")) {
                    if ($line.StartsWith('+') -and -not $line.StartsWith('+++')) { $plusCount++ }
                }
                $plusCount | Should -Be $expected
            } finally {
                Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'patch applies cleanly via `git apply --check` when run against a clean tree' {
            # We cannot mutate the LAT repo here; create a fresh git workspace
            # in temp and apply the patch against that.
            $work = New-TempDir
            try {
                Push-Location $work
                try {
                    git init --initial-branch=main 2>&1 | Out-Null
                    git config user.email 'ci@example.invalid' | Out-Null
                    git config user.name 'ci' | Out-Null
                    'placeholder' | Out-File -FilePath 'seed.txt' -Encoding ASCII
                    git add seed.txt | Out-Null
                    git commit -m 'seed' --quiet | Out-Null

                    $d = New-Draft -Id 'draft-apply-bbb6'
                    $r = Export-LATRulePatch -Rule $d -OutputDir $work
                    # git apply --check exits 0 on cleanly-applicable patch
                    $check = git apply --check $r.Path 2>&1
                    $LASTEXITCODE | Should -Be 0 -Because "git apply --check output: $check"
                } finally {
                    Pop-Location
                }
            } finally {
                Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'refuses to overwrite an existing patch without -Force' {
            $out = New-TempDir
            try {
                $d = New-Draft -Id 'draft-clobber-bbb7'
                $null = Export-LATRulePatch -Rule $d -OutputDir $out
                { Export-LATRulePatch -Rule $d -OutputDir $out } | Should -Throw -ExpectedMessage '*already exists*'
            } finally {
                Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It '-Force overwrites an existing patch' {
            $out = New-TempDir
            try {
                $d = New-Draft -Id 'draft-force-bbb8' -Confidence 75
                $null = Export-LATRulePatch -Rule $d -OutputDir $out
                $d.confidence = 95
                $r = Export-LATRulePatch -Rule $d -OutputDir $out -Force
                $r.Body | Should -Match '"confidence":\s*95'
            } finally {
                Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
