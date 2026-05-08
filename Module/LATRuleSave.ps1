# LATRuleSave.ps1
#
# Session 9: wizard save + submit-upstream. Two entry points:
#
#   Save-LATRuleDraft      -- write a draft to the local overlay
#                             (%LOCALAPPDATA%\LogAnalyzer\rules). Local
#                             overlay always wins on id collision when the
#                             evaluator loads rules (see Get-LATRules).
#   Export-LATRulePatch    -- emit a git-applicable unified diff that
#                             adds the draft to Rules/Baseline/<scope>/
#                             in the LAT repo, for community contribution
#                             / upstream submission. Optionally copies to
#                             clipboard.
#
# Depends on Test-LATRule (for schema gate). Caller dot-sources both.

Set-StrictMode -Version Latest

$script:LATRuleSave_DefaultPatchDir = $null  # resolved at runtime
$script:LATRuleSave_RepoRelativeRoot = 'Rules/Baseline'

function Get-LATLocalOverlayRoot {
    <#
    .SYNOPSIS
        Resolve the default local-overlay directory. Tests override via
        -Override. Creates no directories; caller handles that.
    #>
    param([string]$Override)
    if ($Override) { return $Override }
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = Join-Path $env:USERPROFILE 'AppData\Local' }
    return Join-Path $base 'LogAnalyzer\rules'
}

function Get-LATPatchDir {
    param([string]$Override)
    if ($Override) { return $Override }
    $d = 'c:/temp'
    if (-not (Test-Path $d)) { $d = [System.IO.Path]::GetTempPath() }
    return $d
}

function Format-LATRuleJson {
    # Produce a stable JSON string for persistence. Uses LF line endings so
    # the output is portable across platforms and patch-friendly. Callers
    # that need CRLF on disk should convert after.
    param([Parameter(Mandatory)] $Rule)
    $raw = $Rule | ConvertTo-Json -Depth 12
    # PS 5.1 ConvertTo-Json emits CRLF between nested blocks on Windows;
    # normalize to LF for predictability.
    $raw = $raw -replace "`r`n", "`n"
    $raw = $raw -replace "`r", "`n"
    # Ensure trailing newline so git apply stops cleanly at EOF
    if (-not $raw.EndsWith("`n")) { $raw += "`n" }
    return $raw
}

function Save-LATRuleDraft {
    <#
    .SYNOPSIS
        Write a schema-valid draft to the local-overlay rule directory.
    .PARAMETER Rule
        Draft rule object (from New-LATRuleDraft or hand-authored).
    .PARAMETER OverlayRoot
        Override the default %LOCALAPPDATA%\LogAnalyzer\rules path (tests).
    .PARAMETER Force
        Overwrite an existing file with the same id.
    .OUTPUTS
        [string] path written. Throws on schema failure or when the target
        exists without -Force.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Rule,
        [string]$OverlayRoot,
        [switch]$Force
    )
    # Force source = local so the evaluator's overlay-wins logic applies
    # regardless of how the draft was seeded.
    if ($Rule.PSObject.Properties['source']) {
        $Rule.source = 'local'
    } else {
        $Rule | Add-Member -NotePropertyName source -NotePropertyValue 'local' -Force
    }

    $check = Test-LATRule -Rule $Rule -Path 'draft'
    if (-not $check.Valid) {
        throw "Draft is not schema-valid; refusing to save. Errors:`n  $($check.Errors -join "`n  ")"
    }

    $root = Get-LATLocalOverlayRoot -Override $OverlayRoot
    if (-not (Test-Path $root)) {
        $null = New-Item -ItemType Directory -Path $root -Force
    }

    $file = Join-Path $root ("$($Rule.id).json")
    if ((Test-Path $file) -and -not $Force) {
        throw "Rule file already exists: $file. Pass -Force to overwrite."
    }

    $json = Format-LATRuleJson -Rule $Rule
    # Use .NET to write LF-terminated UTF-8 without BOM. Set-Content with
    # -Encoding UTF8 writes a BOM on PS 5.1 which trips some consumers.
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($file, $json, $utf8NoBom)
    return $file
}

function New-LATRulePatchBody {
    <#
    .SYNOPSIS
        Compose a git-applicable unified diff that adds a single rule file
        under Rules/Baseline/<scope>/<id>.json. Internal helper.
    #>
    param(
        [Parameter(Mandatory)] $Rule,
        [Parameter(Mandatory)] [string]$TargetPathPosix
    )
    $json = Format-LATRuleJson -Rule $Rule
    # Normalize for hunk: split on LF (we just normalized), strip trailing
    # empty line from final newline.
    $lines = $json -split "`n"
    if ($lines[-1] -eq '') { $lines = $lines[0..($lines.Length - 2)] }
    $plusLines = $lines | ForEach-Object { "+$_" }
    $count = $plusLines.Count

    # Pure-addition hunk header: `-0,0` (nothing removed) + `+1,N` (N lines added).
    $header = @(
        "diff --git a/$TargetPathPosix b/$TargetPathPosix"
        "new file mode 100644"
        "--- /dev/null"
        "+++ b/$TargetPathPosix"
        "@@ -0,0 +1,$count @@"
    )
    $body = $header + $plusLines
    return ($body -join "`n") + "`n"
}

function Export-LATRulePatch {
    <#
    .SYNOPSIS
        Emit a git-applicable patch file for adding `Rule` to the LAT
        baseline. Intended for community / upstream contribution flows.
    .DESCRIPTION
        The patch body forces `source = 'baseline'` on the rule (since it
        is going to the tracked baseline, not the local overlay). Target
        path is `Rules/Baseline/<scope>/<id>.json`. Patch is UTF-8,
        LF-terminated, unified diff. Apply with `git apply <patch>` from
        the repo root.
    .PARAMETER Rule
        Draft rule object.
    .PARAMETER OutputDir
        Destination directory. Default c:/temp; falls back to %TEMP%.
    .PARAMETER CopyToClipboard
        Also copy the patch body to the clipboard via Set-Clipboard.
    .PARAMETER Force
        Overwrite an existing patch file with the same id.
    .OUTPUTS
        PSCustomObject @{ Path; Body; TargetRepoPath }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Rule,
        [string]$OutputDir,
        [switch]$CopyToClipboard,
        [switch]$Force
    )
    # Clone the rule so the caller's draft stays untouched.
    $clone = $Rule | ConvertTo-Json -Depth 12 | ConvertFrom-Json
    if ($clone.PSObject.Properties['source']) {
        $clone.source = 'baseline'
    } else {
        $clone | Add-Member -NotePropertyName source -NotePropertyValue 'baseline' -Force
    }

    $check = Test-LATRule -Rule $clone -Path 'draft'
    if (-not $check.Valid) {
        throw "Draft is not schema-valid; refusing to build patch. Errors:`n  $($check.Errors -join "`n  ")"
    }
    if (-not ($clone.PSObject.Properties['scope'])) {
        throw "Draft is missing scope; cannot build target path."
    }

    $targetPath = "$($script:LATRuleSave_RepoRelativeRoot)/$($clone.scope)/$($clone.id).json"
    $body       = New-LATRulePatchBody -Rule $clone -TargetPathPosix $targetPath

    $dir = Get-LATPatchDir -Override $OutputDir
    if (-not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }
    $outFile = Join-Path $dir ("lat-submit-$($clone.id).patch")
    if ((Test-Path $outFile) -and -not $Force) {
        throw "Patch file already exists: $outFile. Pass -Force to overwrite."
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($outFile, $body, $utf8NoBom)

    if ($CopyToClipboard) {
        # Set-Clipboard is available in PS 5.1+. If it is not present
        # (e.g. a trimmed PS host), fall through quietly.
        if (Get-Command Set-Clipboard -ErrorAction SilentlyContinue) {
            try { Set-Clipboard -Value $body -ErrorAction Stop } catch { }
        }
    }

    return [pscustomobject]@{
        Path           = $outFile
        Body           = $body
        TargetRepoPath = $targetPath
    }
}
