# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Cut an OSDP-Embedded release: bump the version, commit, tag, and push.
.DESCRIPTION
    Modelled on OSDP.Net's ci/release.ps1, adapted to this repo. The
    script automates the *local* half of the release — it does NOT publish
    anything itself. Pushing the `v<version>` tag triggers the Azure
    Pipelines `package` job (ci/package.yml), and the crates.io publish +
    binary upload happen in the downstream Azure DevOps Release pipeline,
    behind its approval gate.

    Steps, in order:
      1. Validate: inside a git repo, on `main`, with a clean working tree.
      2. Sync: fetch origin and fast-forward `main` so the tag sits on top
         of what's published.
      3. Resolve the new version — incremented from the current one
         (Get-Version.ps1) per -IncrementType, or taken verbatim from
         -Version.
      4. Show the current -> new version and the commits since the last
         tag, then confirm (unless -AutoConfirm).
      5. Bump (Set-Version.ps1 — updates rust/Cargo.toml + CMakeLists.txt).
      6. Verify (Check-Code.ps1) so the tagged commit is known-green,
         unless -SkipChecks.
      7. Commit "Bump version to X.Y.Z", create annotated tag vX.Y.Z,
         push `main` and the tag.

    -DryRun walks every step and prints what it would do without writing,
    committing, tagging, or pushing anything.
.PARAMETER IncrementType
    Which SemVer field to bump off the current version: Patch (default),
    Minor, or Major. Ignored when -Version is given.
.PARAMETER Version
    Explicit version to release (e.g. '0.1.1' or '0.2.0-alpha.1'). Takes
    precedence over -IncrementType. Must be valid SemVer.
.PARAMETER DryRun
    Preview the whole flow without modifying, committing, tagging, or
    pushing anything.
.PARAMETER AutoConfirm
    Skip the interactive confirmation prompt (for unattended use).
.PARAMETER SkipChecks
    Skip the Check-Code.ps1 verification gates. The pre-push hook still
    runs them at push time if it's enabled.
.EXAMPLE
    ./scripts/New-Release.ps1 -DryRun
    Preview a patch release (0.1.0 -> 0.1.1) end to end.
.EXAMPLE
    ./scripts/New-Release.ps1
    Cut a patch release after confirming at the prompt.
.EXAMPLE
    ./scripts/New-Release.ps1 -IncrementType Minor
    Cut 0.1.0 -> 0.2.0.
.EXAMPLE
    ./scripts/New-Release.ps1 -Version 0.2.0-alpha.1 -AutoConfirm
#>

[CmdletBinding()]
param(
    [ValidateSet('Patch', 'Minor', 'Major')]
    [string]$IncrementType = 'Patch',

    [string]$Version,

    [switch]$DryRun,
    [switch]$AutoConfirm,
    [switch]$SkipChecks
)

$ErrorActionPreference = 'Stop'

# ---- console helpers -------------------------------------------------
# Distinct names so we don't shadow the built-in Write-Warning /
# Write-Error cmdlets.
function Write-Info { param([string]$m) Write-Host $m -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host $m -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host $m -ForegroundColor Yellow }
function Write-Step { param([string]$m) Write-Host "`n==> $m" -ForegroundColor Magenta }

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

# Run a git command and return trimmed stdout; throw on non-zero exit.
function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments)][string[]]$GitArgs)
    $out = & git @GitArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArgs -join ' ') failed:`n$out"
    }
    return ($out | Out-String).Trim()
}

Push-Location $repoRoot
try {
    if ($DryRun) { Write-Warn '*** DRY RUN — no files, commits, tags, or pushes will be made ***' }

    # ---- 1. validate repo state --------------------------------------
    Write-Step 'Validating repository state'

    if (-not (Test-Path (Join-Path $repoRoot '.git'))) {
        throw 'Not a git repository (no .git here). Run from the repo root.'
    }

    $branch = Invoke-Git rev-parse --abbrev-ref HEAD
    if ($branch -ne 'main') {
        throw "Releases are cut from 'main'; you are on '$branch'. Switch branches first."
    }
    Write-Ok "  on branch: $branch"

    $dirty = Invoke-Git status --porcelain
    if ($dirty) {
        Write-Warn $dirty
        throw 'Working tree has uncommitted changes. Commit or stash them before releasing.'
    }
    Write-Ok '  working tree clean'

    # ---- 2. sync with origin -----------------------------------------
    Write-Step 'Syncing with origin'
    Invoke-Git fetch origin --tags | Out-Null

    $local  = Invoke-Git rev-parse '@'
    $remote = Invoke-Git rev-parse 'origin/main'
    $base   = Invoke-Git merge-base '@' 'origin/main'
    if ($local -eq $remote) {
        Write-Ok '  main is up to date with origin/main'
    }
    elseif ($local -eq $base) {
        # Behind — fast-forward so the tag lands on the published tip.
        if ($DryRun) {
            Write-Info '  [dry-run] would fast-forward main from origin/main'
        }
        else {
            Write-Info '  main is behind origin/main — fast-forwarding'
            Invoke-Git merge --ff-only 'origin/main' | Out-Null
        }
    }
    elseif ($remote -eq $base) {
        # Ahead — fine: the release push below carries these commits to
        # origin along with the version bump. Just say so.
        $aheadCount = Invoke-Git rev-list --count 'origin/main..@'
        Write-Info "  main is $aheadCount commit(s) ahead of origin/main — they'll be pushed with the release"
    }
    else {
        throw 'Local main and origin/main have diverged. Reconcile them before releasing.'
    }

    # ---- 3. resolve the new version ----------------------------------
    Write-Step 'Resolving version'
    $current = & (Join-Path $PSScriptRoot 'Get-Version.ps1')
    Write-Info "  current version: $current"

    if ($Version) {
        $newVersion = $Version.Trim()
    }
    else {
        # Parse the numeric MAJOR.MINOR.PATCH, ignoring any pre-release
        # suffix on the current version, then bump the requested field.
        if ($current -notmatch '^(\d+)\.(\d+)\.(\d+)') {
            throw "Cannot parse current version '$current' as SemVer."
        }
        $maj = [int]$Matches[1]; $min = [int]$Matches[2]; $pat = [int]$Matches[3]
        switch ($IncrementType) {
            'Major' { $maj++; $min = 0; $pat = 0 }
            'Minor' { $min++; $pat = 0 }
            'Patch' { $pat++ }
        }
        $newVersion = "$maj.$min.$pat"
    }

    # Validate the resolved version (same grammar Set-Version enforces).
    if ($newVersion -notmatch '^(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.-]+)?$') {
        throw "Resolved version '$newVersion' is not valid SemVer."
    }
    $tag = "v$newVersion"

    # Refuse to clobber an existing tag.
    & git rev-parse --verify --quiet "refs/tags/$tag" *> $null
    if ($LASTEXITCODE -eq 0) {
        throw "Tag '$tag' already exists. Pick a different version."
    }

    Write-Ok "  new version:     $newVersion  (tag $tag)"

    # ---- 4. preview + confirm ----------------------------------------
    Write-Step "Commits since the last tag"
    $lastTag = (& git describe --tags --abbrev=0 2>$null)
    if ($LASTEXITCODE -eq 0 -and $lastTag) {
        & git --no-pager log --oneline "$lastTag..HEAD"
    }
    else {
        & git --no-pager log --oneline -10
    }

    Write-Host ''
    Write-Warn "About to release $current -> $newVersion and push tag $tag to origin."
    Write-Warn 'That triggers the pipeline; the Release pipeline then publishes to'
    Write-Warn 'crates.io (irreversible) and uploads the tool binaries after approval.'

    if (-not $AutoConfirm -and -not $DryRun) {
        $answer = Read-Host "Type the new version ($newVersion) to proceed, or anything else to abort"
        if ($answer -ne $newVersion) {
            Write-Warn 'Aborted — no changes made.'
            return
        }
    }

    # ---- 5. bump the version -----------------------------------------
    Write-Step "Bumping version to $newVersion"
    $setVersion = Join-Path $PSScriptRoot 'Set-Version.ps1'
    if ($DryRun) {
        & $setVersion -Version $newVersion -DryRun
    }
    else {
        & $setVersion -Version $newVersion
    }

    # ---- 6. verify ----------------------------------------------------
    if ($SkipChecks) {
        Write-Step 'Skipping verification gates (-SkipChecks)'
    }
    elseif ($DryRun) {
        Write-Step 'Skipping verification gates (dry run)'
    }
    else {
        Write-Step 'Running verification gates (Check-Code.ps1)'
        & (Join-Path $PSScriptRoot 'Check-Code.ps1')
        if ($LASTEXITCODE -ne 0) {
            throw ("Verification failed. The version bump is staged in your working " +
                   "tree but nothing was committed — fix the failures (or re-run with " +
                   "-SkipChecks) and try again. 'git checkout -- rust/Cargo.toml " +
                   "CMakeLists.txt' reverts the bump.")
        }
    }

    # ---- 7. commit, tag, push ----------------------------------------
    Write-Step 'Committing, tagging, and pushing'
    if ($DryRun) {
        Write-Info "  [dry-run] git add rust/Cargo.toml CMakeLists.txt"
        Write-Info "  [dry-run] git commit -m 'Bump version to $newVersion'"
        Write-Info "  [dry-run] git tag -a $tag -m 'Release $newVersion'"
        Write-Info "  [dry-run] git push origin main"
        Write-Info "  [dry-run] git push origin $tag"
        Write-Host ''
        Write-Ok 'Dry run complete. Re-run without -DryRun to cut the release.'
        return
    }

    Invoke-Git add rust/Cargo.toml CMakeLists.txt | Out-Null
    Invoke-Git commit -m "Bump version to $newVersion" | Out-Null
    Write-Ok "  committed: Bump version to $newVersion"

    Invoke-Git tag -a $tag -m "Release $newVersion" | Out-Null
    Write-Ok "  tagged:    $tag"

    Invoke-Git push origin main | Out-Null
    Write-Ok '  pushed:    origin main'
    Invoke-Git push origin $tag | Out-Null
    Write-Ok "  pushed:    origin $tag"

    Write-Host ''
    Write-Ok "Release $newVersion cut."
    Write-Info 'The Azure pipeline is now building the tagged artifacts. Approve the'
    Write-Info 'Release pipeline to publish the crate to crates.io and upload the'
    Write-Info 'tool binaries.'
}
finally {
    Pop-Location
}
