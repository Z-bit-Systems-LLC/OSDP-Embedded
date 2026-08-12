# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Publish a GitHub Release for an already-pushed OSDP-Embedded tag.
.DESCRIPTION
    Step 3 of the release process, modelled on OSDP.Net's:

      1. Publish the docs.
      2. ./scripts/New-Release.ps1 -AutoConfirm  — bump, commit, tag, push.
      3. ./scripts/Publish-GitHubRelease.ps1     — this script.

    New-Release.ps1 deliberately stops at the push: the tag is what
    triggers the Azure pipeline, and the human-facing GitHub Release is a
    separate, later decision. This script closes that gap. It never
    creates or moves a tag — it only publishes a release for one that is
    already on origin.

    Steps, in order:
      1. Validate: inside a git repo; `gh` is installed and authenticated;
         the tag exists locally AND on origin; no GitHub Release exists
         for it yet (this script never clobbers one).
      2. Resolve the previous tag (`git describe --tags --abbrev=0
         <tag>^`) to bound the commit range. No previous tag means the
         whole history.
      3. Generate release notes from the commits in that range, grouped
         by Conventional Commit type. -NotesFile overrides generation
         entirely and is used verbatim.
      4. Show the rendered notes and confirm (unless -AutoConfirm).
      5. Create the release with `gh release create --notes-file`, adding
         --draft when asked, and print the URL gh returns.

    -DryRun prints the notes and the exact gh command and creates
    nothing.

    Note on history: releases start clean at v1.0.0. The pre-1.0 tags
    (v0.1.2 .. v0.1.28) are development iterations and are deliberately
    NOT backfilled.
.PARAMETER Tag
    The tag to publish, e.g. 'v1.0.0'. Defaults to the most recent tag
    reachable from HEAD (`git describe --tags --abbrev=0`).
.PARAMETER NotesFile
    Path to a hand-written notes file. When given, its contents are used
    verbatim and nothing is generated from the commit log — the escape
    hatch for a release that deserves prose instead of a commit dump.
.PARAMETER Draft
    Create the release as a draft, so a human can edit the notes in the
    GitHub UI before it goes public.
.PARAMETER DryRun
    Print the notes and the exact `gh release create` command that would
    run. Creates nothing — no release, no temp file.
.PARAMETER AutoConfirm
    Skip the interactive confirmation prompt (for unattended use).
.EXAMPLE
    ./scripts/Publish-GitHubRelease.ps1 -DryRun
    Preview the notes for the newest tag without publishing anything.
.EXAMPLE
    ./scripts/Publish-GitHubRelease.ps1 -Tag v1.0.0
    Publish v1.0.0 after confirming at the prompt.
.EXAMPLE
    ./scripts/Publish-GitHubRelease.ps1 -Tag v1.0.0 -Draft
    Stage v1.0.0 as a draft to hand-edit before releasing.
.EXAMPLE
    ./scripts/Publish-GitHubRelease.ps1 -Tag v1.0.0 -NotesFile docs/release-notes/v1.0.0.md -AutoConfirm
#>

[CmdletBinding()]
param(
    [string]$Tag,

    [string]$NotesFile,

    [switch]$Draft,
    [switch]$DryRun,
    [switch]$AutoConfirm
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

# The GitHub repository releases are published to. Passed to every gh
# call explicitly so the script does not depend on which remote the
# working copy happens to have.
$ghRepo  = 'Z-bit-Systems-LLC/OSDP-Embedded'
$repoUrl = "https://github.com/$ghRepo"

# Run a git command and return trimmed stdout; throw on non-zero exit.
function Invoke-Git {
    param([Parameter(ValueFromRemainingArguments)][string[]]$GitArgs)
    $out = & git @GitArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "git $($GitArgs -join ' ') failed:`n$out"
    }
    return ($out | Out-String).Trim()
}

# Conventional Commit type -> release-notes heading. Types absent from
# this map (chore, perf, style, revert, ...) and anything that does not
# parse as a conventional commit fall through to 'Other'.
$typeHeadings = [ordered]@{
    'feat'     = 'Features'
    'fix'      = 'Fixes'
    'docs'     = 'Documentation'
    'build'    = 'Build'
    'ci'       = 'Build'
    'refactor' = 'Refactoring'
    'test'     = 'Tests'
}

# Render order. 'Other' is last on purpose — it is the catch-all.
$headingOrder = @('Features', 'Fixes', 'Documentation', 'Build', 'Refactoring', 'Tests', 'Other')

# Build markdown release notes from `git log --oneline` lines.
function New-ReleaseNotes {
    param(
        [string[]]$LogLines,
        [string]$PrevTag,
        [string]$TagName
    )

    $sections = [ordered]@{}
    foreach ($h in $headingOrder) { $sections[$h] = [System.Collections.Generic.List[string]]::new() }

    foreach ($line in $LogLines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        # --oneline is "<short-sha> <subject>".
        if ($line -match '^(?<sha>[0-9a-f]{7,40})\s+(?<subject>.*)$') {
            $sha     = $Matches['sha']
            $subject = $Matches['subject'].Trim()
        }
        else {
            $sha     = ''
            $subject = $line.Trim()
        }

        $heading = 'Other'
        $scope   = ''
        $desc    = $subject
        $breaking = $false

        # type(optional-scope)!: description
        if ($subject -match '^(?<type>[a-zA-Z]+)(?:\((?<scope>[^)]*)\))?(?<bang>!)?:\s*(?<desc>.+)$') {
            $type     = $Matches['type'].ToLowerInvariant()
            $scope    = $Matches['scope']
            $breaking = [bool]$Matches['bang']
            $desc     = $Matches['desc'].Trim()
            if ($typeHeadings.Contains($type)) { $heading = $typeHeadings[$type] }
        }

        $bullet = '- '
        if ($breaking) { $bullet += '**BREAKING** ' }
        if ($scope)    { $bullet += "**$scope**: " }
        $bullet += $desc
        if ($sha)      { $bullet += " ($sha)" }

        $sections[$heading].Add($bullet)
    }

    $notes = [System.Collections.Generic.List[string]]::new()
    foreach ($h in $headingOrder) {
        if ($sections[$h].Count -eq 0) { continue }
        $notes.Add("## $h")
        $notes.Add('')
        foreach ($b in $sections[$h]) { $notes.Add($b) }
        $notes.Add('')
    }

    if ($notes.Count -eq 0) {
        $notes.Add('_No commits recorded for this release._')
        $notes.Add('')
    }

    if ($PrevTag) {
        $notes.Add("**Full changelog**: $repoUrl/compare/$PrevTag...$TagName")
    }
    else {
        # No earlier tag to compare against — link the commit list instead
        # so the line is never a broken compare URL.
        $notes.Add("**Full changelog**: $repoUrl/commits/$TagName")
    }

    return ($notes -join "`n")
}

$tempNotes = $null

Push-Location $repoRoot
try {
    if ($DryRun) { Write-Warn '*** DRY RUN — no GitHub Release will be created ***' }

    # ---- 1. validate -------------------------------------------------
    Write-Step 'Validating environment'

    if (-not (Test-Path (Join-Path $repoRoot '.git'))) {
        throw 'Not a git repository (no .git here). Run from the repo root.'
    }

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw ("GitHub CLI ('gh') is not on PATH. Install it from " +
               "https://cli.github.com/ and run 'gh auth login'.")
    }

    $authOut = & gh auth status 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub CLI is not authenticated. Run 'gh auth login'.`n$($authOut | Out-String)"
    }
    Write-Ok '  gh installed and authenticated'

    if (-not $Tag) {
        $described = (& git describe --tags --abbrev=0 2>&1)
        if ($LASTEXITCODE -ne 0 -or -not $described) {
            throw 'No tag reachable from HEAD. Cut a release first (scripts/New-Release.ps1) or pass -Tag.'
        }
        $Tag = ($described | Out-String).Trim()
        Write-Info "  no -Tag given; using the newest tag reachable from HEAD"
    }
    Write-Ok "  tag: $Tag"

    # Local tag must exist.
    & git rev-parse --verify --quiet "refs/tags/$Tag" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Tag '$Tag' does not exist locally. Check the name, or fetch it: git fetch origin --tags"
    }
    Write-Ok '  tag exists locally'

    # ...and on origin. A release whose tag origin doesn't have is a
    # broken link: GitHub renders the release but every source-archive
    # and compare URL on it points at nothing.
    $remoteTag = Invoke-Git ls-remote --tags origin "refs/tags/$Tag"
    if (-not $remoteTag) {
        throw ("Tag '$Tag' is not on origin. A release for a tag origin doesn't have " +
               "is a broken link. Push it first:`n    git push origin $Tag")
    }
    Write-Ok '  tag exists on origin'

    # Refuse to clobber an existing release.
    & gh release view $Tag --repo $ghRepo *> $null
    if ($LASTEXITCODE -eq 0) {
        throw ("A GitHub Release already exists for '$Tag'. This script never overwrites one — " +
               "edit it in the UI, or delete it first: gh release delete $Tag --repo $ghRepo")
    }
    Write-Ok '  no existing GitHub Release for this tag'

    # ---- 2. resolve the previous tag ---------------------------------
    Write-Step 'Resolving the commit range'

    $prevTag = $null
    # `<tag>^` fails if the tagged commit is a root commit — then there is
    # no earlier history to describe and the whole log is the range.
    & git rev-parse --verify --quiet "$Tag^" *> $null
    if ($LASTEXITCODE -eq 0) {
        $described = (& git describe --tags --abbrev=0 "$Tag^" 2>&1)
        if ($LASTEXITCODE -eq 0 -and $described) {
            $prevTag = ($described | Out-String).Trim()
        }
    }

    if ($prevTag) {
        $range = "$prevTag..$Tag"
        Write-Ok "  previous tag: $prevTag"
    }
    else {
        # Nothing tagged before this one: describe the whole history.
        $range = $Tag
        Write-Warn '  no previous tag found — using the whole history'
    }
    Write-Info "  range: $range"

    # ---- 3. build the notes ------------------------------------------
    if ($NotesFile) {
        Write-Step "Reading notes from $NotesFile"
        if (-not (Test-Path -LiteralPath $NotesFile)) {
            throw "Notes file '$NotesFile' not found."
        }
        $notes = Get-Content -LiteralPath $NotesFile -Raw
        if ([string]::IsNullOrWhiteSpace($notes)) {
            throw "Notes file '$NotesFile' is empty."
        }
        Write-Ok '  using the file verbatim (no notes generated from commits)'
    }
    else {
        Write-Step 'Generating notes from the commit log'
        $logOut   = Invoke-Git log --oneline --no-merges $range
        $logLines = @($logOut -split "`r?`n" | Where-Object { $_ -ne '' })
        Write-Info "  $($logLines.Count) commit(s) in range"
        $notes = New-ReleaseNotes -LogLines $logLines -PrevTag $prevTag -TagName $Tag
    }

    # ---- 4. preview + confirm ----------------------------------------
    Write-Step "Release notes for $Tag"
    Write-Host ''
    Write-Host $notes
    Write-Host ''

    # Computed even for the dry run so the printed command is the real one.
    $tempPath = Join-Path ([System.IO.Path]::GetTempPath()) "osdp-release-$Tag-$([guid]::NewGuid().ToString('N')).md"

    $ghArgs = @('release', 'create', $Tag, '--repo', $ghRepo, '--title', $Tag, '--notes-file', $tempPath)
    if ($Draft) { $ghArgs += '--draft' }

    if ($DryRun) {
        Write-Step 'Dry run — command that would be executed'
        Write-Info "  gh $($ghArgs -join ' ')"
        Write-Host ''
        Write-Ok 'Dry run complete. Re-run without -DryRun to publish the release.'
        return
    }

    $what = if ($Draft) { 'draft release' } else { 'public release' }
    Write-Warn "About to create a $what for $Tag on $ghRepo."
    if (-not $Draft) {
        Write-Warn 'A published release notifies watchers immediately. Use -Draft to review first.'
    }

    if (-not $AutoConfirm) {
        $answer = Read-Host "Type the tag ($Tag) to proceed, or anything else to abort"
        if ($answer -ne $Tag) {
            Write-Warn 'Aborted — nothing was created.'
            return
        }
    }

    # ---- 5. create the release ---------------------------------------
    Write-Step "Creating the GitHub Release"

    # Via a file, not --notes: the notes are multi-line markdown and can
    # be long, and neither belongs on a command line.
    $tempNotes = $tempPath
    Set-Content -LiteralPath $tempNotes -Value $notes -Encoding utf8NoBOM

    $created = & gh @ghArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "gh release create failed:`n$($created | Out-String)"
    }

    $url = ($created | Out-String).Trim()

    Write-Host ''
    if ($Draft) {
        Write-Ok "Draft release created for $Tag."
        Write-Info '  Review and publish it in the GitHub UI.'
    }
    else {
        Write-Ok "Release $Tag published."
    }
    if ($url) { Write-Info "  $url" }
}
finally {
    if ($tempNotes -and (Test-Path -LiteralPath $tempNotes)) {
        Remove-Item -LiteralPath $tempNotes -Force -ErrorAction SilentlyContinue
    }
    Pop-Location
}
