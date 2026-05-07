# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Bump the OSDP-Embedded version, syncing both Rust and C sources.
.DESCRIPTION
    Updates two places that reference the project version:
      * rust/Cargo.toml - [workspace.package].version (the
        osdp-embedded crate inherits via `version.workspace = true`)
      * CMakeLists.txt - project(... VERSION x.y.z) (numeric portion
        only; CMake doesn't accept pre-release suffixes)
    The Rust version is the source of truth for publishing; the C side
    mirrors only the numeric prefix.
.PARAMETER Version
    The new version string. Cargo / SemVer 2.0 form; pre-release
    suffixes like `0.1.0-alpha.2` are supported. Required.
.PARAMETER DryRun
    Print what would change without writing anything.
.EXAMPLE
    ./scripts/Set-Version.ps1 -Version 0.1.0-alpha.2
.EXAMPLE
    ./scripts/Set-Version.ps1 -Version 0.1.0 -DryRun
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [switch]$DryRun = $false
)

$ErrorActionPreference = 'Stop'

# Validate the version string is something cargo will accept. The
# regex below is the SemVer 2.0 grammar simplified: MAJOR.MINOR.PATCH
# with an optional pre-release segment.
$semverPattern = '^(\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.-]+)?$'
if ($Version -notmatch $semverPattern) {
    throw "Invalid version: '$Version'. Expected SemVer like '0.1.0' or '0.1.0-alpha.2'."
}
$numericPrefix = "$($Matches[1]).$($Matches[2]).$($Matches[3])"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

# Update a single line inside `Path` matched by predicate `LineMatches`.
# `Replacement` is invoked with the matched line and returns the new
# text. Errors if zero or more than one line matches - we want each
# bump to touch exactly one place per file.
function Update-Lines {
    param(
        [string]    $Path,
        [scriptblock] $LineMatches,
        [scriptblock] $Replacement,
        [string]    $Description
    )
    $full  = Join-Path $repoRoot $Path
    if (-not (Test-Path $full)) { throw "Not found: $full" }

    $lines = Get-Content $full
    $matchIndices = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if (& $LineMatches $lines[$i] $i) { $matchIndices += $i }
    }
    if ($matchIndices.Count -eq 0) {
        throw "$Path : no line matched ($Description)"
    }
    if ($matchIndices.Count -gt 1) {
        throw "$Path : ambiguous - $($matchIndices.Count) lines matched ($Description)"
    }
    $i = $matchIndices[0]
    $newLine = & $Replacement $lines[$i]
    if ($newLine -eq $lines[$i]) {
        Write-Host "  (no change) $Path - $Description" -ForegroundColor DarkGray
        return
    }

    if ($DryRun) {
        Write-Host "  [dry-run]   $Path - $Description" -ForegroundColor Cyan
        Write-Host "              - $($lines[$i])" -ForegroundColor DarkGray
        Write-Host "              + $newLine"      -ForegroundColor Cyan
    }
    else {
        $lines[$i] = $newLine
        Set-Content -Path $full -Value $lines
        Write-Host "  updated     $Path - $Description" -ForegroundColor Green
    }
}

Write-Host "Setting version to: $Version (numeric prefix: $numericPrefix)" -ForegroundColor Yellow
if ($DryRun) {
    Write-Host '(dry run - no files will be modified)' -ForegroundColor Cyan
}

# Track the current TOML table while walking lines. The closure runs
# per-line so we accumulate state across the loop.
$ws_table = @{ name = '' }
$ws_match = {
    param($line, $i)
    $trim = $line.Trim()
    if ($trim -match '^\[(.+?)\]\s*$') {
        $ws_table.name = $Matches[1]
        return $false
    }
    $code = ($trim -split '#', 2)[0].Trim()
    return ($ws_table.name -eq 'workspace.package' -and
            $code -match '^version\s*=\s*"[^"]+"\s*$')
}

# 1. rust/Cargo.toml - [workspace.package].version
Update-Lines `
    -Path 'rust/Cargo.toml' `
    -LineMatches $ws_match `
    -Replacement {
        param($line)
        [regex]::Replace($line, '(version\s*=\s*")[^"]+(")', ('${1}' + $Version + '${2}'))
    } `
    -Description '[workspace.package].version'

# 2. CMakeLists.txt - project(... VERSION x.y.z) - numeric only
Update-Lines `
    -Path 'CMakeLists.txt' `
    -LineMatches {
        param($line)
        return ($line -match 'VERSION\s+\d+\.\d+\.\d+')
    } `
    -Replacement {
        param($line)
        [regex]::Replace($line, '(VERSION\s+)\d+\.\d+\.\d+', ('${1}' + $numericPrefix))
    } `
    -Description 'project() VERSION (numeric prefix)'

if ($DryRun) {
    Write-Host "`nDry run complete. Re-run without -DryRun to apply." -ForegroundColor Cyan
}
else {
    Write-Host "`nVersion bumped to $Version. Next steps:" -ForegroundColor Yellow
    Write-Host '  git add rust/Cargo.toml rust/osdp/Cargo.toml CMakeLists.txt'
    Write-Host "  git commit -m `"Bump version to $Version`""
    Write-Host "  git tag v$Version"
    Write-Host "  git push origin main && git push origin v$Version"
}
