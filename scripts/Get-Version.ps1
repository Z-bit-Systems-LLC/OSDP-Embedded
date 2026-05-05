# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Print the OSDP-Embedded version from rust/Cargo.toml.
.DESCRIPTION
    Z-bit Systems' release workflow keeps the canonical project version in
    `rust/Cargo.toml` under `[workspace.package].version`. This script reads
    and prints it; pair with Set-Version.ps1 to bump.
.PARAMETER Format
    'Simple'   - version string only (default; useful in CI / scripts)
    'Detailed' - labelled, colored output for interactive use.
.EXAMPLE
    ./scripts/Get-Version.ps1
    0.1.0-alpha.1
.EXAMPLE
    ./scripts/Get-Version.ps1 -Format Detailed
#>

param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Simple', 'Detailed')]
    [string]$Format = 'Simple'
)

$ErrorActionPreference = 'Stop'

# Resolve repo root (script lives in <repo>/scripts/). Chain
# Join-Path calls - Windows PowerShell 5.1 only accepts a single
# ChildPath argument per call.
$repoRoot   = Resolve-Path (Join-Path $PSScriptRoot '..')
$rustDir    = Join-Path $repoRoot 'rust'
$cargoToml  = Join-Path $rustDir 'Cargo.toml'

if (-not (Test-Path $cargoToml)) {
    throw "rust/Cargo.toml not found at: $cargoToml"
}

# Walk the file line by line. We track the current `[section]` and
# pick the first non-comment `version = "..."` we see while inside
# the `[workspace.package]` table. Comments and the values they
# might contain are skipped, which a single regex over the whole
# file would have to special-case.
$lines        = Get-Content $cargoToml
$currentTable = ''
$version      = $null
foreach ($raw in $lines) {
    $line = $raw.Trim()
    if ($line -match '^\[(.+?)\]\s*$') {
        $currentTable = $Matches[1]
        continue
    }
    # Strip trailing comments (TOML uses `#`). Crude but adequate
    # for our well-controlled Cargo.toml.
    $code = ($line -split '#', 2)[0].Trim()
    if ($currentTable -eq 'workspace.package' -and
        $code -match '^version\s*=\s*"([^"]+)"\s*$') {
        $version = $Matches[1]
        break
    }
}

if (-not $version) {
    throw "Could not find [workspace.package].version in $cargoToml"
}

if ($Format -eq 'Simple') {
    Write-Output $version
}
else {
    Write-Host 'OSDP-Embedded version: ' -NoNewline -ForegroundColor Yellow
    Write-Host $version -ForegroundColor Green
    if ($version -match '-') {
        Write-Host '(pre-release)' -ForegroundColor DarkYellow
    }
}
