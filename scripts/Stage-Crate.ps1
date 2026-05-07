# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Copy the C source tree into rust/osdp/vendor-c/ for `cargo publish`.
.DESCRIPTION
    The osdp-embedded crate's build.rs needs every .c/.h file in
    core/, pd/, and acu/. cargo publish only packages files inside
    the crate directory, so a .crate fetched from crates.io would be
    missing those sources and fail to compile.

    This script stages a copy at rust/osdp/vendor-c/ (gitignored) so
    `cargo publish` can pick it up via the Cargo.toml `include` list.
    build.rs detects the staged layout at compile time and falls back
    to the canonical <repo>/{core,pd,acu}/ paths for in-workspace
    dev builds.

    Run before `cargo publish`. Use -Clean to remove the staged copy
    afterwards (or just delete the directory by hand; it's gitignored).
.PARAMETER Clean
    Remove rust/osdp/vendor-c/ instead of populating it.
.EXAMPLE
    ./scripts/Stage-Crate.ps1
    # ... cargo publish --manifest-path rust/osdp/Cargo.toml ...
    ./scripts/Stage-Crate.ps1 -Clean
#>

param(
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$repoRoot   = Resolve-Path (Join-Path $PSScriptRoot '..')
$rustDir    = Join-Path $repoRoot 'rust'
$crateDir   = Join-Path $rustDir 'osdp'
$vendorDir  = Join-Path $crateDir 'vendor-c'

if ($Clean) {
    if (Test-Path $vendorDir) {
        Write-Host "Removing $vendorDir" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $vendorDir
    }
    else {
        Write-Host 'Nothing to clean.' -ForegroundColor DarkGray
    }
    return
}

# Source set: every .c and .h file under core/, pd/, acu/. Globbing
# is broad; CMakeLists.txt and other non-source files would be
# harmless extra bytes in the crate but we filter them out anyway.
$roots = @('core', 'pd', 'acu')

# Wipe any prior staging so a removed .c file in the source tree
# doesn't linger in the published .crate.
if (Test-Path $vendorDir) {
    Remove-Item -Recurse -Force $vendorDir
}

$total = 0
foreach ($root in $roots) {
    # Resolve to an absolute path with normalised separators so
    # GetRelativePath produces clean output across the bash / pwsh
    # split (the bash side hands us forward-slash paths, pwsh
    # internals mostly use back-slashes).
    $srcRoot = (Resolve-Path (Join-Path $repoRoot $root)).Path
    if (-not (Test-Path $srcRoot)) {
        throw "Expected source directory not found: $srcRoot"
    }

    $files = Get-ChildItem -Path $srcRoot -Recurse -File `
        -Include '*.c', '*.h'

    foreach ($file in $files) {
        # Compute path of $file relative to $srcRoot, then place it
        # under vendor-c/<root>/<relative-path>.
        $relative = [IO.Path]::GetRelativePath($srcRoot, $file.FullName)
        $dest     = Join-Path (Join-Path $vendorDir $root) $relative
        $destDir  = Split-Path $dest -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        Copy-Item -Path $file.FullName -Destination $dest -Force
        $total++
    }
}

Write-Host "Staged $total C source/header files into:" -ForegroundColor Green
Write-Host "  $vendorDir"
Write-Host ''
Write-Host 'Next:' -ForegroundColor Yellow
Write-Host '  cargo publish --manifest-path rust/osdp/Cargo.toml --dry-run --allow-dirty'
Write-Host '  cargo publish --manifest-path rust/osdp/Cargo.toml --allow-dirty'
Write-Host '  ./scripts/Stage-Crate.ps1 -Clean'
Write-Host ''
Write-Host '`--allow-dirty` is required: vendor-c/ is gitignored, so cargo sees it' -ForegroundColor DarkGray
Write-Host 'as untracked. The staged files are byte-for-byte copies of the' -ForegroundColor DarkGray
Write-Host 'committed core/, pd/, acu/ tree at HEAD; the published .crate still' -ForegroundColor DarkGray
Write-Host 'represents the same git state.' -ForegroundColor DarkGray
