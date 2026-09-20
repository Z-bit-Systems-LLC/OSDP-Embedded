# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Validate library.json — the PlatformIO manifest firmware consumers pin.
.DESCRIPTION
    The manifest is the one build description in this repo that nothing
    compiles during CI: a PlatformIO consumer resolves it from a git tag,
    so a mistake surfaces in someone else's firmware build, after the tag
    is cut and immutable. These checks stand in for that missing compile.

    What is verified:

      1. library.json parses, and carries the fields PlatformIO requires.
      2. srcFilter still starts with the deny-all `-<*>` base. Without it
         every later `+<...>` is additive on top of the WHOLE tree, so the
         tools, tests, vendored code and Rust crate would all reach the
         consumer's compiler.
      3. Every `+<dir>` in srcFilter exists, and contains at least one .c
         file (a renamed directory otherwise fails silently — the filter
         matches nothing and the library links short).
      4. Every `-I <dir>` in build.flags exists.
      5. Every header named in `headers` resolves under one of those
         include dirs — that is the include path a consumer is told to
         write, so a moved header must fail here.
      6. The source directories are the SAME set rust/osdp/build.rs
         compiles. build.rs is the other place in this repo that answers
         "which directories are the library"; when a new top-level source
         directory is added there and not here, PlatformIO consumers link
         against a library missing those objects. This is the check that
         catches the drift the glob cannot: srcFilter's `+<core/src/>` is
         recursive, so new SUBdirectories are picked up automatically, but
         a new TOP-LEVEL directory is silently excluded.
      7. The manifest version matches CMakeLists.txt's project() VERSION.
         Set-Version.ps1 keeps them in lockstep; this catches a hand-edit
         that bypassed it, before a tag burns the mismatch in.

    Exits 0 when every check passes, 1 otherwise, printing one line per
    failure. No PlatformIO installation required.
.EXAMPLE
    ./scripts/Test-Manifest.ps1
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot     = Resolve-Path (Join-Path $PSScriptRoot '..')
$manifestPath = Join-Path $repoRoot 'library.json'
$cmakePath    = Join-Path $repoRoot 'CMakeLists.txt'
$buildRsPath  = Join-Path $repoRoot 'rust/osdp/build.rs'

$problems = [System.Collections.Generic.List[string]]::new()
function Add-Problem { param([string]$Text) $problems.Add($Text) }

# ---- 1. parse ---------------------------------------------------------
if (-not (Test-Path $manifestPath)) {
    Write-Host "  [FAIL] library.json not found at $manifestPath" -ForegroundColor Red
    exit 1
}

try {
    $manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json
}
catch {
    Write-Host "  [FAIL] library.json is not valid JSON: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

foreach ($field in @('name', 'version', 'build')) {
    if (-not $manifest.PSObject.Properties.Name.Contains($field)) {
        Add-Problem "library.json is missing the required field '$field'"
    }
}

# Everything below needs build.*; bail out early if it is absent entirely.
if (-not $manifest.PSObject.Properties.Name.Contains('build')) {
    Write-Host "  [FAIL] library.json has no 'build' section — nothing to validate" -ForegroundColor Red
    exit 1
}

$srcFilter = @($manifest.build.srcFilter)
$flags     = @($manifest.build.flags)

# ---- 2. the deny-all base ---------------------------------------------
if ($srcFilter.Count -eq 0) {
    Add-Problem "build.srcFilter is empty — the whole repository would be compiled"
}
elseif ($srcFilter[0].Trim() -ne '-<*>') {
    Add-Problem ("build.srcFilter must start with '-<*>' (found '$($srcFilter[0])') — " +
                 "without it every '+<...>' adds to the whole tree instead of to nothing")
}

# ---- 3. included source directories exist and hold sources ------------
$includedDirs = [System.Collections.Generic.List[string]]::new()
foreach ($entry in $srcFilter) {
    if ($entry -notmatch '^\s*\+<(?<path>[^>]+)>\s*$') { continue }
    $rel  = $Matches['path'].TrimEnd('/', '*')
    $full = Join-Path $repoRoot $rel
    $includedDirs.Add($rel)

    if (-not (Test-Path $full)) {
        Add-Problem "srcFilter includes '$rel', which does not exist"
        continue
    }
    $cFiles = @(Get-ChildItem -Path $full -Filter '*.c' -Recurse -File -ErrorAction SilentlyContinue)
    if ($cFiles.Count -eq 0) {
        Add-Problem "srcFilter includes '$rel', which contains no .c files — renamed or emptied?"
    }
}

if ($includedDirs.Count -eq 0) {
    Add-Problem "build.srcFilter includes no directories — the library would compile nothing"
}

# ---- 4. exported include directories exist ----------------------------
$includePaths = [System.Collections.Generic.List[string]]::new()
foreach ($flag in $flags) {
    # Accept both '-I core/include' and '-Icore/include'.
    if ($flag -notmatch '^\s*-I\s*(?<path>\S+)\s*$') { continue }
    $rel  = $Matches['path']
    $full = Join-Path $repoRoot $rel
    $includePaths.Add($rel)

    if (-not (Test-Path $full)) {
        Add-Problem "build.flags exports '-I $rel', which does not exist"
    }
}

if ($includePaths.Count -eq 0) {
    Add-Problem "build.flags exports no -I include directory — consumers could not include the headers"
}

# ---- 5. advertised headers resolve ------------------------------------
if ($manifest.PSObject.Properties.Name.Contains('headers')) {
    foreach ($header in @($manifest.headers)) {
        $found = $false
        foreach ($inc in $includePaths) {
            if (Test-Path (Join-Path (Join-Path $repoRoot $inc) $header)) { $found = $true; break }
        }
        if (-not $found) {
            Add-Problem ("headers lists '$header', which is not reachable from any exported " +
                         "include dir ($($includePaths -join ', '))")
        }
    }
}

# ---- 6. same source directories the Rust build compiles ---------------
#
# build.rs names each .c file explicitly; reduce both sides to the set of
# top-level "<dir>/src" prefixes and compare. A directory the Rust build
# compiles but the manifest omits is the silent-exclusion bug.
if (Test-Path $buildRsPath) {
    $buildRs  = Get-Content -Raw -Path $buildRsPath
    $rustDirs = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in [regex]::Matches($buildRs, '"(?<path>[A-Za-z0-9_./-]+\.c)"')) {
        $parts = $m.Groups['path'].Value -split '/'
        if ($parts.Count -ge 2) { [void]$rustDirs.Add("$($parts[0])/$($parts[1])") }
    }

    $manifestDirs = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($d in $includedDirs) { [void]$manifestDirs.Add($d.TrimEnd('/')) }

    foreach ($dir in $rustDirs) {
        if (-not $manifestDirs.Contains($dir)) {
            Add-Problem ("rust/osdp/build.rs compiles sources from '$dir', which library.json's " +
                         "srcFilter excludes — PlatformIO consumers would link a short library. " +
                         "Add '+<$dir/>' to srcFilter, or confirm the directory is host-only.")
        }
    }
}

# ---- 7. version lockstep with CMake -----------------------------------
if (Test-Path $cmakePath) {
    $cmakeText = Get-Content -Raw -Path $cmakePath
    $vm = [regex]::Match($cmakeText, 'project\s*\([^)]*?VERSION\s+(?<v>\d+\.\d+\.\d+)')
    if ($vm.Success) {
        $cmakeVersion = $vm.Groups['v'].Value
        # The manifest carries full SemVer; CMake only the numeric prefix.
        $manifestNumeric = ($manifest.version -split '[-+]')[0]
        if ($manifestNumeric -ne $cmakeVersion) {
            Add-Problem ("version drift: library.json says '$($manifest.version)' " +
                         "(numeric '$manifestNumeric') but CMakeLists.txt project() says " +
                         "'$cmakeVersion' — bump with scripts/Set-Version.ps1, not by hand")
        }
    }
}

# ---- report -----------------------------------------------------------
if ($problems.Count -gt 0) {
    foreach ($p in $problems) { Write-Host "  [FAIL] $p" -ForegroundColor Red }
    Write-Host ''
    Write-Host "$($problems.Count) manifest problem(s) found." -ForegroundColor Red
    exit 1
}

Write-Host "  library.json OK — sources [$($includedDirs -join ', ')], includes [$($includePaths -join ', ')], version $($manifest.version)" -ForegroundColor Green
exit 0
