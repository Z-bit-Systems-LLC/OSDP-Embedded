# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Run every pre-push quality gate locally — the same checks CI enforces.
.DESCRIPTION
    Mirrors ci/build.yml so a clean run here means the Azure pipeline's
    `build` job should pass. Two stacks are verified:

      C library + tools (CMake / CTest)
        1. configure   (Release, tests + tools ON)
        2. build
        3. ctest

      Rust workspace (cargo)
        4. cargo fmt   --check        (formatting gate)
        5. cargo clippy -D warnings   (lint gate; warnings are errors)
        6. cargo build  --release     (workspace)
        7. cargo test   --release     (workspace)
        8. cargo run    --example loopback
        9. cargo run    --example loopback_sc
       10. cargo run    --example loopback_sc2

    Every gate runs even if an earlier one fails (dependent steps are
    skipped, not silently passed), so a single invocation surfaces all
    problems at once. The script exits non-zero if any gate failed,
    which makes it usable straight from a git pre-push hook.

    On Windows + MSVC, run from a *Developer PowerShell for VS* so `cl`
    and `rc` are on PATH — the C presets use the Ninja generator, which
    doesn't locate the toolchain on its own.
.PARAMETER SkipC
    Skip the C library + tools (CMake / CTest) stack.
.PARAMETER SkipRust
    Skip the Rust workspace (cargo) stack.
.PARAMETER Fix
    Run `cargo fmt` to auto-format instead of `cargo fmt --check`. The
    formatting gate then reports what it changed rather than failing.
.EXAMPLE
    ./scripts/Check-Code.ps1
    Run all gates. Use before every push.
.EXAMPLE
    ./scripts/Check-Code.ps1 -SkipC
    Only the Rust gates (e.g. when iterating on the wrapper crate).
.EXAMPLE
    ./scripts/Check-Code.ps1 -Fix
    Auto-apply formatting, then run the remaining gates.
#>

[CmdletBinding()]
param(
    [switch]$SkipC,
    [switch]$SkipRust,
    [switch]$Fix
)

# Don't let $ErrorActionPreference = 'Stop' abort the whole run on the
# first failing external tool — we want to collect every gate's result.
# Native-command failures are detected via $LASTEXITCODE instead.
$ErrorActionPreference = 'Continue'

# Resolve repo root (script lives in <repo>/scripts/). Chain Join-Path
# calls — Windows PowerShell 5.1 accepts a single ChildPath per call.
$repoRoot  = Resolve-Path (Join-Path $PSScriptRoot '..')
$rustToml  = Join-Path (Join-Path $repoRoot 'rust') 'Cargo.toml'

# cargo installs to ~/.cargo/bin by default but a non-login / non-VS
# shell may not have it on PATH. Add it pre-emptively so the Rust gates
# work from a plain PowerShell, without disturbing an existing entry.
$cargoBin = Join-Path (Join-Path $env:USERPROFILE '.cargo') 'bin'
if ((Test-Path $cargoBin) -and ($env:Path -notlike "*$cargoBin*")) {
    $env:Path = "$cargoBin;$env:Path"
}

function Test-Tool {
    param([Parameter(Mandatory)][string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# When cmake isn't already on PATH (i.e. we're not running from a
# "Developer PowerShell for VS"), try to locate a Visual Studio install
# and import its build environment so the CMake/Ninja/MSVC stack can run
# instead of being skipped. cmake, ninja, cl and rc all ship *inside*
# Visual Studio and are absent from a plain shell's PATH. Returns $true
# if cmake is invokable afterwards, $false if no toolchain was found.
function Initialize-VsToolchain {
    if (Test-Tool 'cmake') { return $true }

    # Locate the VS install. vswhere is the canonical locator; fall back
    # to scanning the standard install roots if it's missing.
    $vsRoot = $null
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $vsRoot = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null | Select-Object -First 1
    }
    if (-not $vsRoot) {
        foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if (-not $pf) { continue }
            $base = Join-Path $pf 'Microsoft Visual Studio'
            if (-not (Test-Path $base)) { continue }
            $hit = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                ForEach-Object { Get-ChildItem $_.FullName -Directory -ErrorAction SilentlyContinue } |
                Where-Object { Test-Path (Join-Path $_.FullName 'VC\Auxiliary\Build\vcvars64.bat') } |
                Select-Object -First 1
            if ($hit) { $vsRoot = $hit.FullName; break }
        }
    }
    if (-not $vsRoot) { return $false }

    $vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
    if (-not (Test-Path $vcvars)) { return $false }

    # Import the environment vcvars64 produces (PATH, INCLUDE, LIB, ...)
    # into this process — the standard "source vcvars into PowerShell"
    # trick: run it in cmd, dump `set`, and copy each variable across.
    cmd /c "`"$vcvars`" >nul 2>&1 && set" 2>$null | ForEach-Object {
        if ($_ -match '^([^=]+)=(.*)$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }

    # Belt and suspenders: this machine's vcvars has been seen to set
    # INCLUDE/LIB but leave cmake/ninja/cl/rc off PATH. Prepend the
    # bundled cmake + ninja and the newest MSVC toolset / Windows SDK
    # tool dirs so the executables resolve regardless. Newest dir wins so
    # a VS update (which changes the toolset version) needs no edit here.
    $extra = @()
    $cmakeBin = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
    $ninjaBin = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja'
    foreach ($b in @($cmakeBin, $ninjaBin)) { if (Test-Path $b) { $extra += $b } }

    $msvcRoot = Join-Path $vsRoot 'VC\Tools\MSVC'
    if (Test-Path $msvcRoot) {
        $ts = Get-ChildItem $msvcRoot -Directory -ErrorAction SilentlyContinue |
              Sort-Object Name -Descending | Select-Object -First 1
        if ($ts) {
            $b = Join-Path $ts.FullName 'bin\Hostx64\x64'
            if (Test-Path $b) { $extra += $b }
        }
    }

    foreach ($pf in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if (-not $pf) { continue }
        $sdkRoot = Join-Path $pf 'Windows Kits\10\bin'
        if (-not (Test-Path $sdkRoot)) { continue }
        $sdk = Get-ChildItem $sdkRoot -Directory -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match '^\d+\.' -and (Test-Path (Join-Path $_.FullName 'x64\rc.exe')) } |
               Sort-Object Name -Descending | Select-Object -First 1
        if ($sdk) { $extra += (Join-Path $sdk.FullName 'x64'); break }
    }

    if ($extra.Count) { $env:Path = ($extra -join ';') + ';' + $env:Path }

    return [bool](Test-Tool 'cmake')
}

# Results accumulator. Each entry: @{ Name; Status } where Status is
# one of 'pass', 'fail', 'skip'.
$results = [System.Collections.Generic.List[object]]::new()

function Write-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host "==> $Text" -ForegroundColor Cyan
}

# Run one gate. $Action is a script block that invokes a native tool;
# success is judged by $LASTEXITCODE being 0. A non-zero exit, a thrown
# exception, or an explicit $false return all count as failure. Returns
# $true on pass so callers can gate dependent steps.
function Invoke-Gate {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-Header $Name
    $global:LASTEXITCODE = 0
    $ok = $true
    try {
        & $Action
        if ($LASTEXITCODE -ne 0) { $ok = $false }
    }
    catch {
        Write-Host $_.Exception.Message -ForegroundColor Red
        $ok = $false
    }
    if ($ok) {
        Write-Host "    [PASS] $Name" -ForegroundColor Green
        $results.Add([pscustomobject]@{ Name = $Name; Status = 'pass' })
    }
    else {
        Write-Host "    [FAIL] $Name" -ForegroundColor Red
        $results.Add([pscustomobject]@{ Name = $Name; Status = 'fail' })
    }
    return $ok
}

function Skip-Gate {
    param([Parameter(Mandatory)][string]$Name, [string]$Reason)
    Write-Header $Name
    Write-Host "    [SKIP] $Name — $Reason" -ForegroundColor DarkYellow
    $results.Add([pscustomobject]@{ Name = $Name; Status = 'skip' })
}

Push-Location $repoRoot
try {
    # ---- C library + tools (CMake / CTest) ---------------------------
    #
    # Uses the `release` preset, which sets CMAKE_BUILD_TYPE=Release with
    # OSDP_BUILD_TESTS=ON and OSDP_BUILD_TOOLS=ON — the same configuration
    # ci/build.yml builds. Each preset configures into build/release/.
    if ($SkipC) {
        Skip-Gate 'CMake stack' '-SkipC was passed'
    }
    elseif (-not (Initialize-VsToolchain)) {
        Skip-Gate 'CMake stack' 'cmake / Visual Studio toolchain not found — run from a Developer PowerShell for VS, install VS with the C++ workload, or pass -SkipC'
    }
    else {
        $configured = Invoke-Gate 'CMake configure (release preset)' {
            cmake --preset release
        }
        if ($configured) {
            $built = Invoke-Gate 'CMake build (release preset)' {
                cmake --build --preset release
            }
            if ($built) {
                Invoke-Gate 'CTest (release preset)' {
                    ctest --preset release
                } | Out-Null
            }
            else {
                Skip-Gate 'CTest (release preset)' 'build failed'
            }
        }
        else {
            Skip-Gate 'CMake build (release preset)' 'configure failed'
            Skip-Gate 'CTest (release preset)'        'configure failed'
        }
    }

    # ---- Rust workspace (cargo) --------------------------------------
    if ($SkipRust) {
        Skip-Gate 'Rust stack' '-SkipRust was passed'
    }
    elseif (-not (Test-Tool 'cargo')) {
        Skip-Gate 'Rust stack' "cargo not found (looked in $cargoBin) — install Rust via rustup, or pass -SkipRust"
    }
    else {
        if ($Fix) {
            Invoke-Gate 'cargo fmt (auto-fix)' {
                cargo fmt --manifest-path $rustToml --all
            } | Out-Null
        }
        else {
            Invoke-Gate 'cargo fmt --check' {
                cargo fmt --manifest-path $rustToml --all -- --check
            } | Out-Null
        }

        Invoke-Gate 'cargo clippy (warnings = errors)' {
            cargo clippy --manifest-path $rustToml --workspace --all-targets -- -D warnings
        } | Out-Null

        $rustBuilt = Invoke-Gate 'cargo build --workspace --release' {
            cargo build --manifest-path $rustToml --workspace --release
        }

        if ($rustBuilt) {
            Invoke-Gate 'cargo test --workspace --release' {
                cargo test --manifest-path $rustToml --workspace --release
            } | Out-Null

            # Loopback examples assert their own results, so a non-zero
            # exit means the API regressed.
            Invoke-Gate 'cargo run --example loopback' {
                cargo run --manifest-path $rustToml --release --example loopback
            } | Out-Null

            Invoke-Gate 'cargo run --example loopback_sc' {
                cargo run --manifest-path $rustToml --release --example loopback_sc
            } | Out-Null

            Invoke-Gate 'cargo run --example loopback_sc2' {
                cargo run --manifest-path $rustToml --release --example loopback_sc2
            } | Out-Null
        }
        else {
            Skip-Gate 'cargo test --workspace --release' 'build failed'
            Skip-Gate 'cargo run --example loopback'      'build failed'
            Skip-Gate 'cargo run --example loopback_sc'   'build failed'
            Skip-Gate 'cargo run --example loopback_sc2'  'build failed'
        }
    }
}
finally {
    Pop-Location
}

# ---- Summary ---------------------------------------------------------
Write-Host ''
Write-Host '==================== SUMMARY ====================' -ForegroundColor Cyan
foreach ($r in $results) {
    switch ($r.Status) {
        'pass' { Write-Host '  PASS  ' -ForegroundColor Green      -NoNewline }
        'fail' { Write-Host '  FAIL  ' -ForegroundColor Red        -NoNewline }
        'skip' { Write-Host '  SKIP  ' -ForegroundColor DarkYellow -NoNewline }
    }
    Write-Host $r.Name
}
Write-Host '================================================' -ForegroundColor Cyan

$failed  = @($results | Where-Object Status -eq 'fail').Count
$skipped = @($results | Where-Object Status -eq 'skip').Count
if ($failed -gt 0) {
    Write-Host ''
    Write-Host "$failed gate(s) failed — do not push." -ForegroundColor Red
    exit 1
}
if ($skipped -gt 0) {
    Write-Host ''
    Write-Host "All run gates passed, but $skipped were skipped." -ForegroundColor DarkYellow
    exit 0
}
Write-Host ''
Write-Host 'All gates passed — safe to push.' -ForegroundColor Green
exit 0
