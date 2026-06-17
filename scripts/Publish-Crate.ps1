# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Publish a prebuilt osdp-embedded .crate to crates.io.
.DESCRIPTION
    The irreversible half of a release: upload the exact, already-verified
    `osdp-embedded-X.Y.Z.crate` that the build pipeline produced
    (ci/package.yml's `cargo package`, which both builds AND verifies it) to
    crates.io. Designed to be the single task a Classic Azure DevOps
    *Release* pipeline runs after its approval gate — so the run is recorded
    under the web admin's Releases section, while the publish logic stays
    version-controlled here rather than pasted into the UI.

    This consumes ARTIFACTS ONLY — it needs no source checkout. A Classic
    Release triggered by a build downloads that build's published artifacts
    (the .crate) but does NOT check out source, so a source-based
    `cargo publish` would have nothing to build. Instead we publish the
    prebuilt .crate, which has two benefits: the bytes that ship are
    byte-for-byte the bytes CI verified (no rebuild divergence), and the
    release stays a pure artifact consumer.

    Mechanics: `cargo publish` cannot upload a prebuilt .crate directly, so
    we extract it (a .crate is a gzipped tar of the full crate dir — Cargo.toml,
    src/, the vendored C sources under vendor-c/, README) and run
    `cargo publish --no-verify` from the extracted dir. cargo regenerates the
    upload + API metadata from that manifest; --no-verify skips a recompile
    the build already did (and which a publish agent may lack the C toolchain
    to run).

    Steps, in order:
      1. Locate the .crate (-CratePath, or the single osdp-embedded-*.crate
         found under -SearchRoot).
      2. Derive the version from its file name and, if -ExpectedVersion is
         given (e.g. the release tag), verify they match — so a misrouted
         artifact can't publish the wrong number.
      3. Extract into a temp dir; drop cargo's reserved bookkeeping files
         (Cargo.toml.orig, .cargo_vcs_info.json) so cargo regenerates them
         cleanly.
      4. cargo publish --no-verify from the extracted manifest.
      5. Remove the temp dir (always, even on failure).

    The crates.io token is read from the CARGO_REGISTRY_TOKEN environment
    variable — cargo's native mechanism. It is NEVER passed as a command-line
    argument (which would leak it into process listings / CI logs). In a
    Classic Release task, map the secret pipeline variable to that env var
    explicitly (secret vars are not auto-exposed to scripts):

        CARGO_REGISTRY_TOKEN = $(CratesIoToken)

    See docs/PUBLISHING.md for the full Release-pipeline setup.
.PARAMETER CratePath
    Path to the .crate to publish. If omitted, the script searches -SearchRoot
    recursively for a single `osdp-embedded-*.crate` and uses that.
.PARAMETER SearchRoot
    Where to look for the .crate when -CratePath is omitted. Defaults to the
    release agent's artifact root ($env:SYSTEM_DEFAULTWORKINGDIRECTORY) when
    set, else the repo root.
.PARAMETER ExpectedVersion
    If set, the .crate's version (parsed from its file name) must equal this,
    else the script aborts before publishing. Accepts a bare version (0.1.21)
    or a tag (v0.1.21). Wire it to the release tag — e.g. the linked build's
    Build.SourceBranchName — to guard against publishing a stale/misrouted
    artifact.
.PARAMETER DryRun
    Run `cargo publish --dry-run`: re-packages and checks crates.io for
    collisions/metadata WITHOUT uploading. Nothing is burned on the registry.
.PARAMETER Verify
    Run cargo publish WITHOUT --no-verify, forcing a standalone compile of the
    extracted crate before upload. Off by default — the build pipeline already
    verified this exact .crate, and the publish agent may lack the C toolchain.
    Set it only when publishing a .crate that wasn't CI-verified.
.EXAMPLE
    $env:CARGO_REGISTRY_TOKEN='...'; ./scripts/Publish-Crate.ps1 -CratePath ./osdp-embedded-0.1.21.crate -DryRun
    Local rehearsal against a downloaded artifact — no upload.
.EXAMPLE
    ./scripts/Publish-Crate.ps1 -ExpectedVersion v0.1.21
    The real publish, as the Release pipeline runs it: find the artifact,
    check it's v0.1.21, upload (token from env).
#>

[CmdletBinding()]
param(
    [string]$CratePath,
    [string]$SearchRoot,
    [string]$ExpectedVersion,
    [switch]$DryRun,
    [switch]$Verify
)

$ErrorActionPreference = 'Stop'

function Write-Info { param([string]$m) Write-Host $m -ForegroundColor Cyan }
function Write-Ok   { param([string]$m) Write-Host $m -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host $m -ForegroundColor Yellow }
function Write-Step { param([string]$m) Write-Host "`n==> $m" -ForegroundColor Magenta }

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$extractDir = $null

try {
    if ($DryRun) { Write-Warn '*** DRY RUN — cargo publish --dry-run, nothing will be uploaded ***' }

    # ---- 1. locate the .crate ----------------------------------------
    Write-Step 'Locating the .crate'
    if ($CratePath) {
        if (-not (Test-Path $CratePath)) { throw "No .crate at -CratePath: $CratePath" }
        $crate = Resolve-Path $CratePath
    }
    else {
        $root = if ($SearchRoot) { $SearchRoot }
                elseif ($env:SYSTEM_DEFAULTWORKINGDIRECTORY) { $env:SYSTEM_DEFAULTWORKINGDIRECTORY }
                else { $repoRoot }
        if (-not (Test-Path $root)) { throw "Search root does not exist: $root" }
        Write-Info "  searching under: $root"
        $found = @(Get-ChildItem -Path $root -Recurse -File -Filter 'osdp-embedded-*.crate')
        if ($found.Count -eq 0) {
            throw "No osdp-embedded-*.crate found under $root. Did the build artifact download?"
        }
        if ($found.Count -gt 1) {
            $list = ($found | ForEach-Object { "    $($_.FullName)" }) -join "`n"
            throw "Ambiguous: multiple .crate files found. Pass -CratePath.`n$list"
        }
        $crate = $found[0].FullName
    }
    Write-Ok "  crate: $crate"

    # ---- 2. derive + verify the version ------------------------------
    # cargo names the file `<pkg>-<version>.crate`; the package is
    # `osdp-embedded`, so whatever follows that prefix is the version
    # (incl. any SemVer pre-release suffix like 0.2.0-alpha.1).
    $crateName = Split-Path $crate -Leaf
    if ($crateName -notmatch '^osdp-embedded-(?<v>.+)\.crate$') {
        throw "Unexpected .crate file name (can't parse version): $crateName"
    }
    $version = $Matches['v']
    Write-Info "  version: $version"

    if ($ExpectedVersion) {
        # Tolerate a leading 'v' so the release tag (v0.1.21) passes through.
        $want = $ExpectedVersion.Trim() -replace '^v', ''
        if ($version -ne $want) {
            throw ("Version mismatch: artifact is '$version' but -ExpectedVersion " +
                   "resolved to '$want'. Refusing to publish — wrong or stale artifact.")
        }
        Write-Ok "  matches expected: $want"
    }

    # Fail early with a clear message rather than letting cargo emit a less
    # obvious error — but never echo the value.
    if (-not $DryRun -and -not $env:CARGO_REGISTRY_TOKEN) {
        throw ('CARGO_REGISTRY_TOKEN is not set. In the Release task map the ' +
               'secret pipeline variable to it: CARGO_REGISTRY_TOKEN = $(CratesIoToken).')
    }

    # ---- 3. extract --------------------------------------------------
    Write-Step 'Extracting the .crate'
    # System temp, so the extracted dir is never inside a git tree (cargo
    # would otherwise run dirty-checks against the surrounding repo).
    $extractDir = Join-Path ([IO.Path]::GetTempPath()) "osdp-publish-$version"
    if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
    New-Item -ItemType Directory -Path $extractDir | Out-Null

    # `tar` ships with Windows 10+ (bsdtar) and every Linux agent. A .crate
    # always extracts to exactly one top-level dir (`<pkg>-<version>/`);
    # discover it rather than assuming the name.
    & tar -xzf $crate -C $extractDir
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed (exit $LASTEXITCODE)." }

    $dirs = @(Get-ChildItem -Path $extractDir -Directory)
    if ($dirs.Count -ne 1) {
        throw "Expected exactly one top-level dir in the extracted .crate, found $($dirs.Count)."
    }
    $crateDir = $dirs[0].FullName
    $manifest = Join-Path $crateDir 'Cargo.toml'
    if (-not (Test-Path $manifest)) {
        throw "Extracted crate has no Cargo.toml at: $manifest"
    }

    # Drop cargo's reserved bookkeeping files so re-packaging regenerates
    # them instead of erroring on the reserved names.
    foreach ($reserved in @('Cargo.toml.orig', '.cargo_vcs_info.json')) {
        $p = Join-Path $crateDir $reserved
        if (Test-Path $p) { Remove-Item -Force $p }
    }
    Write-Ok "  extracted to: $crateDir"

    # ---- 4. publish --------------------------------------------------
    Write-Step ($DryRun ? 'cargo publish --dry-run' : 'cargo publish (uploading to crates.io)')
    $cargoArgs = @('publish', '--manifest-path', $manifest)
    if (-not $Verify) { $cargoArgs += '--no-verify' }
    if ($DryRun)      { $cargoArgs += '--dry-run' }

    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) { throw "cargo publish failed (exit $LASTEXITCODE)." }

    Write-Host ''
    if ($DryRun) {
        Write-Ok "Dry run complete — osdp-embedded $version would publish cleanly."
    }
    else {
        Write-Ok "Published osdp-embedded $version to crates.io."
        Write-Info '  This version number is now permanent (yank is possible; reuse is not).'
    }
}
finally {
    # ---- 5. always remove the temp extraction ------------------------
    if ($extractDir -and (Test-Path $extractDir)) {
        Remove-Item -Recurse -Force $extractDir
    }
}
