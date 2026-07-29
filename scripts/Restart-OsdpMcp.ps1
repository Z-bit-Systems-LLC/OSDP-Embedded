# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Rebuild osdp-mcp and relaunch it standalone (no MCP client) for live
    testing against a real ACU.
.DESCRIPTION
    Every standalone osdp-mcp.exe left running from an earlier session
    holds the binary file locked, so a plain `cargo build` fails with
    "Access is denied" trying to replace it — this script always stops
    existing instances first, so that never happens.

    Steps:
      1. Stop every running osdp-mcp.exe.
      2. `cargo build -p osdp-mcp` (add -Release for an optimized build).
      3. Launch it standalone with --transport http --ui-bind, using the
         OSDP_MCP_* env vars to auto-start a PD on the given port/baud/
         address/SC mode.
      4. Poll the reader-visual UI's /api/state until it responds (or the
         timeout elapses) and print the PD's connection status.

    Logs go to $env:TEMP\osdp-mcp-stdout.log / -stderr.log — tail those
    for anything beyond the one-line status this script prints.
.PARAMETER Port
    Serial port the PD listens on, e.g. "COM7".
.PARAMETER Baud
    Line rate; must match the ACU. Default 38400.
.PARAMETER Address
    7-bit PD address (0x00..0x7E). Default 0.
.PARAMETER ScMode
    "none", "install" (SCBK-D), or "scbk" (pass -Scbk with a 32-hex-char key).
    Default "install".
.PARAMETER Scbk
    32 hex chars (16 bytes) — the operational SCBK. Only used when
    -ScMode scbk.
.PARAMETER Bind
    MCP HTTP transport bind address. Default 127.0.0.1:8080. The MCP
    endpoint itself (/mcp) is not meant to be used in this standalone
    mode — only the reader-visual UI is.
.PARAMETER UiBind
    Reader-visual UI bind address. Default 127.0.0.1:8088.
.PARAMETER Release
    Build --release instead of the default debug build.
.EXAMPLE
    ./scripts/Restart-OsdpMcp.ps1
    Stop any running instance, rebuild, and relaunch on COM7 @ 38400,
    address 0, SC install mode — the usual live-test posture.
.EXAMPLE
    ./scripts/Restart-OsdpMcp.ps1 -Port COM5 -Baud 9600 -ScMode none
    Relaunch on a different port/baud, clear text.
#>

[CmdletBinding()]
param(
    [string]$Port = "COM7",
    [uint32]$Baud = 38400,
    [byte]$Address = 0,
    [ValidateSet("none", "install", "scbk")]
    [string]$ScMode = "install",
    [string]$Scbk,
    [string]$Bind = "127.0.0.1:8080",
    [string]$UiBind = "127.0.0.1:8088",
    [switch]$Release
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

Write-Host "==> Stopping any running osdp-mcp.exe"
$existing = Get-Process osdp-mcp -ErrorAction SilentlyContinue
if ($existing) {
    $existing | Stop-Process -Force -Confirm:$false
    Start-Sleep -Milliseconds 500
    Write-Host "    stopped $($existing.Count) instance(s)"
} else {
    Write-Host "    none running"
}

Write-Host "==> Building osdp-mcp$(if ($Release) { ' (release)' })"
$cargoArgs = @('build', '--manifest-path', (Join-Path $repoRoot 'rust\Cargo.toml'), '-p', 'osdp-mcp')
if ($Release) { $cargoArgs += '--release' }
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "cargo build failed (exit $LASTEXITCODE)"
    exit $LASTEXITCODE
}

$profile = if ($Release) { 'release' } else { 'debug' }
$exe = Join-Path $repoRoot "rust\target\$profile\osdp-mcp.exe"
if (-not (Test-Path $exe)) {
    Write-Error "built binary not found at $exe"
    exit 1
}

$env:OSDP_MCP_PORT = $Port
$env:OSDP_MCP_BAUD = "$Baud"
$env:OSDP_MCP_ADDRESS = "$Address"
$env:OSDP_MCP_SC_MODE = $ScMode
if ($ScMode -eq 'scbk') {
    if (-not $Scbk) {
        Write-Error "-ScMode scbk requires -Scbk <32 hex chars>"
        exit 1
    }
    $env:OSDP_MCP_SCBK_HEX = $Scbk
} else {
    Remove-Item Env:\OSDP_MCP_SCBK_HEX -ErrorAction SilentlyContinue
}

$stdout = Join-Path $env:TEMP 'osdp-mcp-stdout.log'
$stderr = Join-Path $env:TEMP 'osdp-mcp-stderr.log'

Write-Host "==> Launching: port=$Port baud=$Baud address=0x$('{0:X2}' -f $Address) sc=$ScMode ui=$UiBind"
$proc = Start-Process -FilePath $exe `
    -ArgumentList '--transport', 'http', '--bind', $Bind, '--ui-bind', $UiBind `
    -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
    -WindowStyle Hidden -PassThru

Write-Host "    PID $($proc.Id) — logs: $stdout / $stderr"

Write-Host "==> Waiting for the reader UI to come up"
$uiUrl = "http://$UiBind/api/state"
$deadline = (Get-Date).AddSeconds(10)
$state = $null
while ((Get-Date) -lt $deadline) {
    try {
        $state = Invoke-WebRequest -Uri $uiUrl -UseBasicParsing -TimeoutSec 2
        break
    } catch {
        Start-Sleep -Milliseconds 300
    }
}

if ($null -eq $state) {
    Write-Warning "UI did not respond within 10s — check $stderr"
    Get-Content $stderr -ErrorAction SilentlyContinue | Select-Object -Last 20
    exit 1
}

Write-Host "==> PD is live: $($state.Content)"
Write-Host "==> Reader UI:  http://$UiBind/"
