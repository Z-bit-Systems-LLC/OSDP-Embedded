#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC
#
# provision-linux-agent.sh — provision a self-hosted Linux Azure DevOps
# agent (e.g. a Proxmox LXC) with everything the OSDP-Embedded
# `cross_arm64` job needs, so the pipeline runs with NO runtime
# apt/sudo/rustup (which hangs on a non-interactive agent).
#
# Installs: base build tools (cmake, ninja, gcc, pkg-config, ...), the
# aarch64 cross toolchain, arm64 multiarch + libudev-dev:arm64 (for
# osdp-mcp's serialport dep), and rustup stable + the
# aarch64-unknown-linux-gnu target; then exposes the rust proxies on the
# default PATH so the agent's non-login shell can find them.
#
# Works on Debian and Ubuntu. The two differ in how arm64 packages are
# served: Debian's normal mirrors carry every architecture, while Ubuntu
# splits them (amd64/i386 on archive.ubuntu.com, the rest on
# ports.ubuntu.com) and so needs an extra source + an amd64 pin.
#
# IMPORTANT: run this as the SAME user the agent runs its jobs as (rustup
# is per-user). If the agent service runs as root, run this as root; if it
# runs as e.g. `bytedreamer`, run it as that user (with sudo available).
#
#   ./scripts/provision-linux-agent.sh
#
# Idempotent and self-healing: safe to re-run, and it repairs apt sources
# left behind by an earlier run that guessed the distro wrong. After it
# succeeds, add the user capability `aarch64Toolchain` to the agent in
# Azure DevOps and restart the agent service (see the closing notes).

set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32m[ok]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---- sanity checks ---------------------------------------------------
command -v apt-get >/dev/null || die "This script targets Debian/Ubuntu (apt-get not found)."

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "Run as root, or install sudo."
  SUDO="sudo"
fi

distro_id=$(. /etc/os-release && echo "${ID:-}")
codename=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
log "Provisioning agent toolchain for user '$(id -un)' on ${distro_id:-unknown} ${codename:-?} (HOME=$HOME)"

# ---- 1. enable arm64 multiarch (distro-aware) -----------------------
log "Enabling arm64 multiarch"
$SUDO dpkg --add-architecture arm64

# Heal an earlier Ubuntu-assuming run: on Debian a ports.ubuntu.com
# source 404s and breaks apt entirely, and an amd64 pin would hide arm64.
if [ "$distro_id" != "ubuntu" ]; then
  $SUDO rm -f /etc/apt/sources.list.d/arm64-ports.list
  [ -f /etc/apt/sources.list ] && \
    $SUDO sed -i 's/^deb \[arch=amd64\] /deb /' /etc/apt/sources.list || true
fi

if [ "$distro_id" = "ubuntu" ]; then
  # Ubuntu serves non-amd64 from ports.ubuntu.com. Pin the default mirror
  # to amd64 (so apt doesn't 404 fetching arm64 from it) and add a ports
  # source for arm64.
  if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    grep -q '^Architectures:' /etc/apt/sources.list.d/ubuntu.sources \
      || $SUDO sed -i '/^Types: deb/a Architectures: amd64' \
           /etc/apt/sources.list.d/ubuntu.sources
  else
    $SUDO sed -i 's/^deb \(\[[^]]*\] \)\?/deb [arch=amd64] /' /etc/apt/sources.list
  fi
  $SUDO tee /etc/apt/sources.list.d/arm64-ports.list >/dev/null <<EOF
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename} main restricted universe multiverse
deb [arch=arm64] http://ports.ubuntu.com/ubuntu-ports/ ${codename}-updates main restricted universe multiverse
EOF
  ok "Ubuntu arm64 ports source configured"
else
  # Debian (and derivatives): the standard mirrors already carry every
  # release architecture, so enabling arm64 needs no extra source and no
  # amd64 pin.
  ok "Debian mirrors are multi-arch; no extra source needed"
fi

# ---- 2. install build tools, cross toolchain, arm64 libudev ---------
log "Installing build tools, the aarch64 cross toolchain, and libudev-dev:arm64"
$SUDO apt-get update
$SUDO apt-get install -y \
  build-essential cmake ninja-build git curl file pkg-config \
  gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
  libudev-dev:arm64
ok "system packages installed"

# ---- 3. rustup + stable + aarch64 target (for THIS user) ------------
log "Installing rustup (stable) and the aarch64 Rust target"
if ! command -v rustup >/dev/null 2>&1 && [ ! -x "$HOME/.cargo/bin/rustup" ]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
fi
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
rustup default stable
rustup target add aarch64-unknown-linux-gnu
ok "rust stable + aarch64-unknown-linux-gnu target installed"

# ---- 4. make cargo/rustc/rustup visible to the (non-login) agent -----
# Azure's Bash task runs non-interactive, non-login shells that don't
# source ~/.cargo/env, so expose the rustup proxies on the default PATH.
# The proxies resolve the toolchain from the *running* user's ~/.rustup,
# so this is only correct when the agent runs as the user provisioned
# above (hence the run-as-the-agent-user requirement at the top).
log "Linking rust proxies into /usr/local/bin (agent PATH)"
for bin in cargo rustc rustup; do
  $SUDO ln -sf "$HOME/.cargo/bin/$bin" "/usr/local/bin/$bin"
done
ok "cargo/rustc/rustup linked into /usr/local/bin"

# ---- 5. verify -------------------------------------------------------
log "Verifying the toolchain"
cmake --version | head -1
ninja --version >/dev/null && ok "ninja $(ninja --version)"
aarch64-linux-gnu-gcc --version | head -1
cargo --version
rustc --version
rustup target list --installed | grep -qx 'aarch64-unknown-linux-gnu' \
  && ok "aarch64-unknown-linux-gnu target present" \
  || die "aarch64 Rust target missing"
[ -f /usr/lib/aarch64-linux-gnu/pkgconfig/libudev.pc ] \
  && ok "arm64 libudev.pc present" \
  || die "arm64 libudev.pc missing (osdp-mcp cross-link will fail)"

cat <<'DONE'

==> Toolchain ready. Final steps in Azure DevOps:
    1. Agent pools -> Default -> <this agent> -> Capabilities ->
       User-defined: add   aarch64Toolchain = 1
    2. Restart the agent service so it re-advertises the capability and
       picks up the new /usr/local/bin PATH entries:
         sudo systemctl restart 'vsts.agent.*'   # systemd service install
       (or restart however your agent is run).
DONE
