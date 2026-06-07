// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Build script for osdp-mcp.
//!
//! Currently a no-op unless the `crypto-tiny-aes` feature is active,
//! in which case it compiles `vendor/tiny-aes/aes.c` and exports
//! `AES_ECB_encrypt` / `AES_ECB_decrypt` for the FFI in
//! `src/crypto/tiny_aes.rs`.
//!
//! tiny-AES-c is Unlicense / public domain (`vendor/tiny-aes/unlicense.txt`);
//! we vendor it here for parity with the existing `osdp-pd-mock` CLI
//! tool's crypto path.

fn main() {
    // Re-run only when the feature toggles or the C source changes.
    println!("cargo:rerun-if-changed=build.rs");

    emit_git_version();

    #[cfg(feature = "crypto-tiny-aes")]
    {
        let vendor_dir = std::path::Path::new("..")
            .join("..")
            .join("vendor")
            .join("tiny-aes");
        let aes_c = vendor_dir.join("aes.c");
        if !aes_c.exists() {
            panic!(
                "tiny-AES-c source not found at {} — vendor/tiny-aes/ is required \
                 for the `crypto-tiny-aes` feature.",
                aes_c.display()
            );
        }
        println!("cargo:rerun-if-changed={}", aes_c.display());

        let mut build = cc::Build::new();
        build
            .file(&aes_c)
            // Force ECB-only build; CBC/CTR are also in aes.c but
            // their tables / functions bloat the .text section.
            .define("AES128", "1")
            .define("ECB", "1")
            .define("CBC", "0")
            .define("CTR", "0")
            .include(&vendor_dir);
        build.compile("tiny_aes");
    }
}

/// Stamp the running binary with the git commit it was built from.
///
/// Exposes `OSDP_MCP_GIT_HASH` (short commit) and `OSDP_MCP_GIT_DIRTY`
/// ("true"/"false") to the crate via `option_env!`, so the `version`
/// MCP tool can report exactly which source a deployed binary came
/// from — the question that turned a one-line checksum fix into an
/// online/offline debugging session when a stale binary was running.
///
/// Best-effort: if git or the repo isn't available (release tarball,
/// vendored source) both fall back gracefully and the build still
/// succeeds. Paths are relative to this crate dir (`tools/osdp-mcp`);
/// the repo root is two levels up.
fn emit_git_version() {
    use std::process::Command;

    let git = |args: &[&str]| -> Option<String> {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    };

    let hash = git(&["rev-parse", "--short=12", "HEAD"])
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    // Any tracked-or-untracked change in the working tree counts as dirty.
    let dirty = git(&["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    println!("cargo:rustc-env=OSDP_MCP_GIT_HASH={hash}");
    println!("cargo:rustc-env=OSDP_MCP_GIT_DIRTY={dirty}");

    // Re-stamp when HEAD moves. Watch HEAD itself plus, when HEAD is a
    // symbolic ref, the branch ref it resolves to (so commits on the
    // current branch retrigger, not just checkouts).
    let head = "../../.git/HEAD";
    if std::path::Path::new(head).exists() {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Ok(contents) = std::fs::read_to_string(head) {
        if let Some(reference) = contents.strip_prefix("ref:").map(str::trim) {
            let ref_path = format!("../../.git/{reference}");
            if std::path::Path::new(&ref_path).exists() {
                println!("cargo:rerun-if-changed={ref_path}");
            }
        }
    }
    // Covers commits that only live in packed-refs (e.g. after gc).
    let packed = "../../.git/packed-refs";
    if std::path::Path::new(packed).exists() {
        println!("cargo:rerun-if-changed={packed}");
    }
}
