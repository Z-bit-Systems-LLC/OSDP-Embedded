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
