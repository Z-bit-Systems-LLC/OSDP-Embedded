// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Build script for `osdp-embedded`.
//!
//! Compiles the C library (under `<repo>/{core,pd,acu}/src/`) into
//! one static archive that the Rust crate links against. Uses the
//! `cc` crate so cargo's normal target toolchain handles cross
//! compilation: `cargo build --target thumbv7em-none-eabihf` selects
//! the appropriate gcc/clang for that triple without us configuring
//! anything.
//!
//! The list of source files is intentionally explicit (no glob): if a
//! `.c` file is added to the C core, this list must be updated
//! manually. That coupling is fine - the source set is small and
//! changes infrequently - and avoids the well-known footgun where a
//! build-time glob silently picks up an unrelated file.
//!
//! `core/` sources always compile. `pd/src/*.c` and `acu/src/*.c` are
//! gated by the matching Cargo features; a PD-only firmware build
//! (`--no-default-features --features pd`) doesn't compile any ACU
//! object files at all.

use std::path::PathBuf;

fn main() {
    // Resolve the directory under which the C source tree lives.
    //
    // Two layouts to support:
    //
    //   * Dev / workspace build: the C tree lives at `<repo>/{core,
    //     pd, acu}/`, two levels up from this crate manifest. We're
    //     building from the live OSDP-Embedded repository, source
    //     files visible at their canonical paths.
    //
    //   * Published-crate build: someone fetched
    //     `osdp-embedded-X.Y.Z.crate` from crates.io and is compiling
    //     it as a dependency. The crate tarball can only contain
    //     files inside the crate directory, so we ship a copy of the
    //     C tree under `<crate>/vendor-c/{core,pd,acu}/`.
    //     `scripts/Stage-Crate.ps1` populates that directory before
    //     `cargo publish` runs.
    //
    // Probe a single representative header to choose between the two.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vendored = crate_dir.join("vendor-c");
    let probe = "core/include/osdp/osdp_types.h";

    let source_root = if vendored.join(probe).is_file() {
        // Vendored mode (crates.io consumer build).
        vendored
    } else {
        // Dev mode (workspace build from the source repo).
        let repo_root = crate_dir
            .parent() // rust/
            .and_then(|p| p.parent()) // <repo>/
            .expect("osdp-embedded crate must live under <repo>/rust/osdp/")
            .to_path_buf();
        assert!(
            repo_root.join(probe).is_file(),
            "build.rs: cannot locate the C source tree. Expected either \
             {} (vendored) or {} (dev). For a published-crate build, run \
             scripts/Stage-Crate.ps1 first.",
            crate_dir.join("vendor-c").join(probe).display(),
            repo_root.join(probe).display(),
        );
        repo_root
    };

    // ---- Source list -------------------------------------------------
    //
    // Always-compiled core: framing, codecs, dispatch, SC primitives.
    // PD and ACU state machines append based on the active features.
    let mut sources: Vec<&str> = vec![
        // core: shared (CRC, checksum, framing, streaming)
        "core/src/shared/checksum.c",
        "core/src/shared/crc16.c",
        "core/src/shared/frame.c",
        "core/src/shared/stream.c",
        "core/src/shared/led_state.c",
        "core/src/shared/buz_state.c",
        // core: per-message command codecs
        "core/src/commands/cmd_buz.c",
        "core/src/commands/cmd_cap.c",
        "core/src/commands/cmd_comset.c",
        "core/src/commands/cmd_filetransfer.c",
        "core/src/commands/cmd_id.c",
        "core/src/commands/cmd_keyset.c",
        "core/src/commands/cmd_led.c",
        "core/src/commands/cmd_out.c",
        "core/src/commands/cmd_poll.c",
        "core/src/commands/cmd_text.c",
        // core: per-message reply codecs
        "core/src/replies/reply_ack.c",
        "core/src/replies/reply_com.c",
        "core/src/replies/reply_ftstat.c",
        "core/src/replies/reply_keypad.c",
        "core/src/replies/reply_nak.c",
        "core/src/replies/reply_pdcap.c",
        "core/src/replies/reply_pdid.c",
        "core/src/replies/reply_raw.c",
        // core: optional dispatch helpers
        "core/src/dispatch/dispatch_classify.c",
        // core: secure-channel primitives
        "core/src/sc/cbc.c",
        "core/src/sc/keys.c",
        "core/src/sc/mac.c",
        "core/src/sc/payload.c",
        "core/src/sc/session.c",
        "core/src/sc/wrap.c",
        // core: secure-channel 2 primitives (AES-256-GCM / KMAC256)
        "core/src/sc2/keys.c",
        "core/src/sc2/crypto.c",
        "core/src/sc2/session.c",
        "core/src/sc2/wrap.c",
    ];

    // Cargo sets `CARGO_FEATURE_<NAME>` for every active feature.
    // Probe rather than `cfg!` so the build script reacts at run time
    // (it also runs from a different compile context than the crate).
    let pd_enabled = std::env::var_os("CARGO_FEATURE_PD").is_some();
    let acu_enabled = std::env::var_os("CARGO_FEATURE_ACU").is_some();

    if pd_enabled {
        sources.push("pd/src/pd.c");
        sources.push("pd/src/pd_sc.c");
        sources.push("pd/src/pd_sc2.c");
    }
    if acu_enabled {
        sources.push("acu/src/acu.c");
        sources.push("acu/src/acu_sc.c");
        sources.push("acu/src/acu_sc2.c");
    }

    let mut build = cc::Build::new();
    build
        .std("c11")
        // Public headers - every consumer #include is `<osdp/...>`.
        .include(source_root.join("core/include"))
        .include(source_root.join("pd/include"))
        .include(source_root.join("acu/include"))
        // Internal headers (pack.h, pd_internal.h, acu_internal.h) are
        // included unqualified by the .c files that need them; their
        // own directory has to be on the include path.
        .include(source_root.join("core/src"))
        .include(source_root.join("pd/src"))
        .include(source_root.join("acu/src"));

    // Quietly tighten warnings on hosted builds; embedded toolchains
    // sometimes don't accept these so we gate on a few common ones.
    if !build.get_compiler().is_like_msvc() {
        build.flag_if_supported("-Wall");
        build.flag_if_supported("-Wextra");
        build.flag_if_supported("-Wno-unused-parameter");
    }

    for src in &sources {
        let path = source_root.join(src);
        assert!(
            path.is_file(),
            "build.rs: missing C source file {}",
            path.display()
        );
        build.file(path);
    }

    build.compile("osdp_embedded");

    // Tell cargo to rerun build.rs whenever any of the C sources or
    // public headers change.
    for src in &sources {
        println!("cargo:rerun-if-changed={}", source_root.join(src).display());
    }
    for header_dir in &[
        "core/include/osdp",
        "pd/include/osdp",
        "acu/include/osdp",
        "core/src/shared",
        "pd/src",
        "acu/src",
    ] {
        println!(
            "cargo:rerun-if-changed={}",
            source_root.join(header_dir).display()
        );
    }
    println!("cargo:rerun-if-changed=build.rs");
}
