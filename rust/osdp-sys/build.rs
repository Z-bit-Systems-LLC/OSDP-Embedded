// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! Build script for `osdp-sys`.
//!
//! Compiles every `.c` file under the C core (`core/src`, `pd/src`,
//! `acu/src`) into a single static archive that the Rust crate links
//! against. Uses the `cc` crate so cargo's normal target toolchain
//! handles cross-compilation: `cargo build --target
//! thumbv7em-none-eabihf` selects the appropriate gcc/clang for that
//! triple without us configuring anything.
//!
//! The list of source files is intentionally explicit (no glob): if a
//! `.c` file is added to the C core, this list must be updated
//! manually. That coupling is fine — the source set is small and
//! changes infrequently — and avoids the well-known footgun where a
//! build-time glob silently picks up an unrelated file.
//!
//! The `osdp-sys` and `osdp` crates carry no internal logic of their
//! own; everything goes through this archive.

use std::path::PathBuf;

fn main() {
    // Resolve the workspace root from the crate manifest. The crate
    // lives at `<repo>/rust/osdp-sys/`, so two levels up is the repo
    // root.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = crate_dir
        .parent() // rust/
        .and_then(|p| p.parent()) // <repo>/
        .expect("osdp-sys crate must live under <repo>/rust/osdp-sys/");

    // ---- Source list ------------------------------------------------
    //
    // Mirrors the file set listed in core/CMakeLists.txt etc. The
    // ordering is alphabetical inside each role so diffs stay clean
    // when files are added.
    let sources: &[&str] = &[
        // core: shared (CRC, checksum, framing, streaming)
        "core/src/shared/checksum.c",
        "core/src/shared/crc16.c",
        "core/src/shared/frame.c",
        "core/src/shared/stream.c",
        // core: per-message command codecs
        "core/src/commands/cmd_buz.c",
        "core/src/commands/cmd_cap.c",
        "core/src/commands/cmd_comset.c",
        "core/src/commands/cmd_id.c",
        "core/src/commands/cmd_led.c",
        "core/src/commands/cmd_out.c",
        "core/src/commands/cmd_poll.c",
        "core/src/commands/cmd_text.c",
        // core: per-message reply codecs
        "core/src/replies/reply_ack.c",
        "core/src/replies/reply_com.c",
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
        // pd: state machine + SC handshake
        "pd/src/pd.c",
        "pd/src/pd_sc.c",
        // acu: state machine + SC handshake
        "acu/src/acu.c",
        "acu/src/acu_sc.c",
    ];

    let mut build = cc::Build::new();
    build
        .std("c11")
        // Public headers — every consumer #include is `<osdp/...>`.
        .include(repo_root.join("core/include"))
        .include(repo_root.join("pd/include"))
        .include(repo_root.join("acu/include"))
        // Internal headers (pack.h, pd_internal.h, acu_internal.h) are
        // included unqualified by the .c files that need them; their
        // own directory has to be on the include path.
        .include(repo_root.join("core/src"))
        .include(repo_root.join("pd/src"))
        .include(repo_root.join("acu/src"));

    // Quietly tighten warnings on hosted builds; embedded toolchains
    // sometimes don't accept these so we gate on a few common ones.
    if !build.get_compiler().is_like_msvc() {
        build.flag_if_supported("-Wall");
        build.flag_if_supported("-Wextra");
        build.flag_if_supported("-Wno-unused-parameter");
    }

    for src in sources {
        let path = repo_root.join(src);
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
    for src in sources {
        println!("cargo:rerun-if-changed={}", repo_root.join(src).display());
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
            repo_root.join(header_dir).display()
        );
    }
    // If the build script itself changes, rebuild.
    println!("cargo:rerun-if-changed=build.rs");
}
