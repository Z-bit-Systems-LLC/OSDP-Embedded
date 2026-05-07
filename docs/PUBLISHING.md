# Publishing `osdp-embedded` to crates.io

This is the manual recipe a Z-bit Systems maintainer follows to ship a
new release of the `osdp-embedded` Rust crate. The Azure Pipelines
build produces an `osdp-embedded-X.Y.Z.crate` artifact on every tagged
build (see `ci/package.yml`); the actual `cargo publish` step is kept
manual so a human reviews each release before it lands on a public
registry.

## One-time setup

The first time you publish, you need a crates.io account and a token
on the build machine.

1. Create an account at <https://crates.io>. The OSDP-Embedded crate
   is owned by Z-bit Systems; the publishing account must either be
   in the `osdp-embedded` crate's owner list (run
   `cargo owner --add github:Z-bit-Systems-LLC:owners osdp-embedded`
   on first publish to add the team) or be the original publisher.
2. Generate an API token at <https://crates.io/me> with `publish-new`
   and `publish-update` scopes.
3. Save it locally:
   ```pwsh
   cargo login                # then paste the token at the prompt
   ```
   Tokens land in `%USERPROFILE%\.cargo\credentials.toml` and are
   gitignored automatically. Don't share or check in this file.

## Per-release recipe

Every release follows the same five steps. Pre-release builds (alpha,
beta, rc) work the same way; cargo accepts SemVer pre-release suffixes
(`0.1.0-alpha.2`).

### 1. Bump the version

Use the helper script — it updates both `rust/Cargo.toml`
(`[workspace.package].version`) and `CMakeLists.txt`
(`project(... VERSION ...)`) in lockstep:

```pwsh
./scripts/Set-Version.ps1 -Version 0.1.0-alpha.2 -DryRun   # preview
./scripts/Set-Version.ps1 -Version 0.1.0-alpha.2           # apply
```

### 2. Verify locally

Run the same gates Azure Pipelines runs:

```pwsh
# C side
cmake -S . -B build && cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure

# Rust side
cargo fmt --manifest-path rust/Cargo.toml --all -- --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets -- -D warnings
cargo test --manifest-path rust/Cargo.toml --workspace --release
cargo run --manifest-path rust/Cargo.toml --release --example loopback
cargo run --manifest-path rust/Cargo.toml --release --example loopback_sc
```

Also build with each non-default feature combo to make sure the
feature-gated cfgs are still consistent:

```pwsh
foreach ($combo in @("", "--features pd", "--features acu", "--features pd,acu")) {
    cargo build --manifest-path rust/Cargo.toml -p osdp-embedded `
        --no-default-features $combo
}
```

### 3. Stage the C source tree + README into the crate dir

The `osdp-embedded` crate's `build.rs` references `<repo>/{core,pd,acu}/`
during in-workspace dev builds, but `cargo publish` only packages files
inside the crate directory. The stage script handles both the C
source mirror and the README that crates.io renders on the package
page:

```pwsh
./scripts/Stage-Crate.ps1
```

This copies:
- `<repo>/{core,pd,acu}/**/*.{c,h}` → `rust/osdp/vendor-c/...`
- `<repo>/README.md` → `rust/osdp/README.md`

Both destinations are gitignored — they only exist during the publish
window. `Stage-Crate.ps1 -Clean` removes them.

### 4. Run `cargo package` + dry-run publish

`cargo package` builds the staged tarball *and* compiles it
standalone, exercising the same path crates.io users will hit:

```pwsh
cargo package --manifest-path rust/osdp/Cargo.toml `
    --target-dir rust/target/package --allow-dirty
```

The output ends with `Verifying osdp-embedded v…` followed by a clean
build of the staged crate. If that step fails, the published crate
would also fail — debug it locally before continuing.

Then a registry dry-run, which checks crates.io for name collisions,
license metadata, etc., without actually uploading:

```pwsh
cargo publish --manifest-path rust/osdp/Cargo.toml --dry-run --allow-dirty
```

**Why `--allow-dirty`?** The staged `rust/osdp/vendor-c/` directory
is gitignored (it's a transient mirror, not source-of-truth), so
cargo sees those files as uncommitted changes and refuses to publish
without an explicit override. They're byte-for-byte copies of the
committed `core/`, `pd/`, `acu/` tree at the current HEAD, so the
published `.crate` still represents a deterministic snapshot of the
git state — the override is correct here.

### 5. Tag, publish, push

```pwsh
git add rust/Cargo.toml CMakeLists.txt
git commit -m "Bump version to 0.1.0-alpha.2"
git tag v0.1.0-alpha.2
git push origin main
git push origin v0.1.0-alpha.2          # triggers ci/package.yml

# Actual publish (irreversible — the version number is burned forever
# on crates.io even if you `cargo yank` it):
cargo publish --manifest-path rust/osdp/Cargo.toml --allow-dirty
```

### 6. Clean up

```pwsh
./scripts/Stage-Crate.ps1 -Clean
```

## After the first stable (`0.1.0`) release

A few things change once we drop the pre-release suffix:

- `Cargo.toml` description should mention production-readiness.
- Consider adding a `[badges]` section pointing at the CI build
  status.
- Bump rust-version if we start using newer language features.

## Yanking a bad release

If a published version turns out broken, `cargo yank` removes it from
the resolver's default search but doesn't delete it (nor free up the
version number for re-use):

```pwsh
cargo yank --manifest-path rust/osdp/Cargo.toml --version 0.1.0-alpha.2
```

A yanked version can still be installed by exact-version pin
(`= 0.1.0-alpha.2`), but it won't be picked up by SemVer-range
resolution. Always cut a `+1`-patch fix and publish that — never
re-publish the same version with different bytes.
