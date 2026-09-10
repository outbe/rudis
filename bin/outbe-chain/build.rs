//! Build script that bakes Outbe-side build metadata into the
//! `outbe-chain --version` output.
//!
//! Mirrors reth-node-core's build script (which kona-node and others
//! copy) so operators see a familiar block format. Uses `vergen-git2` to
//! pull commit/SHA/dirty/describe and `vergen` for build timestamp,
//! cargo features and target triple. No runtime dependency is added -
//! everything is collected at build time and exposed via
//! `cargo:rustc-env`.
//!
//! Exported `cargo:rustc-env` variables, consumed by `main.rs`:
//!
//! - `OUTBE_SHORT_VERSION`     `<pkg-version><-dev?> (<sha8>)`
//! - `OUTBE_LONG_VERSION_<0..>` five-line block: Version / Commit SHA /
//!   Build Timestamp / Build Features / Build Profile.
//!
//! Build profile (`debug` / `release` / custom like `maxperf`) is taken
//! from `OUT_DIR` rather than `PROFILE` because Cargo collapses any
//! non-`release` custom profile into `release` for `PROFILE` while
//! preserving the actual profile name in the output path.
#![allow(missing_docs)]

use std::{env, error::Error};
use vergen::{BuildBuilder, CargoBuilder, Emitter};
use vergen_git2::Git2Builder;

fn main() -> Result<(), Box<dyn Error>> {
    let mut emitter = Emitter::default();

    emitter.add_instructions(&BuildBuilder::default().build_timestamp(true).build()?)?;
    emitter.add_instructions(
        &CargoBuilder::default()
            .features(true)
            .target_triple(true)
            .build()?,
    )?;
    emitter.add_instructions(
        &Git2Builder::default()
            .describe(false, true, None)
            .dirty(true)
            .sha(false)
            .build()?,
    )?;

    emitter.emit_and_set()?;

    let sha = env::var("VERGEN_GIT_SHA")?;
    let sha_short = &sha[..8.min(sha.len())];
    let is_dirty = env::var("VERGEN_GIT_DIRTY")? == "true";
    // `git describe --tags --always` ends in `-g<short-sha>` when HEAD is
    // not exactly on a tag. We use that to flip the `-dev` suffix on.
    let describe = env::var("VERGEN_GIT_DESCRIBE")?;
    let not_on_tag = describe.ends_with(&format!("-g{sha_short}"));
    let version_suffix = if is_dirty || not_on_tag { "-dev" } else { "" };

    // Cargo collapses custom release-like profiles back to "release" in the
    // `PROFILE` env var. The third-from-last `OUT_DIR` segment preserves the
    // real profile name (e.g. "maxperf"), which matches the convention used
    // by reth-node-core and kona-node.
    let out_dir = env::var("OUT_DIR")?;
    let profile = out_dir
        .rsplit(std::path::MAIN_SEPARATOR)
        .nth(3)
        .unwrap_or("unknown");

    println!("cargo:rustc-env=OUTBE_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=OUTBE_GIT_SHA_SHORT={sha_short}");

    let pkg_version = env!("CARGO_PKG_VERSION");
    println!("cargo:rustc-env=OUTBE_SHORT_VERSION={pkg_version}{version_suffix} ({sha_short})");

    let features = env::var("VERGEN_CARGO_FEATURES").unwrap_or_default();
    let features_str = if features.is_empty() {
        "no features enabled".to_string()
    } else {
        features
    };

    println!("cargo:rustc-env=OUTBE_LONG_VERSION_0=Version: {pkg_version}{version_suffix}");
    println!("cargo:rustc-env=OUTBE_LONG_VERSION_1=Commit SHA: {sha}");
    println!(
        "cargo:rustc-env=OUTBE_LONG_VERSION_2=Build Timestamp: {}",
        env::var("VERGEN_BUILD_TIMESTAMP")?
    );
    println!("cargo:rustc-env=OUTBE_LONG_VERSION_3=Build Features: {features_str}");
    println!(
        "cargo:rustc-env=OUTBE_LONG_VERSION_4=Build Profile: {profile} ({})",
        env::var("VERGEN_CARGO_TARGET_TRIPLE")?
    );

    Ok(())
}
