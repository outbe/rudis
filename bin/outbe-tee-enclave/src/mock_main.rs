//! `outbe-tee-enclave-mock` - dev/CI mock enclave binary.
//!
//! Built ONLY with `--features mock` (enforced by `required-features` in
//! `Cargo.toml`), so the production `outbe-tee-enclave` binary links none of the
//! mock key material. It runs the SAME code path as production - the node talks
//! to it over the same Noise-IK channel, a single path - differing only in:
//!   - a stable EGETKEY-equivalent sealing key (the `mock` feature; lets the
//!     sealed restart fast-path be exercised under gramine-direct, where real
//!     `EGETKEY` is unavailable), and
//!   - a loud "MOCK ENCLAVE - NOT CONFIDENTIAL" startup banner ([`RunOpts::mock`]).
//!
//! There is no fabricated SGX quote: it runs unattested (empty quote), accepted
//! by the host's development transport. Use for localnet/CI
//! without SGX hardware; never in production.

use outbe_tee_enclave::run::{run, RunOpts};

/// Same heap accounting as the production binary so mock-lane e2e observes the
/// identical `Health` surface.
#[global_allocator]
static ALLOCATOR: outbe_tee_enclave::telemetry::CountingAllocator =
    outbe_tee_enclave::telemetry::CountingAllocator;

fn main() {
    std::process::exit(run(RunOpts::mock()));
}
