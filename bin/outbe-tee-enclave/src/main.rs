//! `outbe-tee-enclave` binary: framed-UDS + Noise-IK server for the Tribute PoC.
//!
//! Usage: `outbe-tee-enclave --socket <path|host:port> [--dkg-seed <hex32>]`
//!        `--tee-dir <dir> [--chain-id <hex32>]`
//!
//! Production requires `--tee-dir`: the persistent enclave identity and its one
//! node-signed `NodeHost` authorization are sealed there. `--chain-id` binds the
//! sealed values to this chain.
//!
//! The public production preamble exposes only initialization discovery,
//! one-time initialization, and authorized reconnect. It never serves the legacy
//! cleartext `GetQuote` behavior used by the separate dev/mock binary.
//!
//! This is the production entrypoint - a thin shim over [`outbe_tee_enclave::run`]
//! with [`RunOpts::prod`] (no mock code). The dev mock binary
//! (`outbe-tee-enclave-mock`, `--features mock`) is the sibling shim.

use outbe_tee_enclave::run::{run, RunOpts};

/// Heap accounting for `EnclaveRequest::Health` (EPC-pressure proxy).
/// Installed only in the binary roots so library users, tests and benches keep
/// the plain system allocator.
#[global_allocator]
static ALLOCATOR: outbe_tee_enclave::telemetry::CountingAllocator =
    outbe_tee_enclave::telemetry::CountingAllocator;

fn main() {
    std::process::exit(run(RunOpts::prod()));
}
