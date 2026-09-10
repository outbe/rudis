//! Chain-owned Poseidon and canonical ZK verifier precompiles.

use alloy_primitives::{Address, Bytes, U256};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use outbe_poseidon::{Poseidon, PoseidonHasher};
use outbe_primitives::dispatch::reject_value;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_protocol::protocol::zkproof::decode_verify_call;
use outbe_zk_backend::barretenberg::{Barretenberg, RawVerifier};
use tracing::trace;

pub use outbe_primitives::storage::gas::ZK_VERIFY_GAS;

pub(crate) const MAX_INPUTS: usize = 12;
pub(crate) const POSEIDON_GAS_BASE: u64 = 1_500;
pub(crate) const POSEIDON_GAS_PER_INPUT: u64 = 500;

/// Selectors on the Poseidon precompile (`0xEE07`) that accept native value.
pub const POSEIDON_PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// Selectors on the UltraHonkKeccak verifier precompile (`0xEE08`) that accept
/// native value.
pub const GROTH16_PAYABLE_SELECTORS: &[[u8; 4]] = &[];

/// Compute Poseidon-BN254 over 1 to 12 packed big-endian field words.
pub fn poseidon_hash(input: &[u8]) -> Result<[u8; 32]> {
    if input.is_empty() {
        return Err(PrecompileError::Revert("poseidon: empty input".into()));
    }
    if !input.len().is_multiple_of(32) {
        return Err(PrecompileError::Revert(format!(
            "poseidon: input length {} is not a multiple of 32",
            input.len()
        )));
    }
    let n = input.len() / 32;
    if n > MAX_INPUTS {
        return Err(PrecompileError::Revert(format!(
            "poseidon: {n} inputs exceeds maximum supported ({MAX_INPUTS})"
        )));
    }

    let inputs: Vec<Fr> = input.chunks(32).map(Fr::from_be_bytes_mod_order).collect();
    let mut poseidon = Poseidon::<Fr>::new_circom(n).map_err(|error| {
        PrecompileError::Revert(format!("poseidon: parameter setup failed: {error}"))
    })?;
    let hash = poseidon
        .hash(&inputs)
        .map_err(|error| PrecompileError::Revert(format!("poseidon: hash failed: {error}")))?;

    let bytes = hash.into_bigint().to_bytes_be();
    let mut output = [0u8; 32];
    output[32 - bytes.len()..].copy_from_slice(&bytes);
    trace!(n_inputs = n, "poseidon precompile");
    Ok(output)
}

/// Dispatch the Poseidon-BN254 hash precompile (`0xEE07`).
pub fn dispatch_poseidon(
    _storage: StorageHandle,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    Ok(Bytes::copy_from_slice(&poseidon_hash(data)?))
}

/// Dispatch the UltraHonkKeccak verifier precompile (`0xEE08`).
pub fn dispatch_groth16(
    _storage: StorageHandle,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    Ok(Bytes::copy_from_slice(&zk_verify(data)?))
}

/// Base gas charged before [`dispatch_poseidon`].
pub fn poseidon_base_gas(input: &[u8]) -> u64 {
    POSEIDON_GAS_BASE + POSEIDON_GAS_PER_INPUT * (input.len() / 32) as u64
}

/// Base gas charged before [`dispatch_groth16`].
pub fn groth16_base_gas(_input: &[u8]) -> u64 {
    ZK_VERIFY_GAS
}

pub(crate) fn zk_verify(input: &[u8]) -> Result<[u8; 32]> {
    let call =
        decode_verify_call(input).map_err(|error| PrecompileError::Revert(error.to_string()))?;
    let Some(descriptor) = outbe_zk_canonical::noir::CIRCUIT_REGISTRY
        .iter()
        .find(|descriptor| descriptor.circuit_hash == call.circuit_hash)
    else {
        trace!(circuit_hash = ?call.circuit_hash, "zk_verify: unknown circuit_hash");
        return Ok([0u8; 32]);
    };

    let verified = Barretenberg::default()
        .verify_combined(descriptor.vk_bytes, call.combined_proof)
        .map_err(|error| {
            PrecompileError::Revert(format!("zk verification backend failed: {error}"))
        })?;
    trace!(circuit = descriptor.label, verified, "zk_verify");

    let mut output = [0u8; 32];
    output[31] = u8::from(verified);
    Ok(output)
}
