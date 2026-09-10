//! Cross-module surface: ZK merkle-root signature verification for
//! `TributeFactory.offerTribute`.

use alloy_primitives::Address;
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381::primitives::{
    group::G1, ops::verify_message, variant::MinSig,
};
use outbe_primitives::error::Result;
use outbe_primitives::storage::StorageHandle;

use crate::errors::L2RegistryError;
use crate::runtime::decode_public_key;
use crate::schema::L2RegistryContract;

/// Domain-separation namespace for L2 signatures over `zkMerkleRoot`.
///
/// Must match the L2 committee's root-certificate signing namespace.
pub const ZK_MERKLE_ROOT_NAMESPACE: &[u8] = b"_PSO_CHAIN_COMMITMENT_ROOT";

/// Outcome of the offer-time ZK signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZkOfferCheck {
    /// The caller is not a registered L2 operator address; no check applies.
    NotRegistered,
    /// The caller's network is registered with ZK verification disabled.
    Disabled { chain_id: u64 },
    /// The signature over `zkMerkleRoot` verified against the network key.
    Verified { chain_id: u64 },
}

/// Verifies `signature` over `zk_merkle_root` for the network registered to
/// `l1_address`.
///
/// - Caller not registered as an L1 operator: [`ZkOfferCheck::NotRegistered`].
/// - Registered with `zk_enabled == false`: [`ZkOfferCheck::Disabled`].
/// - Registered with `zk_enabled == true`: `zk_merkle_root` must be 32 bytes
///   and `signature` must be a valid BLS MinSig G1 signature over it under
///   [`ZK_MERKLE_ROOT_NAMESPACE`]; any failure reverts.
pub fn check_zk_merkle_root_signature(
    storage: StorageHandle<'_>,
    l1_address: Address,
    zk_merkle_root: &[u8],
    signature: &[u8],
) -> Result<ZkOfferCheck> {
    let registry = L2RegistryContract::new(storage);
    let Some(record) = registry.network_by_l1_address(l1_address)? else {
        return Ok(ZkOfferCheck::NotRegistered);
    };
    let chain_id = record.chain_id;
    if !record.zk_enabled {
        return Ok(ZkOfferCheck::Disabled { chain_id });
    }
    if zk_merkle_root.len() != 32 {
        return Err(L2RegistryError::ZkMerkleRootRequired.into());
    }

    let pubkey = decode_public_key(&record.public_key_bytes())?;
    let sig = G1::decode(signature).map_err(|_| L2RegistryError::InvalidZkSignature)?;
    verify_message::<MinSig>(&pubkey, ZK_MERKLE_ROOT_NAMESPACE, zk_merkle_root, &sig)
        .map_err(|_| L2RegistryError::InvalidZkSignature)?;
    Ok(ZkOfferCheck::Verified { chain_id })
}
