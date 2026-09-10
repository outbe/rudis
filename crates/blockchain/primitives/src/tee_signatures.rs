//! Shared recoverable secp256k1 signature verification for TEE protocols.

use alloy_primitives::{keccak256, Address, B256};
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey};

use crate::error::{PrecompileError, Result};

fn revert(message: String) -> PrecompileError {
    PrecompileError::Revert(message)
}

/// Recover the compressed public key that produced a recoverable secp256k1
/// signature (`r(32) || s(32) || v(1)`) over `prehash`.
///
/// `v` accepts the raw recovery id (`0`/`1`) and the EIP-155-free legacy form
/// (`27`/`28`).
pub fn recover_signer_public_key(prehash: &B256, signature: &[u8; 65]) -> Result<[u8; 33]> {
    let recid_byte = signature[64];
    let normalized = match recid_byte {
        27 | 28 => recid_byte - 27,
        other => other,
    };
    let recovery_id = RecoveryId::from_byte(normalized).ok_or_else(|| {
        revert(format!(
            "recoverable signature has invalid recovery id {recid_byte}"
        ))
    })?;
    let ecdsa_sig = EcdsaSignature::from_slice(&signature[..64])
        .map_err(|error| revert(format!("recoverable signature is malformed: {error}")))?;
    let verifying_key =
        VerifyingKey::recover_from_prehash(prehash.as_slice(), &ecdsa_sig, recovery_id)
            .map_err(|error| revert(format!("signature recovery failed: {error}")))?;
    let encoded = verifying_key.to_encoded_point(true);
    encoded
        .as_bytes()
        .try_into()
        .map_err(|_| revert("recovered compressed public key is not 33 bytes".to_string()))
}

/// Recover the EVM address that produced a recoverable secp256k1 signature.
pub fn recover_signer(prehash: &B256, signature: &[u8; 65]) -> Result<Address> {
    let compressed = recover_signer_public_key(prehash, signature)?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&compressed)
        .map_err(|error| revert(format!("recovered key decode failed: {error}")))?;
    let encoded = verifying_key.to_encoded_point(false);
    let digest = keccak256(&encoded.as_bytes()[1..]);
    Ok(Address::from_slice(&digest[12..]))
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{signature::hazmat::PrehashSigner as _, SigningKey};

    use super::*;

    #[test]
    fn signer_and_public_key_round_trip() {
        let key = SigningKey::from_slice(&crate::test_keys::secret(0x42)).unwrap();
        let prehash = keccak256(b"outbe/tee/signature-test/v1");
        let (signature, recovery_id): (EcdsaSignature, RecoveryId) =
            key.sign_prehash(prehash.as_slice()).unwrap();
        let mut encoded = [0_u8; 65];
        encoded[..64].copy_from_slice(signature.to_bytes().as_slice());
        encoded[64] = recovery_id.to_byte();

        let public = recover_signer_public_key(&prehash, &encoded).unwrap();
        assert_eq!(
            public.as_slice(),
            key.verifying_key().to_encoded_point(true).as_bytes()
        );

        let uncompressed = key.verifying_key().to_encoded_point(false);
        let digest = keccak256(&uncompressed.as_bytes()[1..]);
        assert_eq!(
            recover_signer(&prehash, &encoded).unwrap(),
            Address::from_slice(&digest[12..])
        );
    }

    #[test]
    fn invalid_recovery_id_rejects() {
        let error = recover_signer(&B256::ZERO, &[0xFF; 65]).unwrap_err();
        assert!(error.to_string().contains("invalid recovery id"));
    }
}
