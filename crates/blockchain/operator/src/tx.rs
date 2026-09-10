//! Relay transaction construction shared by lifecycle CLI and daemon paths.

use std::{
    fs::{self, OpenOptions},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use alloy_primitives::{keccak256, Address, B256, U256};
use eyre::{Result, WrapErr as _};
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub fn buffered_gas_price(suggested: U256) -> U256 {
    suggested
        .saturating_mul(U256::from(2))
        .max(U256::from(alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RawRelayTransactionV1 {
    pub relay: Address,
    pub chain_id: u64,
    pub account_nonce: u64,
    pub gas_price: U256,
    pub gas_limit: u64,
    pub calldata_hash: B256,
    pub raw_transaction: Vec<u8>,
    pub transaction_hash: B256,
}

pub struct RelaySignerV1 {
    key: SigningKey,
    address: Address,
}

impl RelaySignerV1 {
    pub fn new(private_key_hex: &str) -> Result<Self> {
        let encoded = private_key_hex
            .trim()
            .strip_prefix("0x")
            .unwrap_or(private_key_hex.trim());
        let decoded = Zeroizing::new(hex::decode(encoded).wrap_err("decode relay private key")?);
        Self::from_bytes(decoded.as_ref())
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let path_metadata = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("stat relay private key {}", path.display()))?;
        if !path_metadata.file_type().is_file()
            || path_metadata.uid() != rustix::process::geteuid().as_raw()
            || path_metadata.permissions().mode() & 0o777 != 0o600
            || path_metadata.nlink() != 1
            || path_metadata.len() == 0
            || path_metadata.len() > 130
        {
            eyre::bail!("relay private key must be an owner-bound 0600 regular file");
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .wrap_err_with(|| format!("open relay private key {}", path.display()))?;
        let opened = file
            .metadata()
            .wrap_err_with(|| format!("stat opened relay private key {}", path.display()))?;
        if opened.dev() != path_metadata.dev() || opened.ino() != path_metadata.ino() {
            eyre::bail!("relay private key path changed while opening");
        }
        let mut bytes = Vec::with_capacity(opened.len() as usize);
        file.take(131)
            .read_to_end(&mut bytes)
            .wrap_err_with(|| format!("read relay private key {}", path.display()))?;
        if bytes.len() > 130 {
            eyre::bail!("relay private key grew beyond its size bound");
        }
        let encoded = Zeroizing::new(bytes);
        if encoded.len() == 32 {
            return Self::from_bytes(encoded.as_ref());
        }
        let text = std::str::from_utf8(encoded.as_ref())
            .wrap_err("relay private key is neither raw bytes nor UTF-8 hex")?;
        Self::new(text)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| eyre::eyre!("relay private key must contain exactly 32 bytes"))?;
        let key = SigningKey::from_bytes((&bytes).into())
            .map_err(|error| eyre::eyre!("invalid relay private key: {error}"))?;
        let public = key.verifying_key().to_encoded_point(false);
        let hash = keccak256(&public.as_bytes()[1..]);
        let address = Address::from_slice(&hash[12..]);
        Ok(Self { key, address })
    }

    #[must_use]
    pub const fn address(&self) -> Address {
        self.address
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_renewal(
        &self,
        chain_id: u64,
        account_nonce: u64,
        gas_price: U256,
        gas_limit: u64,
        to: Address,
        calldata: &[u8],
    ) -> Result<RawRelayTransactionV1> {
        let raw_transaction = self.sign_legacy_transaction(
            chain_id,
            account_nonce,
            gas_price,
            gas_limit,
            to,
            U256::ZERO,
            calldata,
        )?;
        Ok(RawRelayTransactionV1 {
            relay: self.address,
            chain_id,
            account_nonce,
            gas_price,
            gas_limit,
            calldata_hash: keccak256(calldata),
            transaction_hash: keccak256(&raw_transaction),
            raw_transaction,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_legacy_transaction(
        &self,
        chain_id: u64,
        nonce: u64,
        gas_price: U256,
        gas_limit: u64,
        to: Address,
        value: U256,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        let unsigned_fields = [
            rlp_u64(nonce),
            rlp_u256(gas_price),
            rlp_u64(gas_limit),
            rlp_bytes(to.as_slice()),
            rlp_u256(value),
            rlp_bytes(data),
            rlp_u64(chain_id),
            rlp_u64(0),
            rlp_u64(0),
        ];
        let unsigned = rlp_list(&unsigned_fields);
        let digest = keccak256(&unsigned);
        let (signature, recovery): (k256::ecdsa::Signature, k256::ecdsa::RecoveryId) = self
            .key
            .sign_prehash(digest.as_slice())
            .map_err(|error| eyre::eyre!("relay signing failed: {error}"))?;
        let bytes = signature.to_bytes();
        let v = chain_id
            .checked_mul(2)
            .and_then(|value| value.checked_add(35 + u64::from(recovery.to_byte())))
            .ok_or_else(|| eyre::eyre!("EIP-155 recovery id overflow"))?;
        Ok(rlp_list(&[
            rlp_u64(nonce),
            rlp_u256(gas_price),
            rlp_u64(gas_limit),
            rlp_bytes(to.as_slice()),
            rlp_u256(value),
            rlp_bytes(data),
            rlp_u64(v),
            rlp_u256(U256::from_be_slice(&bytes[..32])),
            rlp_u256(U256::from_be_slice(&bytes[32..])),
        ]))
    }
}

fn rlp_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes();
    rlp_bytes(&bytes[bytes.iter().position(|byte| *byte != 0).unwrap_or(7)..])
}

fn rlp_u256(value: U256) -> Vec<u8> {
    if value.is_zero() {
        return vec![0x80];
    }
    let bytes = value.to_be_bytes::<32>();
    rlp_bytes(&bytes[bytes.iter().position(|byte| *byte != 0).unwrap_or(31)..])
}

fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    if value.len() == 1 && value[0] < 0x80 {
        return value.to_vec();
    }
    let mut encoded = length_prefix(0x80, 0xb7, value.len());
    encoded.extend_from_slice(value);
    encoded
}

fn rlp_list(fields: &[Vec<u8>]) -> Vec<u8> {
    let length = fields.iter().map(Vec::len).sum();
    let mut encoded = length_prefix(0xc0, 0xf7, length);
    for field in fields {
        encoded.extend_from_slice(field);
    }
    encoded
}

fn length_prefix(short: u8, long: u8, length: usize) -> Vec<u8> {
    if length <= 55 {
        return vec![short + length as u8];
    }
    let bytes = length.to_be_bytes();
    let significant = &bytes[bytes.iter().position(|byte| *byte != 0).unwrap_or(7)..];
    let mut prefix = Vec::with_capacity(1 + significant.len());
    prefix.push(long + significant.len() as u8);
    prefix.extend_from_slice(significant);
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE;

    #[test]
    fn buffered_gas_price_uses_native_unit_protocol_floor() {
        let protocol_floor = U256::from(MIN_PROTOCOL_BASE_FEE);
        assert_eq!(buffered_gas_price(U256::ZERO), protocol_floor);
        assert_eq!(
            buffered_gas_price(protocol_floor),
            protocol_floor * U256::from(2)
        );
    }

    #[test]
    fn exact_inputs_produce_exact_raw_transaction_and_hash() {
        let signer = RelaySignerV1::new(&format!("{:064x}", 1)).unwrap();
        let first = signer
            .sign_renewal(
                70_860_602,
                7,
                U256::from(1_000_000_000_u64),
                1_000_000,
                Address::repeat_byte(0xee),
                &[1, 2, 3],
            )
            .unwrap();
        let second = signer
            .sign_renewal(
                70_860_602,
                7,
                U256::from(1_000_000_000_u64),
                1_000_000,
                Address::repeat_byte(0xee),
                &[1, 2, 3],
            )
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.transaction_hash, keccak256(&first.raw_transaction));
    }

    #[test]
    fn replacement_keeps_nonce_and_calldata_but_changes_only_fee_and_hash() {
        let signer = RelaySignerV1::new(&format!("{:064x}", 2)).unwrap();
        let low = signer
            .sign_renewal(1, 9, U256::from(10), 100, Address::ZERO, &[4, 5])
            .unwrap();
        let high = signer
            .sign_renewal(1, 9, U256::from(20), 100, Address::ZERO, &[4, 5])
            .unwrap();
        assert_eq!(low.account_nonce, high.account_nonce);
        assert_eq!(low.calldata_hash, high.calldata_hash);
        assert_ne!(low.raw_transaction, high.raw_transaction);
        assert_ne!(low.transaction_hash, high.transaction_hash);
    }
}
