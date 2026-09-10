//! Canonical fresh-genesis OCOMP authority manifest.

use std::collections::BTreeSet;

use alloy_primitives::{keccak256, B256};
use outbe_ocomp_protocol::{
    committee::OcompKeyRegistrationV1, profile::ProtocolBundleV1, SchemaLimits,
};
use outbe_primitives::error::Result;

use crate::{
    errors::corruption,
    runtime::{validate_protocol_authority, OcompProtocolAuthorityV1},
    OcompRequestProfile,
};

const MAGIC: [u8; 4] = *b"OFI1";
const VERSION: u16 = 1;
const FIXED_LEN: usize = 4 + 2 + 1 + 8 + 4 + 4 + 4;
const HASH_DOMAIN: &[u8] = b"OUTBE_OCOMP_FORK_INSTALL_V1\0";

pub const OCOMP_POC_FINAL_ACTIVATION_HEIGHT: u64 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OcompForkInstallClassification {
    Measurement = 1,
    Final = 2,
}

impl OcompForkInstallClassification {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Measurement),
            2 => Ok(Self::Final),
            _ => Err(corruption("unknown OCOMP fork-install classification")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OcompForkInstallV1 {
    pub classification: OcompForkInstallClassification,
    pub activation_height: u64,
    pub request_profile: OcompRequestProfile,
    pub protocol_bundle: ProtocolBundleV1,
    pub founder_registrations: Vec<OcompKeyRegistrationV1>,
}

impl OcompForkInstallV1 {
    pub fn authority(&self) -> OcompProtocolAuthorityV1 {
        OcompProtocolAuthorityV1 {
            request_profile: self.request_profile.clone(),
            protocol_bundle: self.protocol_bundle.clone(),
        }
    }

    pub fn validate_for_chain(
        &self,
        expected_chain_id: u64,
        expected_genesis_hash: B256,
        limits: &SchemaLimits,
    ) -> Result<()> {
        if self.activation_height == 0 {
            return Err(corruption("OCOMP fork activation height must be non-zero"));
        }
        if self.classification == OcompForkInstallClassification::Final
            && self.activation_height != OCOMP_POC_FINAL_ACTIVATION_HEIGHT
        {
            return Err(corruption(
                "final OCOMP PoC fork must activate at height 32",
            ));
        }
        if self.request_profile.chain_id != expected_chain_id
            || self.request_profile.genesis_hash != expected_genesis_hash
        {
            return Err(corruption("OCOMP fork-install chain identity mismatch"));
        }
        if self.protocol_bundle.protocol_version != 1 {
            return Err(corruption(
                "unsupported initial OCOMP protocol bundle version",
            ));
        }
        validate_protocol_authority(&self.authority(), limits)?;
        self.validate_founders(limits)
    }

    fn validate_founders(&self, limits: &SchemaLimits) -> Result<()> {
        let max = usize::try_from(outbe_consensus::bls::MAX_VALIDATORS)
            .map_err(|_| corruption("consensus validator bound exceeds usize"))?;
        if self.founder_registrations.is_empty() || self.founder_registrations.len() > max {
            return Err(corruption(format!(
                "OCOMP founder registration count must be 1..={max}"
            )));
        }
        let mut identities = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for registration in &self.founder_registrations {
            if registration.core.chain_id != self.request_profile.chain_id
                || registration.core.genesis_hash != self.request_profile.genesis_hash
                || registration.core.validator_identity_hash.is_zero()
                || !identities.insert(registration.core.validator_identity_hash)
                || !keys.insert(registration.core.ocomp_public_key_sec1)
            {
                return Err(corruption(
                    "invalid or duplicate OCOMP founder registration",
                ));
            }
            registration
                .validate_proof_of_possession(limits)
                .map_err(protocol_error)?;
        }
        Ok(())
    }

    pub fn encode_canonical(&self, limits: &SchemaLimits) -> Result<Vec<u8>> {
        self.validate_for_chain(
            self.request_profile.chain_id,
            self.request_profile.genesis_hash,
            limits,
        )?;
        let profile = self.request_profile.encode_canonical(limits)?;
        let bundle = self
            .protocol_bundle
            .encode_canonical(limits)
            .map_err(protocol_error)?;
        validate_nested(profile.len(), limits)?;
        validate_nested(bundle.len(), limits)?;
        let mut registrations = Vec::with_capacity(self.founder_registrations.len());
        for registration in &self.founder_registrations {
            let bytes = registration
                .encode_canonical(limits)
                .map_err(protocol_error)?;
            validate_nested(bytes.len(), limits)?;
            registrations.push(bytes);
        }
        let total = registrations.iter().try_fold(
            FIXED_LEN
                .checked_add(profile.len())
                .and_then(|n| n.checked_add(bundle.len()))
                .ok_or_else(|| corruption("OCOMP fork-install length overflow"))?,
            |sum, item| {
                sum.checked_add(4)
                    .and_then(|n| n.checked_add(item.len()))
                    .ok_or_else(|| corruption("OCOMP fork-install length overflow"))
            },
        )?;
        validate_total(total, limits)?;
        let mut encoded = Vec::with_capacity(total);
        encoded.extend_from_slice(&MAGIC);
        encoded.extend_from_slice(&VERSION.to_be_bytes());
        encoded.push(self.classification as u8);
        encoded.extend_from_slice(&self.activation_height.to_be_bytes());
        append_bounded(&mut encoded, &profile)?;
        append_bounded(&mut encoded, &bundle)?;
        encoded.extend_from_slice(
            &u32::try_from(registrations.len())
                .map_err(|_| corruption("OCOMP founder count exceeds u32"))?
                .to_be_bytes(),
        );
        for registration in registrations {
            append_bounded(&mut encoded, &registration)?;
        }
        Ok(encoded)
    }

    pub fn decode_canonical(encoded: &[u8], limits: &SchemaLimits) -> Result<Self> {
        validate_total(encoded.len(), limits)?;
        let mut reader = Reader::new(encoded);
        if reader.take::<4>()? != MAGIC || u16::from_be_bytes(reader.take::<2>()?) != VERSION {
            return Err(corruption("OCOMP fork-install magic/version mismatch"));
        }
        let classification = OcompForkInstallClassification::decode(reader.take::<1>()?[0])?;
        let activation_height = u64::from_be_bytes(reader.take::<8>()?);
        let profile = OcompRequestProfile::decode_canonical(reader.bounded(limits)?, limits)?;
        let bundle = ProtocolBundleV1::decode_canonical(reader.bounded(limits)?, limits)
            .map_err(protocol_error)?;
        let count = usize::try_from(u32::from_be_bytes(reader.take::<4>()?))
            .map_err(|_| corruption("OCOMP founder count exceeds usize"))?;
        let max = usize::try_from(outbe_consensus::bls::MAX_VALIDATORS)
            .map_err(|_| corruption("consensus validator bound exceeds usize"))?;
        if count == 0 || count > max {
            return Err(corruption("invalid OCOMP founder registration count"));
        }
        let mut founder_registrations = Vec::with_capacity(count);
        for _ in 0..count {
            founder_registrations.push(
                OcompKeyRegistrationV1::decode_canonical(reader.bounded(limits)?, limits)
                    .map_err(protocol_error)?,
            );
        }
        if reader.remaining() != 0 {
            return Err(corruption("trailing OCOMP fork-install bytes"));
        }
        let install = Self {
            classification,
            activation_height,
            request_profile: profile,
            protocol_bundle: bundle,
            founder_registrations,
        };
        install.validate_for_chain(
            install.request_profile.chain_id,
            install.request_profile.genesis_hash,
            limits,
        )?;
        if install.encode_canonical(limits)? != encoded {
            return Err(corruption("non-canonical OCOMP fork-install encoding"));
        }
        Ok(install)
    }

    pub fn install_hash(&self, limits: &SchemaLimits) -> Result<B256> {
        let encoded = self.encode_canonical(limits)?;
        let mut preimage = Vec::with_capacity(HASH_DOMAIN.len() + encoded.len());
        preimage.extend_from_slice(HASH_DOMAIN);
        preimage.extend_from_slice(&encoded);
        Ok(keccak256(preimage))
    }
}

fn append_bounded(target: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    target.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| corruption("OCOMP fork-install field exceeds u32"))?
            .to_be_bytes(),
    );
    target.extend_from_slice(bytes);
    Ok(())
}

fn validate_nested(length: usize, limits: &SchemaLimits) -> Result<()> {
    if length > limits.codec.max_allocation_bytes {
        Err(corruption("OCOMP fork-install field exceeds byte cap"))
    } else {
        Ok(())
    }
}

fn validate_total(length: usize, limits: &SchemaLimits) -> Result<()> {
    if length < FIXED_LEN || length > limits.codec.max_allocation_bytes {
        Err(corruption("OCOMP fork-install exceeds byte cap"))
    } else {
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| corruption("OCOMP fork-install offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| corruption("truncated OCOMP fork-install"))?;
        self.offset = end;
        bytes
            .try_into()
            .map_err(|_| corruption("OCOMP fork-install fixed-width decode"))
    }
    fn bounded(&mut self, limits: &SchemaLimits) -> Result<&'a [u8]> {
        let length = usize::try_from(u32::from_be_bytes(self.take::<4>()?))
            .map_err(|_| corruption("OCOMP field length exceeds usize"))?;
        validate_nested(length, limits)?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| corruption("OCOMP field offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| corruption("truncated OCOMP fork-install field"))?;
        self.offset = end;
        Ok(bytes)
    }
}

fn protocol_error(error: impl core::fmt::Display) -> outbe_primitives::error::PrecompileError {
    corruption(format!("invalid OCOMP fork-install object: {error}"))
}
