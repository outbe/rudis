use alloy_primitives::{B256, U256};
use outbe_ocomp_protocol::{profile::ProtocolBundleV1, SchemaLimits, OCB1_HEADER_LEN};
use outbe_primitives::error::Result;

use crate::{
    errors::corruption,
    precompile::IOcompRegistry,
    profile::{validate_request_profile, OcompRequestProfile},
    schema::OcompRegistry,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OcompProtocolAuthorityV1 {
    pub request_profile: OcompRequestProfile,
    pub protocol_bundle: ProtocolBundleV1,
}

/// One predecessor-bound OCOMP authority carried by an Update proposal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OcompSuccessorV1 {
    pub activation_height: u64,
    pub predecessor_protocol_bundle_hash: B256,
    pub authority: OcompProtocolAuthorityV1,
}

const AUTHORITY_MAGIC: [u8; 4] = *b"OCA1";
const SUCCESSOR_MAGIC: [u8; 4] = *b"OCS1";
const SUCCESSOR_VERSION: u16 = 1;

impl OcompRegistry<'_> {
    pub fn initialize_genesis_authority(
        &mut self,
        authority: &OcompProtocolAuthorityV1,
        install_hash: B256,
        activation_height: u64,
        current_height: u64,
        limits: &SchemaLimits,
    ) -> Result<()> {
        if activation_height == 0
            || current_height != activation_height
            || self.storage.block_number()? != current_height
        {
            return Err(corruption(
                "OCOMP Registry install attempted outside its activation height",
            ));
        }
        if install_hash.is_zero() {
            return Err(corruption("OCOMP Registry install hash must be non-zero"));
        }
        validate_protocol_authority(authority, limits)?;
        if self.storage.chain_id()? != authority.request_profile.chain_id
            || self.storage.genesis_hash()? != authority.request_profile.genesis_hash
        {
            return Err(corruption("OCOMP Registry chain identity mismatch"));
        }

        match self.active_authority(limits)? {
            Some(existing)
                if existing == *authority
                    && self.install_hash.read()? == install_hash
                    && self.activation_height.read()? == activation_height =>
            {
                return Ok(())
            }
            Some(_) => {
                return Err(corruption("OCOMP Registry genesis authority is immutable"));
            }
            None => {}
        }
        if !self.install_hash.read()?.is_zero() || self.activation_height.read()? != 0 {
            return Err(corruption("OCOMP Registry genesis authority is partial"));
        }

        let request_profile = authority.request_profile.encode_canonical(limits)?;
        let protocol_bundle = authority
            .protocol_bundle
            .encode_canonical(limits)
            .map_err(protocol_error)?;
        let bundle_hash = authority.request_profile.protocol_bundle_hash;
        let checkpoint = self.storage.checkpoint_guard();
        self.active_request_profile.write(&request_profile)?;
        self.active_protocol_bundle.write(&protocol_bundle)?;
        self.active_protocol_bundle_hash.write(bundle_hash)?;
        self.install_hash.write(install_hash)?;
        self.activation_height.write(activation_height)?;
        self.emit(IOcompRegistry::OcompProtocolAuthorityInstalled {
            protocolBundleHash: bundle_hash,
            installHash: install_hash,
            activationHeight: activation_height,
        })?;
        if self.active_authority(limits)? != Some(authority.clone()) {
            return Err(corruption("OCOMP Registry authority write/read mismatch"));
        }
        checkpoint.commit();
        Ok(())
    }

    pub fn active_authority(
        &self,
        limits: &SchemaLimits,
    ) -> Result<Option<OcompProtocolAuthorityV1>> {
        let profile_len = self.active_request_profile.len()?;
        let bundle_len = self.active_protocol_bundle.len()?;
        let bundle_hash = self.active_protocol_bundle_hash.read()?;
        if profile_len == 0 && bundle_len == 0 && bundle_hash.is_zero() {
            return Ok(None);
        }
        if profile_len == 0 || bundle_len == 0 || bundle_hash.is_zero() {
            return Err(corruption("OCOMP Registry active authority is partial"));
        }
        let max = limits
            .codec
            .max_allocation_bytes
            .checked_add(OCB1_HEADER_LEN)
            .ok_or_else(|| corruption("OCOMP Registry authority byte cap overflow"))?;
        if profile_len > max || bundle_len > max {
            return Err(corruption(
                "OCOMP Registry active authority exceeds byte cap",
            ));
        }
        let request_profile =
            OcompRequestProfile::decode_canonical(&self.active_request_profile.read()?, limits)?;
        let protocol_bundle =
            ProtocolBundleV1::decode_canonical(&self.active_protocol_bundle.read()?, limits)
                .map_err(protocol_error)?;
        let authority = OcompProtocolAuthorityV1 {
            request_profile,
            protocol_bundle,
        };
        validate_protocol_authority(&authority, limits)?;
        if authority.request_profile.protocol_bundle_hash != bundle_hash {
            return Err(corruption(
                "OCOMP Registry active bundle hash slot is inconsistent",
            ));
        }
        Ok(Some(authority))
    }

    pub fn staged_successor(
        &self,
        limits: &SchemaLimits,
    ) -> Result<Option<(U256, OcompSuccessorV1)>> {
        let bytes = self.staged_successor.read()?;
        let proposal_id = self.staged_proposal_id.read()?;
        match (bytes.is_empty(), proposal_id.is_zero()) {
            (true, true) => Ok(None),
            (false, false) => Ok(Some((
                proposal_id,
                OcompSuccessorV1::decode_canonical(&bytes, limits)?,
            ))),
            _ => Err(corruption("OCOMP Registry staged successor is partial")),
        }
    }

    pub fn stage_successor(
        &mut self,
        proposal_id: U256,
        successor: &OcompSuccessorV1,
        limits: &SchemaLimits,
    ) -> Result<()> {
        if proposal_id.is_zero() {
            return Err(corruption("OCOMP successor proposal id must be non-zero"));
        }
        let current_height = self.storage.block_number()?;
        let active = self
            .active_authority(limits)?
            .ok_or_else(|| corruption("OCOMP Registry is not initialized"))?;
        validate_successor(&active, successor, current_height, limits)?;
        if !self.retiring_authority.is_empty()? {
            return Err(corruption(
                "OCOMP predecessor retirement must finish before staging another successor",
            ));
        }
        let encoded = successor.encode_canonical(limits)?;
        if let Some((stored_id, stored)) = self.staged_successor(limits)? {
            if stored_id == proposal_id && stored == *successor {
                return Ok(());
            }
            return Err(corruption("another OCOMP successor is already staged"));
        }
        let checkpoint = self.storage.checkpoint_guard();
        self.staged_successor.write(&encoded)?;
        self.staged_proposal_id.write(proposal_id)?;
        self.emit(IOcompRegistry::OcompSuccessorStaged {
            proposalId: proposal_id,
            protocolBundleHash: successor.authority.request_profile.protocol_bundle_hash,
            activationHeight: successor.activation_height,
        })?;
        checkpoint.commit();
        Ok(())
    }

    pub fn discard_staged_successor(&mut self, proposal_id: U256) -> Result<()> {
        let Some((stored_id, _)) = self.staged_successor(&poc_limits())? else {
            return Ok(());
        };
        if stored_id != proposal_id {
            return Err(corruption(
                "cannot discard another Update proposal's OCOMP successor",
            ));
        }
        self.staged_successor.clear()?;
        self.staged_proposal_id.delete()
    }

    pub fn promote_staged_successor(
        &mut self,
        proposal_id: U256,
        current_height: u64,
        limits: &SchemaLimits,
    ) -> Result<()> {
        if self.storage.block_number()? != current_height {
            return Err(corruption(
                "OCOMP successor activation height does not match storage context",
            ));
        }
        let Some((stored_id, successor)) = self.staged_successor(limits)? else {
            return Err(corruption("OCOMP successor is not staged"));
        };
        if stored_id != proposal_id || successor.activation_height != current_height {
            return Err(corruption(
                "OCOMP successor activation proposal or height mismatch",
            ));
        }
        if !self.retiring_authority.is_empty()? {
            return Err(corruption(
                "OCOMP Registry already has a retiring predecessor",
            ));
        }
        let active = self
            .active_authority(limits)?
            .ok_or_else(|| corruption("OCOMP Registry is not initialized"))?;
        validate_successor(
            &active,
            &successor,
            current_height.saturating_sub(1),
            limits,
        )?;
        let old_hash = active.request_profile.protocol_bundle_hash;
        let new_hash = successor.authority.request_profile.protocol_bundle_hash;
        let old_encoded = encode_authority(&active, limits)?;
        let new_profile = successor
            .authority
            .request_profile
            .encode_canonical(limits)?;
        let new_bundle = successor
            .authority
            .protocol_bundle
            .encode_canonical(limits)
            .map_err(protocol_error)?;
        let checkpoint = self.storage.checkpoint_guard();
        self.retiring_authority.write(&old_encoded)?;
        self.active_request_profile.write(&new_profile)?;
        self.active_protocol_bundle.write(&new_bundle)?;
        self.active_protocol_bundle_hash.write(new_hash)?;
        self.activation_height.write(current_height)?;
        self.staged_successor.clear()?;
        self.staged_proposal_id.delete()?;
        if self.live_lineage_count.read(&old_hash)? == 0 {
            self.retention_until
                .write(&old_hash, retention_deadline(current_height, &active)?)?;
        }
        self.emit(IOcompRegistry::OcompSuccessorActivated {
            proposalId: proposal_id,
            predecessorProtocolBundleHash: old_hash,
            protocolBundleHash: new_hash,
            activationHeight: current_height,
        })?;
        checkpoint.commit();
        Ok(())
    }

    pub fn authority_by_bundle_hash(
        &self,
        bundle_hash: B256,
        limits: &SchemaLimits,
    ) -> Result<Option<OcompProtocolAuthorityV1>> {
        if let Some(active) = self.active_authority(limits)? {
            if active.request_profile.protocol_bundle_hash == bundle_hash {
                return Ok(Some(active));
            }
        }
        let retiring = self.retiring_authority.read()?;
        if retiring.is_empty() {
            return Ok(None);
        }
        let authority = decode_authority(&retiring, limits)?;
        if authority.request_profile.protocol_bundle_hash == bundle_hash {
            Ok(Some(authority))
        } else {
            Ok(None)
        }
    }

    pub fn retiring_authority(
        &self,
        limits: &SchemaLimits,
    ) -> Result<Option<OcompProtocolAuthorityV1>> {
        let encoded = self.retiring_authority.read()?;
        if encoded.is_empty() {
            Ok(None)
        } else {
            decode_authority(&encoded, limits).map(Some)
        }
    }

    /// Pins a fresh lineage to the current active bundle. Exact replay returns
    /// the existing pin and never silently follows a later active bundle.
    pub fn pin_lineage(&mut self, lineage: B256, limits: &SchemaLimits) -> Result<B256> {
        if lineage.is_zero() {
            return Err(corruption("OCOMP lineage id must be non-zero"));
        }
        let existing = self.lineage_bundle.read(&lineage)?;
        if !existing.is_zero() {
            if self.authority_by_bundle_hash(existing, limits)?.is_none() {
                return Err(corruption("OCOMP lineage references an unavailable bundle"));
            }
            return Ok(existing);
        }
        let active = self
            .active_authority(limits)?
            .ok_or_else(|| corruption("OCOMP Registry is not initialized"))?;
        let bundle_hash = active.request_profile.protocol_bundle_hash;
        let count = self.live_lineage_count.read(&bundle_hash)?;
        let next = count
            .checked_add(1)
            .ok_or_else(|| corruption("OCOMP live lineage count overflow"))?;
        let checkpoint = self.storage.checkpoint_guard();
        self.lineage_bundle.write(&lineage, bundle_hash)?;
        self.live_lineage_count.write(&bundle_hash, next)?;
        checkpoint.commit();
        Ok(bundle_hash)
    }

    /// Pins a retry/successor lineage to the exact bundle of its predecessor.
    /// The predecessor must still be live; absence is fatal and never falls
    /// back to the current active authority.
    pub fn pin_inherited_lineage(
        &mut self,
        lineage: B256,
        predecessor_lineage: B256,
        limits: &SchemaLimits,
    ) -> Result<B256> {
        if lineage.is_zero() || predecessor_lineage.is_zero() || lineage == predecessor_lineage {
            return Err(corruption("invalid OCOMP inherited lineage binding"));
        }
        let inherited = self
            .resolve_lineage(predecessor_lineage)?
            .ok_or_else(|| corruption("OCOMP predecessor lineage is not pinned"))?;
        if self.authority_by_bundle_hash(inherited, limits)?.is_none() {
            return Err(corruption(
                "OCOMP predecessor lineage authority is unavailable",
            ));
        }
        let existing = self.lineage_bundle.read(&lineage)?;
        if !existing.is_zero() {
            return if existing == inherited {
                Ok(existing)
            } else {
                Err(corruption("OCOMP inherited lineage binding changed"))
            };
        }
        let count = self.live_lineage_count.read(&inherited)?;
        let next = count
            .checked_add(1)
            .ok_or_else(|| corruption("OCOMP live lineage count overflow"))?;
        let checkpoint = self.storage.checkpoint_guard();
        self.lineage_bundle.write(&lineage, inherited)?;
        self.live_lineage_count.write(&inherited, next)?;
        checkpoint.commit();
        Ok(inherited)
    }

    pub fn resolve_lineage(&self, lineage: B256) -> Result<Option<B256>> {
        let bundle_hash = self.lineage_bundle.read(&lineage)?;
        Ok((!bundle_hash.is_zero()).then_some(bundle_hash))
    }

    pub fn release_lineage(
        &mut self,
        lineage: B256,
        current_height: u64,
        limits: &SchemaLimits,
    ) -> Result<bool> {
        let Some(bundle_hash) = self.resolve_lineage(lineage)? else {
            return Ok(false);
        };
        let count = self.live_lineage_count.read(&bundle_hash)?;
        let next = count
            .checked_sub(1)
            .ok_or_else(|| corruption("OCOMP live lineage count underflow"))?;
        let checkpoint = self.storage.checkpoint_guard();
        self.lineage_bundle.get(&lineage).delete()?;
        self.live_lineage_count.write(&bundle_hash, next)?;
        if next == 0 {
            let retiring = self.retiring_authority.read()?;
            if !retiring.is_empty() {
                let authority = decode_authority(&retiring, limits)?;
                if authority.request_profile.protocol_bundle_hash == bundle_hash {
                    self.retention_until.write(
                        &bundle_hash,
                        retention_deadline(current_height, &authority)?,
                    )?;
                }
            }
        }
        checkpoint.commit();
        Ok(true)
    }

    pub fn try_retire_predecessor(
        &mut self,
        current_height: u64,
        limits: &SchemaLimits,
    ) -> Result<bool> {
        let bytes = self.retiring_authority.read()?;
        if bytes.is_empty() {
            return Ok(false);
        }
        if self.storage.block_number()? != current_height {
            return Err(corruption(
                "OCOMP retirement height does not match storage context",
            ));
        }
        let authority = decode_authority(&bytes, limits)?;
        let bundle_hash = authority.request_profile.protocol_bundle_hash;
        if self.live_lineage_count.read(&bundle_hash)? != 0 {
            return Ok(false);
        }
        let deadline = self.retention_until.read(&bundle_hash)?;
        if deadline == 0 || current_height < deadline {
            return Ok(false);
        }
        let checkpoint = self.storage.checkpoint_guard();
        self.retiring_authority.clear()?;
        self.retention_until.get(&bundle_hash).delete()?;
        self.emit(IOcompRegistry::OcompProtocolAuthorityRetired {
            protocolBundleHash: bundle_hash,
            retiredAt: current_height,
        })?;
        checkpoint.commit();
        Ok(true)
    }
}

impl OcompSuccessorV1 {
    pub fn validate_against(
        &self,
        predecessor: &OcompProtocolAuthorityV1,
        current_height: u64,
        limits: &SchemaLimits,
    ) -> Result<()> {
        validate_successor(predecessor, self, current_height, limits)
    }

    pub fn encode_canonical(&self, limits: &SchemaLimits) -> Result<Vec<u8>> {
        let authority = encode_authority(&self.authority, limits)?;
        let authority_len = u32::try_from(authority.len())
            .map_err(|_| corruption("OCOMP successor authority exceeds u32"))?;
        let mut bytes = Vec::with_capacity(4 + 2 + 8 + 32 + 4 + authority.len());
        bytes.extend_from_slice(&SUCCESSOR_MAGIC);
        bytes.extend_from_slice(&SUCCESSOR_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.activation_height.to_be_bytes());
        bytes.extend_from_slice(self.predecessor_protocol_bundle_hash.as_slice());
        bytes.extend_from_slice(&authority_len.to_be_bytes());
        bytes.extend_from_slice(&authority);
        validate_encoded_cap(bytes.len(), limits)?;
        Ok(bytes)
    }

    pub fn decode_canonical(bytes: &[u8], limits: &SchemaLimits) -> Result<Self> {
        validate_encoded_cap(bytes.len(), limits)?;
        if bytes.len() < 50
            || bytes[..4] != SUCCESSOR_MAGIC
            || u16::from_be_bytes(
                bytes[4..6]
                    .try_into()
                    .map_err(|_| corruption("truncated OCOMP successor"))?,
            ) != SUCCESSOR_VERSION
        {
            return Err(corruption("OCOMP successor magic/version mismatch"));
        }
        let activation_height = u64::from_be_bytes(
            bytes[6..14]
                .try_into()
                .map_err(|_| corruption("truncated OCOMP successor height"))?,
        );
        let predecessor_protocol_bundle_hash = B256::from_slice(&bytes[14..46]);
        let authority_len =
            usize::try_from(u32::from_be_bytes(bytes[46..50].try_into().map_err(
                |_| corruption("truncated OCOMP successor authority length"),
            )?))
            .map_err(|_| corruption("OCOMP successor authority length exceeds usize"))?;
        if bytes.len().checked_sub(50) != Some(authority_len) {
            return Err(corruption("OCOMP successor authority length mismatch"));
        }
        let decoded = Self {
            activation_height,
            predecessor_protocol_bundle_hash,
            authority: decode_authority(&bytes[50..], limits)?,
        };
        if decoded.encode_canonical(limits)? != bytes {
            return Err(corruption("non-canonical OCOMP successor encoding"));
        }
        Ok(decoded)
    }
}

pub(crate) fn validate_protocol_authority(
    authority: &OcompProtocolAuthorityV1,
    limits: &SchemaLimits,
) -> Result<()> {
    validate_request_profile(&authority.request_profile)?;
    let bundle = &authority.protocol_bundle;
    let bundle_hash = bundle
        .protocol_bundle_hash(limits)
        .map_err(protocol_error)?;
    if bundle_hash != authority.request_profile.protocol_bundle_hash
        || bundle.fork_id != authority.request_profile.fork_id
        || bundle.correctness_profile_id != authority.request_profile.correctness_profile_id
        || bundle.capacity_profile_id != authority.request_profile.capacity_profile.profile_id
    {
        return Err(corruption(
            "OCOMP protocol bundle differs from the request profile",
        ));
    }
    bundle
        .validate_lysis_v1_input_codecs()
        .map_err(protocol_error)
}

fn protocol_error(error: impl core::fmt::Display) -> outbe_primitives::error::PrecompileError {
    corruption(format!("invalid OCOMP protocol authority: {error}"))
}

fn validate_successor(
    active: &OcompProtocolAuthorityV1,
    successor: &OcompSuccessorV1,
    current_height: u64,
    limits: &SchemaLimits,
) -> Result<()> {
    validate_protocol_authority(&successor.authority, limits)?;
    if successor.activation_height <= current_height
        || successor.predecessor_protocol_bundle_hash != active.request_profile.protocol_bundle_hash
        || successor.authority.request_profile.chain_id != active.request_profile.chain_id
        || successor.authority.request_profile.genesis_hash != active.request_profile.genesis_hash
        || successor.authority.request_profile.capacity_profile
            != active.request_profile.capacity_profile
        || successor
            .authority
            .request_profile
            .source_availability_policy_id
            != active.request_profile.source_availability_policy_id
        || successor.authority.protocol_bundle.protocol_version
            != active
                .protocol_bundle
                .protocol_version
                .checked_add(1)
                .ok_or_else(|| corruption("OCOMP protocol version overflow"))?
        || successor
            .authority
            .protocol_bundle
            .consensus_state_schema_version
            != active.protocol_bundle.consensus_state_schema_version
    {
        return Err(corruption(
            "OCOMP successor violates predecessor or immutable-policy invariants",
        ));
    }
    Ok(())
}

fn encode_authority(
    authority: &OcompProtocolAuthorityV1,
    limits: &SchemaLimits,
) -> Result<Vec<u8>> {
    validate_protocol_authority(authority, limits)?;
    let profile = authority.request_profile.encode_canonical(limits)?;
    let bundle = authority
        .protocol_bundle
        .encode_canonical(limits)
        .map_err(protocol_error)?;
    let profile_len = u32::try_from(profile.len())
        .map_err(|_| corruption("OCOMP authority profile exceeds u32"))?;
    let bundle_len = u32::try_from(bundle.len())
        .map_err(|_| corruption("OCOMP authority bundle exceeds u32"))?;
    let mut bytes = Vec::with_capacity(12 + profile.len() + bundle.len());
    bytes.extend_from_slice(&AUTHORITY_MAGIC);
    bytes.extend_from_slice(&profile_len.to_be_bytes());
    bytes.extend_from_slice(&profile);
    bytes.extend_from_slice(&bundle_len.to_be_bytes());
    bytes.extend_from_slice(&bundle);
    validate_encoded_cap(bytes.len(), limits)?;
    Ok(bytes)
}

fn decode_authority(bytes: &[u8], limits: &SchemaLimits) -> Result<OcompProtocolAuthorityV1> {
    validate_encoded_cap(bytes.len(), limits)?;
    if bytes.len() < 12 || bytes[..4] != AUTHORITY_MAGIC {
        return Err(corruption("OCOMP authority magic mismatch"));
    }
    let profile_len = usize::try_from(u32::from_be_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| corruption("truncated OCOMP authority profile length"))?,
    ))
    .map_err(|_| corruption("OCOMP authority profile length exceeds usize"))?;
    let profile_end = 8usize
        .checked_add(profile_len)
        .ok_or_else(|| corruption("OCOMP authority profile length overflow"))?;
    let bundle_len_end = profile_end
        .checked_add(4)
        .ok_or_else(|| corruption("OCOMP authority bundle offset overflow"))?;
    if bundle_len_end > bytes.len() {
        return Err(corruption("truncated OCOMP authority profile"));
    }
    let bundle_len = usize::try_from(u32::from_be_bytes(
        bytes[profile_end..bundle_len_end]
            .try_into()
            .map_err(|_| corruption("truncated OCOMP authority bundle length"))?,
    ))
    .map_err(|_| corruption("OCOMP authority bundle length exceeds usize"))?;
    let bundle_end = bundle_len_end
        .checked_add(bundle_len)
        .ok_or_else(|| corruption("OCOMP authority bundle length overflow"))?;
    if bundle_end != bytes.len() {
        return Err(corruption("OCOMP authority bundle length mismatch"));
    }
    let authority = OcompProtocolAuthorityV1 {
        request_profile: OcompRequestProfile::decode_canonical(&bytes[8..profile_end], limits)?,
        protocol_bundle: ProtocolBundleV1::decode_canonical(
            &bytes[bundle_len_end..bundle_end],
            limits,
        )
        .map_err(protocol_error)?,
    };
    validate_protocol_authority(&authority, limits)?;
    if encode_authority(&authority, limits)? != bytes {
        return Err(corruption("non-canonical OCOMP authority encoding"));
    }
    Ok(authority)
}

fn validate_encoded_cap(length: usize, limits: &SchemaLimits) -> Result<()> {
    if length == 0 || length > limits.codec.max_allocation_bytes {
        return Err(corruption(
            "OCOMP Registry canonical object exceeds byte cap",
        ));
    }
    Ok(())
}

fn retention_deadline(current_height: u64, authority: &OcompProtocolAuthorityV1) -> Result<u64> {
    current_height
        .checked_add(
            authority
                .request_profile
                .capacity_profile
                .source_retention_after_terminal_blocks,
        )
        .ok_or_else(|| corruption("OCOMP predecessor retention height overflow"))
}

fn poc_limits() -> SchemaLimits {
    crate::profile::poc_schema_limits()
}
