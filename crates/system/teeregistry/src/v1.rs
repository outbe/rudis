//! TeeRegistry V1 node-enclave registration state machine.
//!
//! A0 activates this schema through the production precompile route. Accepted
//! hardware-free tests still enter only through the private typed post-verifier
//! capability and cannot replace enclave-resident production verification.

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::{
    error::{PrecompileError, Result},
    tee_attestation_v1::{NodeIdV1, TeePolicyV1, MAX_TEE_POLICY_BYTES},
    tee_genesis_v1::is_attestation_mode_allowed_for_chain_id,
};
use outbe_validatorset::contract::ValidatorSet;
#[cfg(feature = "tee-attestation-v1")]
use outbe_validatorset::runtime::status as validator_status;

use crate::schema::TeeRegistry;
#[cfg(feature = "tee-attestation-v1")]
use alloy_primitives::keccak256;

#[cfg(feature = "tee-attestation-v1")]
use outbe_primitives::tee_attestation_v1::{
    AttestationEvidenceV1, AttestationMode, AttestationOperationV1, PlatformTcbStatusSetV1,
    RegistrationIntentV1, ValidatorNodeBindingV1,
};
#[cfg(feature = "tee-attestation-v1")]
use outbe_tee::dcap_protocol::{
    dcap_evidence_hash_v1, DcapOnboardingArtifactV1, DcapOnboardingContextV1,
    DcapPlatformTcbStatusV1, DcapVerdictV1, DcapVerificationOutcomeV1,
};

pub use outbe_primitives::tee_registry_abi_v1::ITeeRegistryV1::{
    EnclaveBindingReplacedV1, EnclaveMeasurementTransitionedV1, EnclaveRegisteredV1,
    EnclaveRenewedV1, OfferKeySealedForRegistryV1, TeePolicyActivatedV1, ValidatorNodeHostBoundV1,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1RegistrationOutcome {
    Created,
    Idempotent,
}

#[cfg(feature = "tee-attestation-v1")]
pub(crate) struct V1OnboardingOutcome {
    pub(crate) registration: V1RegistrationOutcome,
    pub(crate) artifact: Option<DcapOnboardingArtifactV1>,
}

#[cfg(feature = "tee-attestation-v1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifiedEnclaveClaimsV1 {
    mrenclave: B256,
    mrsigner: B256,
    isv_prod_id: u16,
    isv_svn: u16,
    collateral_valid_until: u64,
    platform_tcb_status: u8,
    verdict_hash: B256,
}

#[cfg(feature = "tee-attestation-v1")]
struct VerifiedClaimsMutationV1<'a> {
    expected_operation: AttestationOperationV1,
    caller: Option<Address>,
    intent: &'a RegistrationIntentV1,
    node_signature: &'a [u8; 65],
    enclave_signature: &'a [u8; 64],
    policy: &'a TeePolicyV1,
    claims: &'a VerifiedEnclaveClaimsV1,
    evidence_hash: B256,
}

#[cfg(feature = "tee-attestation-v1")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegistrationCallerContextV1 {
    expired_rejoin: bool,
}

#[cfg(feature = "tee-attestation-v1")]
impl VerifiedEnclaveClaimsV1 {
    fn from_dcap(verdict: &DcapVerdictV1) -> Result<Self> {
        let verdict_bytes = verdict.encode_canonical().map_err(|code| {
            PrecompileError::Fatal(format!(
                "verified DCAP verdict cannot be encoded: {:#06x}",
                code.code()
            ))
        })?;
        Ok(Self {
            mrenclave: verdict.mrenclave,
            mrsigner: verdict.mrsigner,
            isv_prod_id: verdict.isv_prod_id,
            isv_svn: verdict.isv_svn,
            collateral_valid_until: verdict.collateral_valid_until,
            platform_tcb_status: verdict.platform_tcb_status as u8,
            verdict_hash: keccak256(verdict_bytes),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeEnclaveBindingV1 {
    pub node_id_hash: B256,
    pub enclave_id: B256,
    pub binding_id: B256,
    pub intent_hash: B256,
    pub evidence_hash: B256,
    pub policy_hash: B256,
    pub binding_version: u64,
    pub registration_version: u64,
    pub renewal_nonce: u64,
    pub transition_nonce: u64,
    pub lease_started_at: u64,
    pub valid_until: u64,
    pub collateral_valid_until: u64,
    pub recipient_x25519: B256,
    pub attestation_ed25519: B256,
    pub noise_responder_x25519: B256,
    pub mrenclave: B256,
    pub mrsigner: B256,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub platform_tcb_status: u8,
    pub verdict_hash: B256,
    pub node_host_authorization_hash: B256,
}

impl TeeRegistry<'_> {
    #[cfg(feature = "tee-attestation-v1")]
    fn require_registration_caller_v1(
        &self,
        caller: Address,
        binding: &ValidatorNodeBindingV1,
    ) -> Result<RegistrationCallerContextV1> {
        if caller != Address::from(binding.validator) {
            return Err(PrecompileError::Revert(
                "registration caller does not match the NodeHost EVM association".into(),
            ));
        }
        let associated_node = self.validator_v1_node_hash.read(&caller)?;
        let current = self.node_enclave_binding_v1(binding.node_id_hash)?;
        let Some(current) = current else {
            if !associated_node.is_zero() {
                return Err(PrecompileError::Revert(
                    "registration caller is already associated with another NodeHost".into(),
                ));
            }
            return Ok(RegistrationCallerContextV1 {
                expired_rejoin: false,
            });
        };
        if associated_node != binding.node_id_hash {
            return Err(PrecompileError::Revert(
                "registration caller is not associated with the existing NodeHost".into(),
            ));
        }
        let expired_rejoin = consensus_timestamp(&self.storage)? >= current.valid_until;
        if expired_rejoin
            && ValidatorSet::new(self.storage.clone())
                .get_validator(caller)?
                .is_some_and(|record| record.status == validator_status::JAILED)
        {
            return Err(PrecompileError::Revert(
                "jailed validator must complete ordinary unjail before enclave rejoin".into(),
            ));
        }
        Ok(RegistrationCallerContextV1 { expired_rejoin })
    }

    #[cfg(feature = "tee-attestation-v1")]
    fn require_associated_caller_v1(&self, caller: Address, node_id_hash: B256) -> Result<()> {
        if self.validator_v1_node_hash.read(&caller)? != node_id_hash {
            return Err(PrecompileError::Revert(
                "TEE mutator caller is not associated with the target NodeHost".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "tee-attestation-v1")]
    fn require_initial_binding_target_v1(
        intent: &RegistrationIntentV1,
        binding: &ValidatorNodeBindingV1,
    ) -> Result<()> {
        let registered_node_id_hash = intent
            .node_id
            .node_id_hash()
            .map_err(|error| revert_codec("registration NodeHost identity is invalid", error))?;
        if binding.node_id_hash != registered_node_id_hash {
            return Err(PrecompileError::Revert(
                "initial address association must reference the same NodeHost as the registration"
                    .into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "tee-attestation-v1")]
    fn require_initial_binding_evidence_target_v1(
        evidence: &[u8],
        binding: &ValidatorNodeBindingV1,
    ) -> Result<()> {
        let decoded = AttestationEvidenceV1::decode_canonical(evidence)
            .map_err(|error| revert_codec("attestation evidence is not canonical", error))?;
        let intent = match &decoded {
            AttestationEvidenceV1::Dcap(value) => &value.intent,
            AttestationEvidenceV1::GramineDirectDev(value) => &value.intent,
        };
        Self::require_initial_binding_target_v1(intent, binding)
    }

    /// Installs the immutable first V1 policy. Successors are staged and
    /// promoted only by the existing protocol Update lifecycle; this bootstrap
    /// method intentionally cannot rotate a policy.
    pub fn install_initial_policy_v1(&mut self, policy: &TeePolicyV1) -> Result<()> {
        let canonical = policy
            .encode_canonical()
            .map_err(|error| revert_codec("invalid initial V1 policy", error))?;
        let chain_id = self.storage.chain_id()?;
        let expected_chain_id = chain_id_word(chain_id);
        if policy.chain_id != expected_chain_id
            || policy.genesis_hash != self.storage.genesis_hash()?
        {
            return Err(PrecompileError::Revert(
                "initial V1 policy chain identity mismatch".into(),
            ));
        }
        if !is_attestation_mode_allowed_for_chain_id(chain_id, policy.attestation_mode) {
            return Err(PrecompileError::Revert(
                "initial V1 policy attestation mode is not allowed for this chain".into(),
            ));
        }
        if policy.policy_version != 1
            || policy.activation_height != 1
            || !policy.predecessor_policy_hash.is_zero()
        {
            return Err(PrecompileError::Revert(
                "initial V1 policy must be version one at block one".into(),
            ));
        }

        let policy_hash = policy
            .policy_hash()
            .map_err(|error| revert_codec("invalid initial V1 policy", error))?;
        let installed_len = self.active_v1_policy_len.read()?;
        if installed_len != 0 {
            let installed = self.read_policy_bytes_v1()?;
            if installed == canonical && self.active_v1_policy_hash.read()? == policy_hash {
                return Ok(());
            }
            return Err(PrecompileError::Revert(
                "initial V1 policy is already installed".into(),
            ));
        }
        let anchored_hash = self.active_v1_policy_hash.read()?;
        if !anchored_hash.is_zero() && anchored_hash != policy_hash {
            return Err(PrecompileError::Revert(
                "initial V1 policy hash conflicts with registry anchor".into(),
            ));
        }

        for (index, chunk) in canonical.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            let index = u32::try_from(index)
                .map_err(|_| PrecompileError::Revert("V1 policy has too many chunks".into()))?;
            self.active_v1_policy_chunk
                .write(&index, B256::from(word))?;
        }
        let len = u32::try_from(canonical.len())
            .map_err(|_| PrecompileError::Revert("V1 policy is too large".into()))?;
        self.active_v1_policy_len.write(len)?;
        self.active_v1_policy_hash.write(policy_hash)?;
        Ok(())
    }

    /// Stages the one exact successor authorized by an approved protocol
    /// update. The policy remains unavailable to ordinary admission until its
    /// activation height; I7 measurement transition is its only rollout path.
    pub fn stage_successor_policy_v1(
        &mut self,
        proposal_id: U256,
        policy: &TeePolicyV1,
    ) -> Result<()> {
        if proposal_id.is_zero() {
            return Err(PrecompileError::Revert(
                "successor policy proposal id must be nonzero".into(),
            ));
        }
        let canonical = policy
            .encode_canonical()
            .map_err(|error| revert_codec("invalid successor V1 policy", error))?;
        let current = self.active_policy_v1()?;
        let current_hash = current
            .policy_hash()
            .map_err(|error| revert_codec("invalid current V1 policy", error))?;
        let expected_version = current
            .policy_version
            .checked_add(1)
            .ok_or_else(|| PrecompileError::Revert("V1 policy version overflow".into()))?;
        if policy.chain_id != current.chain_id || policy.genesis_hash != current.genesis_hash {
            return Err(PrecompileError::Revert(
                "successor V1 policy chain identity mismatch".into(),
            ));
        }
        if policy.attestation_mode != current.attestation_mode {
            return Err(PrecompileError::Revert(
                "successor V1 policy cannot change attestation mode".into(),
            ));
        }
        if policy.policy_version != expected_version {
            return Err(PrecompileError::Revert(
                "successor V1 policy version is not current plus one".into(),
            ));
        }
        if policy.predecessor_policy_hash != current_hash {
            return Err(PrecompileError::Revert(
                "successor V1 policy predecessor hash mismatch".into(),
            ));
        }
        if policy.activation_height <= self.storage.block_number()? {
            return Err(PrecompileError::Revert(
                "successor V1 policy activation must be in the future".into(),
            ));
        }

        let policy_hash = policy
            .policy_hash()
            .map_err(|error| revert_codec("invalid successor V1 policy", error))?;
        if self.staged_v1_policy_len.read()? != 0 {
            let staged = self.read_staged_policy_bytes_v1()?;
            if self.staged_v1_policy_proposal_id.read()? == proposal_id
                && self.staged_v1_policy_hash.read()? == policy_hash
                && staged == canonical
            {
                return Ok(());
            }
            return Err(PrecompileError::Revert(
                "another successor V1 policy is already staged".into(),
            ));
        }

        for (index, chunk) in canonical.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            let index = u32::try_from(index).map_err(|_| {
                PrecompileError::Revert("successor V1 policy has too many chunks".into())
            })?;
            self.staged_v1_policy_chunk
                .write(&index, B256::from(word))?;
        }
        let len = u32::try_from(canonical.len())
            .map_err(|_| PrecompileError::Revert("successor V1 policy is too large".into()))?;
        self.staged_v1_policy_len.write(len)?;
        self.staged_v1_policy_hash.write(policy_hash)?;
        self.staged_v1_policy_proposal_id.write(proposal_id)?;
        self.staged_v1_policy_activation_height
            .write(policy.activation_height)?;
        Ok(())
    }

    /// Returns the authenticated staged successor and its owning Update
    /// proposal, or `None` when no TEE policy update is pending.
    pub fn staged_successor_policy_v1(&self) -> Result<Option<(U256, TeePolicyV1)>> {
        let len = self.staged_v1_policy_len.read()?;
        if len == 0 {
            if !self.staged_v1_policy_hash.read()?.is_zero()
                || !self.staged_v1_policy_proposal_id.read()?.is_zero()
                || self.staged_v1_policy_activation_height.read()? != 0
            {
                return Err(PrecompileError::Fatal(
                    "empty staged V1 policy has non-empty anchors".into(),
                ));
            }
            return Ok(None);
        }
        let canonical = self.read_staged_policy_bytes_v1()?;
        let policy = TeePolicyV1::decode_canonical(&canonical).map_err(|error| {
            PrecompileError::Fatal(format!("stored staged V1 policy is non-canonical: {error}"))
        })?;
        let policy_hash = policy.policy_hash().map_err(|error| {
            PrecompileError::Fatal(format!("stored staged V1 policy cannot be hashed: {error}"))
        })?;
        if policy_hash != self.staged_v1_policy_hash.read()? {
            return Err(PrecompileError::Fatal(
                "stored staged V1 policy hash does not match its anchor".into(),
            ));
        }
        if policy.activation_height != self.staged_v1_policy_activation_height.read()? {
            return Err(PrecompileError::Fatal(
                "stored staged V1 policy activation does not match its anchor".into(),
            ));
        }
        let proposal_id = self.staged_v1_policy_proposal_id.read()?;
        if proposal_id.is_zero() {
            return Err(PrecompileError::Fatal(
                "stored staged V1 policy has zero proposal id".into(),
            ));
        }
        Ok(Some((proposal_id, policy)))
    }

    /// Atomically promotes the successor owned by `proposal_id` once its
    /// software-update height is reached. Exact replay after promotion is a
    /// no-op; a different or absent proposal cannot rotate policy authority.
    pub fn promote_staged_successor_policy_v1(
        &mut self,
        proposal_id: U256,
        block_number: u64,
    ) -> Result<()> {
        let Some((staged_proposal_id, policy)) = self.staged_successor_policy_v1()? else {
            if self.active_v1_policy_proposal_id.read()? == proposal_id && !proposal_id.is_zero() {
                return Ok(());
            }
            return Err(PrecompileError::Revert(
                "no successor V1 policy is staged for this update".into(),
            ));
        };
        if staged_proposal_id != proposal_id {
            return Err(PrecompileError::Revert(
                "staged successor V1 policy belongs to another update".into(),
            ));
        }
        if block_number < policy.activation_height {
            return Err(PrecompileError::Revert(
                "successor V1 policy activation height has not been reached".into(),
            ));
        }
        let current = self.active_policy_v1()?;
        let current_hash = current
            .policy_hash()
            .map_err(|error| revert_codec("invalid current V1 policy", error))?;
        if policy.attestation_mode != current.attestation_mode {
            return Err(PrecompileError::Fatal(
                "staged successor V1 policy changes attestation mode".into(),
            ));
        }
        if policy.chain_id != current.chain_id
            || policy.genesis_hash != current.genesis_hash
            || policy.predecessor_policy_hash != current_hash
            || policy.policy_version
                != current
                    .policy_version
                    .checked_add(1)
                    .ok_or_else(|| PrecompileError::Fatal("V1 policy version overflow".into()))?
        {
            return Err(PrecompileError::Fatal(
                "staged successor V1 policy no longer follows current policy".into(),
            ));
        }
        let canonical = policy.encode_canonical().map_err(|error| {
            PrecompileError::Fatal(format!("staged successor V1 policy is invalid: {error}"))
        })?;
        let policy_hash = policy.policy_hash().map_err(|error| {
            PrecompileError::Fatal(format!(
                "staged successor V1 policy cannot be hashed: {error}"
            ))
        })?;
        for (index, chunk) in canonical.chunks(32).enumerate() {
            let mut word = [0u8; 32];
            word[..chunk.len()].copy_from_slice(chunk);
            let index = u32::try_from(index).map_err(|_| {
                PrecompileError::Fatal("successor V1 policy chunk index overflow".into())
            })?;
            self.active_v1_policy_chunk
                .write(&index, B256::from(word))?;
        }
        let len = u32::try_from(canonical.len())
            .map_err(|_| PrecompileError::Fatal("successor V1 policy length overflow".into()))?;
        self.active_v1_policy_len.write(len)?;
        self.active_v1_policy_hash.write(policy_hash)?;
        self.active_v1_policy_proposal_id.write(proposal_id)?;
        self.clear_staged_successor_policy_v1()?;
        self.emit(TeePolicyActivatedV1 {
            proposalId: proposal_id,
            policyHash: policy_hash,
            policyVersion: policy.policy_version,
            activationHeight: policy.activation_height,
        })?;
        Ok(())
    }

    /// Clears a staged successor only when its exact owning Update proposal is
    /// being canceled by a newer activated protocol version.
    pub fn discard_staged_successor_policy_v1(&mut self, proposal_id: U256) -> Result<()> {
        let Some((staged_proposal_id, _)) = self.staged_successor_policy_v1()? else {
            return Ok(());
        };
        if staged_proposal_id != proposal_id {
            return Err(PrecompileError::Revert(
                "cannot discard another update's staged V1 policy".into(),
            ));
        }
        self.clear_staged_successor_policy_v1()
    }

    fn clear_staged_successor_policy_v1(&mut self) -> Result<()> {
        self.staged_v1_policy_len.write(0)?;
        self.staged_v1_policy_hash.write(B256::ZERO)?;
        self.staged_v1_policy_proposal_id.write(U256::ZERO)?;
        self.staged_v1_policy_activation_height.write(0)
    }

    /// Reads and authenticates current policy bytes from consensus storage.
    /// Calldata cannot supply or override policy authority.
    pub fn active_policy_v1(&self) -> Result<TeePolicyV1> {
        let canonical = self.read_policy_bytes_v1()?;
        let policy = TeePolicyV1::decode_canonical(&canonical).map_err(|error| {
            PrecompileError::Fatal(format!("stored V1 policy is non-canonical: {error}"))
        })?;
        if policy.chain_id != chain_id_word(self.storage.chain_id()?)
            || policy.genesis_hash != self.storage.genesis_hash()?
        {
            return Err(PrecompileError::Fatal(
                "stored V1 policy chain identity mismatch".into(),
            ));
        }
        let policy_hash = policy.policy_hash().map_err(|error| {
            PrecompileError::Fatal(format!("stored V1 policy cannot be hashed: {error}"))
        })?;
        if self.active_v1_policy_hash.read()? != policy_hash {
            return Err(PrecompileError::Fatal(
                "stored V1 policy hash does not match registry anchor".into(),
            ));
        }
        if policy.activation_height > self.storage.block_number()? {
            return Err(PrecompileError::Revert(
                "no V1 TEE policy is active at this height".into(),
            ));
        }
        Ok(policy)
    }

    fn read_policy_bytes_v1(&self) -> Result<Vec<u8>> {
        let len = usize::try_from(self.active_v1_policy_len.read()?)
            .map_err(|_| PrecompileError::Fatal("stored V1 policy length overflow".into()))?;
        if len == 0 {
            return Err(PrecompileError::Revert(
                "V1 TEE policy is not installed".into(),
            ));
        }
        if len > MAX_TEE_POLICY_BYTES {
            return Err(PrecompileError::Fatal(
                "stored V1 policy exceeds the protocol cap".into(),
            ));
        }
        let words = len.div_ceil(32);
        let mut canonical = Vec::with_capacity(words * 32);
        for index in 0..words {
            let index = u32::try_from(index)
                .map_err(|_| PrecompileError::Fatal("stored V1 policy index overflow".into()))?;
            canonical.extend_from_slice(self.active_v1_policy_chunk.read(&index)?.as_slice());
        }
        canonical.truncate(len);
        Ok(canonical)
    }

    fn read_staged_policy_bytes_v1(&self) -> Result<Vec<u8>> {
        let len = usize::try_from(self.staged_v1_policy_len.read()?).map_err(|_| {
            PrecompileError::Fatal("stored staged V1 policy length overflow".into())
        })?;
        if len == 0 {
            return Err(PrecompileError::Fatal(
                "staged V1 policy bytes requested while empty".into(),
            ));
        }
        if len > MAX_TEE_POLICY_BYTES {
            return Err(PrecompileError::Fatal(
                "stored staged V1 policy exceeds the protocol cap".into(),
            ));
        }
        let words = len.div_ceil(32);
        let mut canonical = Vec::with_capacity(words * 32);
        for index in 0..words {
            let index = u32::try_from(index).map_err(|_| {
                PrecompileError::Fatal("stored staged V1 policy index overflow".into())
            })?;
            canonical.extend_from_slice(self.staged_v1_policy_chunk.read(&index)?.as_slice());
        }
        canonical.truncate(len);
        Ok(canonical)
    }

    pub fn validator_enclave_binding_v1(
        &self,
        validator: Address,
    ) -> Result<Option<NodeEnclaveBindingV1>> {
        let node_id_hash = self.validator_v1_node_hash.read(&validator)?;
        if node_id_hash.is_zero() {
            return Ok(None);
        }
        self.node_enclave_binding_v1(node_id_hash)
    }

    pub fn node_host_enclave_binding_v1(
        &self,
        reth_p2p_public: [u8; 33],
    ) -> Result<Option<NodeEnclaveBindingV1>> {
        let node_id_hash = NodeIdV1 { reth_p2p_public }
            .node_id_hash()
            .map_err(|error| revert_codec("NodeHost P2P identity is invalid", error))?;
        self.node_enclave_binding_v1(node_id_hash)
    }

    /// Reads one V1 binding by its complete canonical node identity and rejects
    /// a profile or identity-map mismatch. This is the shared read seam for
    /// finalized-state session admission; callers do not reconstruct Registry
    /// slots or trust an address-only validator lookup.
    pub fn node_enclave_binding_for_identity_v1(
        &self,
        node_id: &NodeIdV1,
    ) -> Result<Option<NodeEnclaveBindingV1>> {
        let expected_hash = node_id
            .node_id_hash()
            .map_err(|error| revert_codec("node identity is invalid", error))?;
        let binding = self.node_host_enclave_binding_v1(node_id.reth_p2p_public)?;
        let Some(binding) = binding else {
            return Ok(None);
        };
        if binding.node_id_hash != expected_hash {
            return Err(PrecompileError::Fatal(
                "stored V1 binding identity mismatch".into(),
            ));
        }
        Ok(Some(binding))
    }

    /// Returns the exact append-only storage slots read by
    /// [`Self::node_enclave_binding_for_identity_v1`]. External light clients
    /// use this canonical plan to request one bounded MPT proof; keeping the
    /// plan beside the schema prevents a parallel hand-maintained layout.
    pub fn node_enclave_binding_storage_slots_v1(&self, node_id: &NodeIdV1) -> Result<Vec<B256>> {
        let node_hash = node_id
            .node_id_hash()
            .map_err(|error| revert_codec("node identity is invalid", error))?;
        let mut slots = Vec::with_capacity(22);
        for slot in [
            self.v1_node_enclave_id.slot(&node_hash).slot(),
            self.v1_node_binding_id.slot(&node_hash).slot(),
            self.v1_node_intent_hash.slot(&node_hash).slot(),
            self.v1_node_policy_hash.slot(&node_hash).slot(),
            self.v1_node_binding_version.slot(&node_hash).slot(),
            self.v1_node_registration_version.slot(&node_hash).slot(),
            self.v1_node_renewal_nonce.slot(&node_hash).slot(),
            self.v1_node_transition_nonce.slot(&node_hash).slot(),
            self.v1_node_valid_until.slot(&node_hash).slot(),
            self.v1_node_collateral_valid_until.slot(&node_hash).slot(),
            self.v1_node_recipient_x25519.slot(&node_hash).slot(),
            self.v1_node_attestation_ed25519.slot(&node_hash).slot(),
            self.v1_node_noise_responder_x25519.slot(&node_hash).slot(),
            self.v1_node_mrenclave.slot(&node_hash).slot(),
            self.v1_node_mrsigner.slot(&node_hash).slot(),
            self.v1_node_isv_prod_id.slot(&node_hash).slot(),
            self.v1_node_isv_svn.slot(&node_hash).slot(),
            self.v1_node_platform_tcb_status.slot(&node_hash).slot(),
            self.v1_node_verdict_hash.slot(&node_hash).slot(),
            self.v1_node_evidence_hash.slot(&node_hash).slot(),
            self.v1_node_lease_started_at.slot(&node_hash).slot(),
            self.v1_node_host_authorization_hash.slot(&node_hash).slot(),
        ] {
            slots.push(B256::from(slot.to_be_bytes::<32>()));
        }
        slots.sort_unstable();
        slots.dedup();
        Ok(slots)
    }

    /// Deterministic attestation readiness only. Full nodes do not consult the
    /// validator set; the exact compressed Reth P2P key is their node identity.
    pub fn is_node_host_enclave_ready_v1(&self, reth_p2p_public: [u8; 33]) -> Result<bool> {
        let Some(binding) = self.node_host_enclave_binding_v1(reth_p2p_public)? else {
            return Ok(false);
        };
        Ok(!binding.binding_id.is_zero()
            && !binding.enclave_id.is_zero()
            && binding.valid_until > consensus_timestamp(&self.storage)?)
    }

    /// Deterministic attestation readiness only. Consensus membership/status is a
    /// separate consumer concern, but missing, expired or key-rotated bindings
    /// are never ready.
    pub fn is_validator_enclave_ready_v1(&self, validator: Address) -> Result<bool> {
        let Some(binding) = self.validator_enclave_binding_v1(validator)? else {
            return Ok(false);
        };
        if binding.binding_id.is_zero() || binding.enclave_id.is_zero() {
            return Ok(false);
        }
        let validators = ValidatorSet::new(self.storage.clone());
        if validators.get_validator(validator)?.is_none() {
            return Ok(false);
        }
        Ok(binding.valid_until > consensus_timestamp(&self.storage)?)
    }

    fn node_enclave_binding_v1(&self, node_id_hash: B256) -> Result<Option<NodeEnclaveBindingV1>> {
        if self.v1_node_intent_hash.read(&node_id_hash)?.is_zero() {
            return Ok(None);
        }
        let isv_prod_id = checked_u16(
            self.v1_node_isv_prod_id.read(&node_id_hash)?,
            "stored V1 ISV product id",
        )?;
        let isv_svn = checked_u16(
            self.v1_node_isv_svn.read(&node_id_hash)?,
            "stored V1 ISV SVN",
        )?;
        let platform_tcb_status = checked_u8(
            self.v1_node_platform_tcb_status.read(&node_id_hash)?,
            "stored V1 Platform TCB status",
        )?;
        Ok(Some(NodeEnclaveBindingV1 {
            node_id_hash,
            enclave_id: self.v1_node_enclave_id.read(&node_id_hash)?,
            binding_id: self.v1_node_binding_id.read(&node_id_hash)?,
            intent_hash: self.v1_node_intent_hash.read(&node_id_hash)?,
            evidence_hash: self.v1_node_evidence_hash.read(&node_id_hash)?,
            policy_hash: self.v1_node_policy_hash.read(&node_id_hash)?,
            binding_version: self.v1_node_binding_version.read(&node_id_hash)?,
            registration_version: self.v1_node_registration_version.read(&node_id_hash)?,
            renewal_nonce: self.v1_node_renewal_nonce.read(&node_id_hash)?,
            transition_nonce: self.v1_node_transition_nonce.read(&node_id_hash)?,
            lease_started_at: self.v1_node_lease_started_at.read(&node_id_hash)?,
            valid_until: self.v1_node_valid_until.read(&node_id_hash)?,
            collateral_valid_until: self.v1_node_collateral_valid_until.read(&node_id_hash)?,
            recipient_x25519: self.v1_node_recipient_x25519.read(&node_id_hash)?,
            attestation_ed25519: self.v1_node_attestation_ed25519.read(&node_id_hash)?,
            noise_responder_x25519: self.v1_node_noise_responder_x25519.read(&node_id_hash)?,
            mrenclave: self.v1_node_mrenclave.read(&node_id_hash)?,
            mrsigner: self.v1_node_mrsigner.read(&node_id_hash)?,
            isv_prod_id,
            isv_svn,
            platform_tcb_status,
            verdict_hash: self.v1_node_verdict_hash.read(&node_id_hash)?,
            node_host_authorization_hash: self
                .v1_node_host_authorization_hash
                .read(&node_id_hash)?,
        }))
    }
}

#[cfg(feature = "tee-attestation-v1")]
impl TeeRegistry<'_> {
    /// Writes the independently authorized address-to-NodeHost association as
    /// the second half of initial registration. ValidatorSet membership is not
    /// consulted: key possession is not a validator role, and the ordinary
    /// ValidatorSet lifecycle remains the sole owner of that role.
    fn apply_validator_node_binding_v1(
        &mut self,
        binding: &ValidatorNodeBindingV1,
        validator_signature: &[u8; 65],
        node_signature: &[u8; 65],
    ) -> Result<V1RegistrationOutcome> {
        binding
            .validate_chain_identity(
                chain_id_word(self.storage.chain_id()?),
                self.storage.genesis_hash()?,
            )
            .map_err(|error| revert_codec("validator NodeHost binding chain mismatch", error))?;
        if !binding.verify_validator_signature(validator_signature)
            || !binding.verify_node_signature(node_signature)
        {
            return Err(PrecompileError::Revert(
                "validator NodeHost binding proof of possession is invalid".into(),
            ));
        }
        let validator = Address::from(binding.validator);
        let node = self
            .node_enclave_binding_v1(binding.node_id_hash)?
            .ok_or_else(|| {
                PrecompileError::Revert(
                    "validator NodeHost binding references an unregistered NodeHost".into(),
                )
            })?;
        if node.valid_until <= consensus_timestamp(&self.storage)? {
            return Err(PrecompileError::Revert(
                "validator NodeHost binding references an expired NodeHost".into(),
            ));
        }
        let current = self.validator_v1_node_hash.read(&validator)?;
        if current == binding.node_id_hash {
            return Ok(V1RegistrationOutcome::Idempotent);
        }
        if !current.is_zero() {
            return Err(PrecompileError::Revert(
                "validator is already bound to another NodeHost".into(),
            ));
        }
        self.validator_v1_node_hash
            .write(&validator, binding.node_id_hash)?;
        self.emit(ValidatorNodeHostBoundV1 {
            validator,
            nodeIdHash: binding.node_id_hash,
        })?;
        Ok(V1RegistrationOutcome::Created)
    }

    #[cfg(feature = "tee-attestation-v1")]
    fn require_atomic_registration_outcome_v1(
        registration: V1RegistrationOutcome,
        association: V1RegistrationOutcome,
        context: RegistrationCallerContextV1,
    ) -> Result<V1RegistrationOutcome> {
        match (registration, association, context.expired_rejoin) {
            (V1RegistrationOutcome::Created, V1RegistrationOutcome::Created, false)
            | (V1RegistrationOutcome::Created, V1RegistrationOutcome::Idempotent, true)
            | (V1RegistrationOutcome::Idempotent, V1RegistrationOutcome::Idempotent, _) => {
                Ok(registration)
            }
            _ => Err(PrecompileError::Fatal(
                "NodeHost registration and address association outcomes are inconsistent".into(),
            )),
        }
    }

    /// Emit only the artifact produced by the same purpose-bound enclave
    /// verification capability that accepted this registration. No second raw
    /// host-selected sealing request exists on the production path.
    pub(crate) fn emit_verified_onboarding_artifact_v1(
        &mut self,
        outcome: &V1OnboardingOutcome,
        node_id_hash: B256,
    ) -> Result<()> {
        if outcome.registration == V1RegistrationOutcome::Idempotent {
            return Ok(());
        }
        let artifact = outcome.artifact.as_ref().ok_or_else(|| {
            PrecompileError::Fatal(
                "created registration has no purpose-bound onboarding artifact".into(),
            )
        })?;
        let context = artifact.context;
        let expected_offer_public = self.offer_public_key()?;
        if expected_offer_public.is_zero()
            || context.chain_id != chain_id_word(self.storage.chain_id()?)
            || context.genesis_hash != self.storage.genesis_hash()?
            || context.node_id_hash != node_id_hash
            || context.tribute_offer_public != expected_offer_public.0
            || context.key_epoch != self.key_epoch()?
            || context.tribute_offer_epoch != self.tribute_offer_epoch()?
            || self.v1_node_intent_hash.read(&node_id_hash)? != context.intent_hash
            || self.v1_node_enclave_id.read(&node_id_hash)? != context.enclave_id
            || self.v1_node_recipient_x25519.read(&node_id_hash)?
                != B256::from(context.recipient_x25519)
        {
            return Err(PrecompileError::Fatal(
                "purpose-bound onboarding artifact does not match committed Registry binding"
                    .into(),
            ));
        }
        let encoded = artifact.encode_canonical().map_err(|code| {
            PrecompileError::Fatal(format!(
                "purpose-bound onboarding artifact is non-canonical: {:#06x}",
                code.code()
            ))
        })?;
        self.emit(OfferKeySealedForRegistryV1 {
            nodeIdHash: node_id_hash,
            sealedOfferKey: encoded.into(),
        })
    }

    /// Production verifier boundary. The transaction caller is part of the
    /// canonical NodeHost authorization and is checked before replay handling.
    #[allow(clippy::too_many_arguments)]
    pub fn register_enclave_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        binding: &ValidatorNodeBindingV1,
        validator_signature: &[u8; 65],
        node_binding_signature: &[u8; 65],
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        self.register_enclave_with_active_policy_v1(
            caller,
            evidence,
            node_signature,
            enclave_signature,
            binding,
            validator_signature,
            node_binding_signature,
            &policy,
        )
    }

    pub fn renew_enclave_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        self.renew_enclave_with_active_policy_v1(
            caller,
            evidence,
            node_signature,
            enclave_signature,
            &policy,
        )
    }

    pub fn replace_enclave_binding_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        self.replace_enclave_binding_with_active_policy_v1(
            caller,
            evidence,
            node_signature,
            enclave_signature,
            &policy,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_enclave_with_active_policy_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        binding: &ValidatorNodeBindingV1,
        validator_signature: &[u8; 65],
        node_binding_signature: &[u8; 65],
        policy: &TeePolicyV1,
    ) -> Result<V1RegistrationOutcome> {
        Self::require_initial_binding_evidence_target_v1(evidence, binding)?;
        let caller_context = self.require_registration_caller_v1(caller, binding)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            let registration = self.apply_evidence_mutation_with_active_policy_v1(
                AttestationOperationV1::RegisterEnclave,
                caller,
                evidence,
                node_signature,
                enclave_signature,
                policy,
            )?;
            let association = self.apply_validator_node_binding_v1(
                binding,
                validator_signature,
                node_binding_signature,
            )?;
            Self::require_atomic_registration_outcome_v1(registration, association, caller_context)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_enclave_with_onboarding_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        binding: &ValidatorNodeBindingV1,
        validator_signature: &[u8; 65],
        node_binding_signature: &[u8; 65],
        policy: &TeePolicyV1,
    ) -> Result<V1OnboardingOutcome> {
        Self::require_initial_binding_evidence_target_v1(evidence, binding)?;
        let caller_context = self.require_registration_caller_v1(caller, binding)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            let onboarding = self.apply_evidence_mutation_with_onboarding_v1(
                AttestationOperationV1::RegisterEnclave,
                caller,
                evidence,
                node_signature,
                enclave_signature,
                policy,
                true,
            )?;
            let association = self.apply_validator_node_binding_v1(
                binding,
                validator_signature,
                node_binding_signature,
            )?;
            Self::require_atomic_registration_outcome_v1(
                onboarding.registration,
                association,
                caller_context,
            )?;
            Ok(onboarding)
        })
    }

    pub(crate) fn renew_enclave_with_active_policy_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        policy: &TeePolicyV1,
    ) -> Result<V1RegistrationOutcome> {
        self.apply_evidence_mutation_with_active_policy_v1(
            AttestationOperationV1::RenewEnclave,
            caller,
            evidence,
            node_signature,
            enclave_signature,
            policy,
        )
    }

    pub(crate) fn replace_enclave_binding_with_active_policy_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        policy: &TeePolicyV1,
    ) -> Result<V1RegistrationOutcome> {
        self.apply_evidence_mutation_with_active_policy_v1(
            AttestationOperationV1::ReplaceEnclaveBinding,
            caller,
            evidence,
            node_signature,
            enclave_signature,
            policy,
        )
    }

    pub(crate) fn transition_enclave_measurement_with_staged_policy_v1(
        &mut self,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
    ) -> Result<V1RegistrationOutcome> {
        let (_, policy) = self
            .staged_successor_policy_v1()?
            .ok_or_else(|| PrecompileError::Revert("no successor V1 policy is staged".into()))?;
        if self.storage.block_number()? >= policy.activation_height {
            return Err(PrecompileError::Revert(
                "measurement rollout closes at successor policy activation".into(),
            ));
        }
        self.apply_evidence_mutation_with_active_policy_v1(
            AttestationOperationV1::TransitionEnclaveMeasurement,
            caller,
            evidence,
            node_signature,
            enclave_signature,
            &policy,
        )
    }

    fn apply_evidence_mutation_with_active_policy_v1(
        &mut self,
        expected_operation: AttestationOperationV1,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        policy: &TeePolicyV1,
    ) -> Result<V1RegistrationOutcome> {
        self.apply_evidence_mutation_with_onboarding_v1(
            expected_operation,
            caller,
            evidence,
            node_signature,
            enclave_signature,
            policy,
            false,
        )
        .map(|outcome| outcome.registration)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_evidence_mutation_with_onboarding_v1(
        &mut self,
        expected_operation: AttestationOperationV1,
        caller: Address,
        evidence: &[u8],
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        policy: &TeePolicyV1,
        issue_onboarding_artifact: bool,
    ) -> Result<V1OnboardingOutcome> {
        let decoded = AttestationEvidenceV1::decode_canonical(evidence)
            .map_err(|error| revert_codec("attestation evidence is not canonical", error))?;
        if expected_operation == AttestationOperationV1::TransitionEnclaveMeasurement {
            self.validate_transition_key_ready_proof_v1(&decoded)?;
        }
        if decoded.mode() != policy.attestation_mode {
            return Err(PrecompileError::Revert(
                "attestation evidence mode does not match the active V1 policy".into(),
            ));
        }

        let (intent, claims, evidence_hash, onboarding_artifact) = match &decoded {
            AttestationEvidenceV1::Dcap(dcap) => {
                let policy_bytes = policy.encode_canonical().map_err(|error| {
                    PrecompileError::Fatal(format!("active V1 policy cannot be encoded: {error}"))
                })?;
                let consensus_timestamp = consensus_timestamp(&self.storage)?;
                let (outcome, onboarding_artifact) = if issue_onboarding_artifact {
                    if expected_operation != AttestationOperationV1::RegisterEnclave {
                        return Err(PrecompileError::Fatal(
                            "onboarding artifact requested for a non-registration operation".into(),
                        ));
                    }
                    let offer_public = self.offer_public_key()?;
                    if offer_public.is_zero() {
                        return Err(PrecompileError::Fatal(
                            "DcapRequired registration requires the OST3 offer-key commitment"
                                .into(),
                        ));
                    }
                    let result = outbe_tee::verify_dcap_registration_and_seal_v1(
                        evidence,
                        &policy_bytes,
                        consensus_timestamp,
                        node_signature,
                        enclave_signature,
                        offer_public.0,
                        self.key_epoch()?,
                        self.tribute_offer_epoch()?,
                    )
                    .map_err(|error| {
                        PrecompileError::Fatal(format!(
                            "purpose-bound DCAP onboarding verifier is unavailable or unauthenticated: {error}"
                        ))
                    })?;
                    (result.outcome, result.artifact)
                } else {
                    (
                        outbe_tee::verify_dcap_evidence_v1(
                            evidence,
                            &policy_bytes,
                            consensus_timestamp,
                        )
                        .map_err(|error| {
                            PrecompileError::Fatal(format!(
                                "enclave-resident DCAP verifier is unavailable or unauthenticated: {error}"
                            ))
                        })?,
                        None,
                    )
                };
                let verdict = match outcome {
                    DcapVerificationOutcomeV1::Accepted(verdict) => verdict,
                    DcapVerificationOutcomeV1::Rejected(code) => {
                        return Err(PrecompileError::Revert(format!(
                            "DCAP evidence rejected with code {:#06x}",
                            code.code()
                        )))
                    }
                };
                let evidence_hash = dcap_evidence_hash_v1(evidence).map_err(|code| {
                    PrecompileError::Fatal(format!(
                        "accepted DCAP evidence cannot be hashed: {:#06x}",
                        code.code()
                    ))
                })?;
                (
                    dcap.intent.clone(),
                    VerifiedEnclaveClaimsV1::from_dcap(&verdict)?,
                    evidence_hash,
                    onboarding_artifact,
                )
            }
            AttestationEvidenceV1::GramineDirectDev(dev) => {
                if dev.dev_attestation_public != dev.intent.attestation_ed25519
                    || dev.dev_signature != *enclave_signature
                    || !dev.intent.verify_enclave_signature(&dev.dev_signature)
                {
                    return Err(PrecompileError::Revert(
                        "GramineDirectDev evidence signature does not bind the registration intent"
                            .into(),
                    ));
                }
                let evidence_hash = decoded.evidence_hash().map_err(|error| {
                    revert_codec("GramineDirectDev evidence is not canonical", error)
                })?;
                let height =
                    if expected_operation == AttestationOperationV1::TransitionEnclaveMeasurement {
                        policy.activation_height
                    } else {
                        self.storage.block_number()?
                    };
                let claims = direct_dev_claims(policy, height, evidence_hash)?;
                (dev.intent.clone(), claims, evidence_hash, None)
            }
        };
        let registration = self.apply_verified_claims_mutation_v1(VerifiedClaimsMutationV1 {
            expected_operation,
            caller: Some(caller),
            intent: &intent,
            node_signature,
            enclave_signature,
            policy,
            claims: &claims,
            evidence_hash,
        })?;
        let onboarding_artifact = if onboarding_artifact.is_some()
            || !issue_onboarding_artifact
            || registration == V1RegistrationOutcome::Idempotent
        {
            onboarding_artifact
        } else if policy.attestation_mode == AttestationMode::GramineDirectDev {
            if expected_operation != AttestationOperationV1::RegisterEnclave {
                return Err(PrecompileError::Fatal(
                    "onboarding artifact requested for a non-registration operation".into(),
                ));
            }
            let offer_public = self.offer_public_key()?;
            if offer_public.is_zero() {
                return Err(PrecompileError::Fatal(
                    "GramineDirectDev registration requires the OST3 offer-key commitment".into(),
                ));
            }
            let context = DcapOnboardingContextV1 {
                chain_id: intent.chain_id,
                genesis_hash: intent.genesis_hash,
                intent_hash: intent.intent_hash().map_err(|error| {
                    revert_codec("GramineDirectDev registration intent is invalid", error)
                })?,
                node_id_hash: intent.node_id.node_id_hash().map_err(|error| {
                    revert_codec("GramineDirectDev node identity is invalid", error)
                })?,
                enclave_id: intent.enclave_id,
                binding_id: intent.binding_id,
                policy_hash: intent.policy_hash,
                recipient_x25519: intent.recipient_x25519,
                tribute_offer_public: offer_public.0,
                key_epoch: self.key_epoch()?,
                tribute_offer_epoch: self.tribute_offer_epoch()?,
            };
            Some(
                outbe_tee::prepare_gramine_direct_dev_onboarding_artifact_v1(context).map_err(
                    |error| {
                        PrecompileError::Fatal(format!(
                            "purpose-bound GramineDirectDev onboarding artifact failed: {error}"
                        ))
                    },
                )?,
            )
        } else {
            return Err(PrecompileError::Fatal(
                "created registration has no purpose-bound onboarding artifact".into(),
            ));
        };
        Ok(V1OnboardingOutcome {
            registration,
            artifact: onboarding_artifact,
        })
    }

    pub(crate) fn validate_transition_key_ready_proof_v1(
        &self,
        evidence: &AttestationEvidenceV1,
    ) -> Result<()> {
        let AttestationEvidenceV1::Dcap(dcap) = evidence else {
            return Err(PrecompileError::Revert(
                "measurement transition requires DCAP key-ready evidence".into(),
            ));
        };
        let proof = dcap.transition_key_ready_proof.as_ref().ok_or_else(|| {
            PrecompileError::Revert("measurement transition is missing key-ready proof".into())
        })?;
        let offer_public = self.offer_public_key()?;
        if offer_public.is_zero() {
            return Err(PrecompileError::Fatal(
                "measurement transition requires the permanent offer-key commitment".into(),
            ));
        }
        proof
            .verify_for_transition(&dcap.intent, offer_public.0)
            .map_err(|error| {
                PrecompileError::Revert(format!(
                    "measurement transition key-ready proof is invalid: {error}"
                ))
            })
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_verified_claims_mutation_v1(
        &mut self,
        mutation: VerifiedClaimsMutationV1<'_>,
    ) -> Result<V1RegistrationOutcome> {
        let VerifiedClaimsMutationV1 {
            expected_operation,
            caller,
            intent,
            node_signature,
            enclave_signature,
            policy,
            claims,
            evidence_hash,
        } = mutation;
        intent
            .encode_canonical()
            .map_err(|error| revert_codec("registration intent is not canonical", error))?;
        intent
            .validate_chain_identity(
                chain_id_word(self.storage.chain_id()?),
                self.storage.genesis_hash()?,
            )
            .map_err(|error| revert_codec("registration intent chain mismatch", error))?;
        if intent.operation != expected_operation
            || intent.attestation_mode != policy.attestation_mode
        {
            return Err(PrecompileError::Revert(
                "attestation intent operation or mode does not match the registry mutator".into(),
            ));
        }
        let policy_hash = policy
            .policy_hash()
            .map_err(|error| revert_codec("active V1 policy is invalid", error))?;
        let anchored_policy_hash =
            if expected_operation == AttestationOperationV1::TransitionEnclaveMeasurement {
                self.staged_v1_policy_hash.read()?
            } else {
                self.active_v1_policy_hash.read()?
            };
        if intent.policy_hash != policy_hash || anchored_policy_hash != policy_hash {
            return Err(PrecompileError::Revert(
                "registration intent does not bind the authoritative V1 policy".into(),
            ));
        }
        if intent
            .derived_enclave_id()
            .map_err(|error| revert_codec("registration enclave identity is invalid", error))?
            != intent.enclave_id
        {
            return Err(PrecompileError::Revert(
                "registration enclave id is not derived from its persistent keys".into(),
            ));
        }
        if !intent.verify_node_signature(node_signature) {
            return Err(PrecompileError::Revert(
                "node proof of possession is invalid".into(),
            ));
        }
        if !intent.verify_enclave_signature(enclave_signature) {
            return Err(PrecompileError::Revert(
                "enclave proof of possession is invalid".into(),
            ));
        }

        let height = if expected_operation == AttestationOperationV1::TransitionEnclaveMeasurement {
            policy.activation_height
        } else {
            self.storage.block_number()?
        };
        if policy.measurement_rule_match_count(
            claims.mrenclave,
            claims.mrsigner,
            claims.isv_prod_id,
            claims.isv_svn,
            height,
        ) != 1
        {
            return Err(PrecompileError::Revert(
                "verified enclave claims must match exactly one active profile measurement rule"
                    .into(),
            ));
        }
        let platform_requires_advisory_policy = matches!(
            claims.platform_tcb_status,
            status
                if status == DcapPlatformTcbStatusV1::SWHardeningNeeded as u8
                    || status
                        == DcapPlatformTcbStatusV1::ConfigurationAndSWHardeningNeeded as u8
        );
        if policy.attestation_mode == AttestationMode::DcapRequired
            && platform_requires_advisory_policy
            && policy.accepted_platform_tcb_statuses
                != PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded
        {
            return Err(PrecompileError::Revert(
                "QVL Platform TCB status is stricter than active policy allows".into(),
            ));
        }

        let now = consensus_timestamp(&self.storage)?;
        let node_id_hash = intent
            .node_id
            .node_id_hash()
            .map_err(|error| revert_codec("node identity is invalid", error))?;
        if expected_operation != AttestationOperationV1::RegisterEnclave {
            if let Some(caller) = caller {
                self.require_associated_caller_v1(caller, node_id_hash)?;
            }
        }
        let intent_hash = intent
            .intent_hash()
            .map_err(|error| revert_codec("registration intent is invalid", error))?;
        let current_intent_hash = self.v1_node_intent_hash.read(&node_id_hash)?;
        if !current_intent_hash.is_zero() && current_intent_hash == intent_hash {
            if self.v1_node_evidence_hash.read(&node_id_hash)? != evidence_hash {
                return Err(PrecompileError::Revert(
                    "registry mutation is not an exact evidence replay".into(),
                ));
            }
            if self.v1_node_binding_id.read(&node_id_hash)? != intent.binding_id
                || self.v1_node_enclave_id.read(&node_id_hash)? != intent.enclave_id
            {
                return Err(PrecompileError::Fatal(
                    "stored V1 idempotency identity is inconsistent".into(),
                ));
            }
            return Ok(V1RegistrationOutcome::Idempotent);
        }

        let current = self.node_enclave_binding_v1(node_id_hash)?;
        match expected_operation {
            AttestationOperationV1::RegisterEnclave => {
                if let Some(current) = current.as_ref() {
                    if now < current.valid_until {
                        return Err(PrecompileError::Revert(
                            "live enclave binding must renew instead of rejoin".into(),
                        ));
                    }
                    if B256::from(intent.node_host_authorization_hash)
                        != current.node_host_authorization_hash
                    {
                        return Err(PrecompileError::Revert(
                            "expired rejoin changes the persistent NodeHost authorization".into(),
                        ));
                    }
                    if intent.binding_version
                        != next_counter(current.binding_version, "binding version")?
                        || intent.registration_version
                            != next_counter(current.registration_version, "registration version")?
                        || intent.renewal_nonce != current.renewal_nonce
                        || intent.transition_nonce != current.transition_nonce
                    {
                        return Err(PrecompileError::Revert(
                            "expired rejoin does not carry the exact next registration versions"
                                .into(),
                        ));
                    }
                } else if intent.binding_version != 1
                    || intent.registration_version != 0
                    || intent.renewal_nonce != 0
                    || intent.transition_nonce != 0
                {
                    return Err(PrecompileError::Revert(
                        "initial registration versions and nonces are not canonical".into(),
                    ));
                }
            }
            AttestationOperationV1::RenewEnclave => {
                let current = current.as_ref().ok_or_else(|| {
                    PrecompileError::Revert("cannot renew a missing enclave binding".into())
                })?;
                ensure_continuous_binding(current, intent, claims)?;
                if intent.binding_version != current.binding_version
                    || intent.registration_version
                        != next_counter(current.registration_version, "registration version")?
                    || intent.renewal_nonce != next_counter(current.renewal_nonce, "renewal nonce")?
                    || intent.transition_nonce != current.transition_nonce
                {
                    return Err(PrecompileError::Revert(
                        "renewal does not carry the exact next renewal version and nonce".into(),
                    ));
                }
                ensure_renewal_window(current, policy, now)?;
            }
            AttestationOperationV1::ReplaceEnclaveBinding => {
                let current = current.as_ref().ok_or_else(|| {
                    PrecompileError::Revert("cannot replace a missing enclave binding".into())
                })?;
                ensure_live_binding(current, now)?;
                if B256::from(intent.node_host_authorization_hash)
                    != current.node_host_authorization_hash
                {
                    return Err(PrecompileError::Revert(
                        "replacement changes the persistent NodeHost authorization".into(),
                    ));
                }
                if intent.enclave_id == current.enclave_id
                    || intent.binding_id == current.binding_id
                {
                    return Err(PrecompileError::Revert(
                        "replacement must use a fresh enclave and binding id".into(),
                    ));
                }
                if intent.binding_version
                    != next_counter(current.binding_version, "binding version")?
                    || intent.registration_version
                        != next_counter(current.registration_version, "registration version")?
                    || intent.renewal_nonce != current.renewal_nonce
                    || intent.transition_nonce != current.transition_nonce
                {
                    return Err(PrecompileError::Revert(
                        "replacement does not carry the exact next binding version".into(),
                    ));
                }
            }
            AttestationOperationV1::TransitionEnclaveMeasurement => {
                let current = current.as_ref().ok_or_else(|| {
                    PrecompileError::Revert("cannot transition a missing enclave binding".into())
                })?;
                ensure_live_binding(current, now)?;
                if B256::from(intent.node_host_authorization_hash)
                    != current.node_host_authorization_hash
                {
                    return Err(PrecompileError::Revert(
                        "measurement transition changes the persistent NodeHost authorization"
                            .into(),
                    ));
                }
                if intent.enclave_id == current.enclave_id
                    || intent.binding_id == current.binding_id
                {
                    return Err(PrecompileError::Revert(
                        "measurement transition must use a fresh enclave and binding id".into(),
                    ));
                }
                if intent.binding_version
                    != next_counter(current.binding_version, "binding version")?
                    || intent.registration_version
                        != next_counter(current.registration_version, "registration version")?
                    || intent.renewal_nonce != current.renewal_nonce
                    || intent.transition_nonce
                        != next_counter(current.transition_nonce, "transition nonce")?
                {
                    return Err(PrecompileError::Revert(
                        "measurement transition does not carry the exact next versions and nonce"
                            .into(),
                    ));
                }
            }
        }

        if expected_operation == AttestationOperationV1::RenewEnclave {
            let current = current.as_ref().ok_or_else(|| {
                PrecompileError::Fatal("renewal binding disappeared during validation".into())
            })?;
            let expected_deadline = current
                .valid_until
                .checked_add(policy.maximum_lease)
                .ok_or_else(|| PrecompileError::Revert("renewal deadline overflows u64".into()))?;
            if intent.requested_valid_until != expected_deadline {
                return Err(PrecompileError::Revert(
                    "renewal must extend exactly one lease period from the current deadline".into(),
                ));
            }
        } else {
            let lease = intent
                .requested_valid_until
                .checked_sub(now)
                .ok_or_else(|| {
                    PrecompileError::Revert("requested lease is already expired".into())
                })?;
            if lease < policy.minimum_lease || lease > policy.maximum_lease {
                return Err(PrecompileError::Revert(
                    "requested lease is outside active policy bounds".into(),
                ));
            }
        }
        if policy.attestation_mode == AttestationMode::DcapRequired {
            let collateral_limit = claims
                .collateral_valid_until
                .checked_sub(policy.collateral_margin)
                .ok_or_else(|| {
                    PrecompileError::Revert(
                        "verified collateral leaves no mandatory safety margin".into(),
                    )
                })?;
            if intent.requested_valid_until > collateral_limit {
                return Err(PrecompileError::Revert(
                    "requested lease exceeds verified collateral validity".into(),
                ));
            }
        }
        let enclave_owner = self.v1_enclave_node_hash.read(&intent.enclave_id)?;
        let binding_owner = self.v1_binding_node_hash.read(&intent.binding_id)?;
        match expected_operation {
            AttestationOperationV1::RegisterEnclave => {
                if let Some(current) = current.as_ref() {
                    if self.v1_enclave_node_hash.read(&current.enclave_id)? != node_id_hash
                        || self.v1_binding_node_hash.read(&current.binding_id)? != node_id_hash
                    {
                        return Err(PrecompileError::Fatal(
                            "expired rejoin found inconsistent current reverse ownership".into(),
                        ));
                    }
                    let same_current_enclave = intent.enclave_id == current.enclave_id;
                    if (same_current_enclave && enclave_owner != node_id_hash)
                        || (!same_current_enclave && !enclave_owner.is_zero())
                    {
                        return Err(PrecompileError::Revert(
                            "expired rejoin enclave is not current or globally fresh".into(),
                        ));
                    }
                    if !binding_owner.is_zero() {
                        return Err(PrecompileError::Revert(
                            "expired rejoin binding id has already been used".into(),
                        ));
                    }
                } else {
                    if !enclave_owner.is_zero() {
                        return Err(PrecompileError::Revert(
                            "enclave is already bound to another node".into(),
                        ));
                    }
                    if !binding_owner.is_zero() {
                        return Err(PrecompileError::Revert(
                            "binding id has already been used by another node".into(),
                        ));
                    }
                }
            }
            AttestationOperationV1::RenewEnclave => {
                if enclave_owner != node_id_hash || binding_owner != node_id_hash {
                    return Err(PrecompileError::Fatal(
                        "stored V1 renewal reverse ownership is inconsistent".into(),
                    ));
                }
            }
            AttestationOperationV1::ReplaceEnclaveBinding
            | AttestationOperationV1::TransitionEnclaveMeasurement => {
                if !enclave_owner.is_zero() || !binding_owner.is_zero() {
                    return Err(PrecompileError::Revert(
                        "successor enclave or binding id has already been used".into(),
                    ));
                }
            }
        }

        let recipient = B256::from(intent.recipient_x25519);
        let attestation = B256::from(intent.attestation_ed25519);
        let noise = B256::from(intent.noise_responder_x25519);

        self.v1_node_enclave_id
            .write(&node_id_hash, intent.enclave_id)?;
        self.v1_enclave_node_hash
            .write(&intent.enclave_id, node_id_hash)?;
        self.v1_node_binding_id
            .write(&node_id_hash, intent.binding_id)?;
        self.v1_binding_node_hash
            .write(&intent.binding_id, node_id_hash)?;
        self.v1_node_intent_hash.write(&node_id_hash, intent_hash)?;
        self.v1_node_evidence_hash
            .write(&node_id_hash, evidence_hash)?;
        self.v1_node_policy_hash.write(&node_id_hash, policy_hash)?;
        self.v1_node_binding_version
            .write(&node_id_hash, intent.binding_version)?;
        self.v1_node_registration_version
            .write(&node_id_hash, intent.registration_version)?;
        self.v1_node_renewal_nonce
            .write(&node_id_hash, intent.renewal_nonce)?;
        self.v1_node_transition_nonce
            .write(&node_id_hash, intent.transition_nonce)?;
        self.v1_node_lease_started_at.write(&node_id_hash, now)?;
        self.v1_node_valid_until
            .write(&node_id_hash, intent.requested_valid_until)?;
        self.v1_node_collateral_valid_until
            .write(&node_id_hash, claims.collateral_valid_until)?;
        self.v1_node_recipient_x25519
            .write(&node_id_hash, recipient)?;
        self.v1_node_attestation_ed25519
            .write(&node_id_hash, attestation)?;
        self.v1_node_noise_responder_x25519
            .write(&node_id_hash, noise)?;
        self.v1_node_mrenclave
            .write(&node_id_hash, claims.mrenclave)?;
        self.v1_node_mrsigner
            .write(&node_id_hash, claims.mrsigner)?;
        self.v1_node_isv_prod_id
            .write(&node_id_hash, u64::from(claims.isv_prod_id))?;
        self.v1_node_isv_svn
            .write(&node_id_hash, u64::from(claims.isv_svn))?;
        self.v1_node_platform_tcb_status
            .write(&node_id_hash, u64::from(claims.platform_tcb_status))?;
        self.v1_node_verdict_hash
            .write(&node_id_hash, claims.verdict_hash)?;
        self.v1_node_host_authorization_hash.write(
            &node_id_hash,
            B256::from(intent.node_host_authorization_hash),
        )?;

        match expected_operation {
            AttestationOperationV1::RegisterEnclave => self.emit(EnclaveRegisteredV1 {
                nodeIdHash: node_id_hash,
                enclaveId: intent.enclave_id,
                bindingId: intent.binding_id,
                validUntil: intent.requested_valid_until,
                bindingVersion: intent.binding_version,
            })?,
            AttestationOperationV1::RenewEnclave => self.emit(EnclaveRenewedV1 {
                nodeIdHash: node_id_hash,
                enclaveId: intent.enclave_id,
                bindingId: intent.binding_id,
                validUntil: intent.requested_valid_until,
                registrationVersion: intent.registration_version,
                renewalNonce: intent.renewal_nonce,
            })?,
            AttestationOperationV1::ReplaceEnclaveBinding => {
                self.emit(EnclaveBindingReplacedV1 {
                    nodeIdHash: node_id_hash,
                    enclaveId: intent.enclave_id,
                    bindingId: intent.binding_id,
                    validUntil: intent.requested_valid_until,
                    bindingVersion: intent.binding_version,
                })?
            }
            AttestationOperationV1::TransitionEnclaveMeasurement => {
                self.emit(EnclaveMeasurementTransitionedV1 {
                    nodeIdHash: node_id_hash,
                    enclaveId: intent.enclave_id,
                    bindingId: intent.binding_id,
                    policyHash: policy_hash,
                    validUntil: intent.requested_valid_until,
                    bindingVersion: intent.binding_version,
                    transitionNonce: intent.transition_nonce,
                })?
            }
        }
        Ok(V1RegistrationOutcome::Created)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn apply_verified_mutation_v1(
        &mut self,
        expected_operation: AttestationOperationV1,
        caller: Option<Address>,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        policy: &TeePolicyV1,
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        let claims = VerifiedEnclaveClaimsV1::from_dcap(&capability.verdict)?;
        self.apply_verified_claims_mutation_v1(VerifiedClaimsMutationV1 {
            expected_operation,
            caller,
            intent,
            node_signature,
            enclave_signature,
            policy,
            claims: &claims,
            evidence_hash: capability.evidence_hash,
        })
    }

    #[cfg(test)]
    pub(crate) fn register_enclave_after_verifier_for_test(
        &mut self,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        self.apply_verified_mutation_v1(
            AttestationOperationV1::RegisterEnclave,
            None,
            intent,
            node_signature,
            enclave_signature,
            &policy,
            capability,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_enclave_and_bind_after_verifier_for_test(
        &mut self,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        binding: &ValidatorNodeBindingV1,
        validator_signature: &[u8; 65],
        node_binding_signature: &[u8; 65],
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        self.register_enclave_and_bind_after_verifier_for_test_as(
            Address::from(binding.validator),
            intent,
            node_signature,
            enclave_signature,
            binding,
            validator_signature,
            node_binding_signature,
            capability,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_enclave_and_bind_after_verifier_for_test_as(
        &mut self,
        caller: Address,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        binding: &ValidatorNodeBindingV1,
        validator_signature: &[u8; 65],
        node_binding_signature: &[u8; 65],
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        Self::require_initial_binding_target_v1(intent, binding)?;
        let caller_context = self.require_registration_caller_v1(caller, binding)?;
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            let registration = self.apply_verified_mutation_v1(
                AttestationOperationV1::RegisterEnclave,
                Some(caller),
                intent,
                node_signature,
                enclave_signature,
                &policy,
                capability,
            )?;
            let association = self.apply_validator_node_binding_v1(
                binding,
                validator_signature,
                node_binding_signature,
            )?;
            Self::require_atomic_registration_outcome_v1(registration, association, caller_context)
        })
    }

    #[cfg(test)]
    pub(crate) fn renew_enclave_after_verifier_for_test(
        &mut self,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        self.apply_verified_mutation_v1(
            AttestationOperationV1::RenewEnclave,
            None,
            intent,
            node_signature,
            enclave_signature,
            &policy,
            capability,
        )
    }

    #[cfg(test)]
    pub(crate) fn renew_enclave_after_verifier_for_test_as(
        &mut self,
        caller: Address,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        self.apply_verified_mutation_v1(
            AttestationOperationV1::RenewEnclave,
            Some(caller),
            intent,
            node_signature,
            enclave_signature,
            &policy,
            capability,
        )
    }

    #[cfg(test)]
    pub(crate) fn renew_enclave_after_verifier_with_active_policy_for_test(
        &mut self,
        caller: Address,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        policy: &TeePolicyV1,
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        self.apply_verified_mutation_v1(
            AttestationOperationV1::RenewEnclave,
            Some(caller),
            intent,
            node_signature,
            enclave_signature,
            policy,
            capability,
        )
    }

    #[cfg(test)]
    pub(crate) fn replace_enclave_binding_after_verifier_for_test(
        &mut self,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        let policy = self.active_policy_v1()?;
        self.apply_verified_mutation_v1(
            AttestationOperationV1::ReplaceEnclaveBinding,
            None,
            intent,
            node_signature,
            enclave_signature,
            &policy,
            capability,
        )
    }

    #[cfg(test)]
    pub(crate) fn replace_enclave_binding_after_verifier_with_active_policy_for_test(
        &mut self,
        caller: Address,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        policy: &TeePolicyV1,
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        self.apply_verified_mutation_v1(
            AttestationOperationV1::ReplaceEnclaveBinding,
            Some(caller),
            intent,
            node_signature,
            enclave_signature,
            policy,
            capability,
        )
    }

    #[cfg(test)]
    pub(crate) fn transition_enclave_measurement_after_verifier_for_test(
        &mut self,
        caller: Address,
        intent: &RegistrationIntentV1,
        node_signature: &[u8; 65],
        enclave_signature: &[u8; 64],
        capability: PostVerifierDcapCapabilityV1,
    ) -> Result<V1RegistrationOutcome> {
        let (_, policy) = self
            .staged_successor_policy_v1()?
            .ok_or_else(|| PrecompileError::Revert("no successor V1 policy is staged".into()))?;
        if self.storage.block_number()? >= policy.activation_height {
            return Err(PrecompileError::Revert(
                "measurement rollout closes at successor policy activation".into(),
            ));
        }
        self.apply_verified_mutation_v1(
            AttestationOperationV1::TransitionEnclaveMeasurement,
            Some(caller),
            intent,
            node_signature,
            enclave_signature,
            &policy,
            capability,
        )
    }
}

#[cfg(feature = "tee-attestation-v1")]
fn ensure_continuous_binding(
    current: &NodeEnclaveBindingV1,
    intent: &RegistrationIntentV1,
    claims: &VerifiedEnclaveClaimsV1,
) -> Result<()> {
    if intent.enclave_id != current.enclave_id
        || intent.binding_id != current.binding_id
        || B256::from(intent.recipient_x25519) != current.recipient_x25519
        || B256::from(intent.attestation_ed25519) != current.attestation_ed25519
        || B256::from(intent.noise_responder_x25519) != current.noise_responder_x25519
        || B256::from(intent.node_host_authorization_hash) != current.node_host_authorization_hash
    {
        return Err(PrecompileError::Revert(
            "renewal targets a superseded or different enclave identity".into(),
        ));
    }
    if claims.mrenclave != current.mrenclave
        || claims.mrsigner != current.mrsigner
        || claims.isv_prod_id != current.isv_prod_id
        || claims.isv_svn != current.isv_svn
    {
        return Err(PrecompileError::Revert(
            "renewal cannot replace the admitted enclave measurement".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "tee-attestation-v1")]
fn direct_dev_claims(
    policy: &TeePolicyV1,
    height: u64,
    evidence_hash: B256,
) -> Result<VerifiedEnclaveClaimsV1> {
    let mut matching = policy.measurement_rules.iter().filter(|rule| {
        height >= rule.admit_from_height && height < rule.admit_until_height_exclusive
    });
    let rule = matching.next().ok_or_else(|| {
        PrecompileError::Revert(
            "GramineDirectDev policy has no active measurement projection".into(),
        )
    })?;
    if matching.next().is_some() {
        return Err(PrecompileError::Revert(
            "GramineDirectDev policy has overlapping measurement projections".into(),
        ));
    }
    Ok(VerifiedEnclaveClaimsV1 {
        mrenclave: rule.mrenclave,
        mrsigner: rule.mrsigner,
        isv_prod_id: rule.isv_prod_id,
        isv_svn: rule.minimum_isv_svn,
        collateral_valid_until: u64::MAX,
        platform_tcb_status: 0,
        verdict_hash: evidence_hash,
    })
}

#[cfg(feature = "tee-attestation-v1")]
fn next_counter(current: u64, name: &'static str) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| PrecompileError::Revert(format!("{name} is exhausted")))
}

#[cfg(feature = "tee-attestation-v1")]
fn ensure_live_binding(current: &NodeEnclaveBindingV1, now: u64) -> Result<()> {
    if now >= current.valid_until {
        return Err(PrecompileError::Revert(
            "enclave lease expired; registerEnclave rejoin is required".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "tee-attestation-v1")]
fn ensure_renewal_window(
    current: &NodeEnclaveBindingV1,
    policy: &TeePolicyV1,
    now: u64,
) -> Result<()> {
    ensure_live_binding(current, now)?;
    if policy.maximum_lease == 0 || !policy.maximum_lease.is_multiple_of(2) {
        return Err(PrecompileError::Fatal(
            "active V1 lease period is not a positive even duration".into(),
        ));
    }
    let opens_at = current.valid_until.saturating_sub(policy.maximum_lease / 2);
    if now < opens_at {
        return Err(PrecompileError::Revert(
            "renewal window has not opened".into(),
        ));
    }
    Ok(())
}

/// Test-only typed capability that begins strictly after public QVL verification.
/// It is absent from every non-test artifact and cannot parse or bless evidence.
#[cfg(all(test, feature = "tee-attestation-v1"))]
pub(crate) struct PostVerifierDcapCapabilityV1 {
    verdict: DcapVerdictV1,
    evidence_hash: B256,
}

#[cfg(all(test, feature = "tee-attestation-v1"))]
impl PostVerifierDcapCapabilityV1 {
    pub(crate) fn new(verdict: DcapVerdictV1) -> Self {
        Self {
            verdict,
            evidence_hash: B256::repeat_byte(0xEC),
        }
    }

    pub(crate) fn with_evidence_hash(verdict: DcapVerdictV1, evidence_hash: B256) -> Self {
        Self {
            verdict,
            evidence_hash,
        }
    }
}

fn chain_id_word(chain_id: u64) -> [u8; 32] {
    U256::from(chain_id).to_be_bytes()
}

fn consensus_timestamp(storage: &outbe_primitives::storage::StorageHandle<'_>) -> Result<u64> {
    u64::try_from(storage.timestamp()?)
        .map_err(|_| PrecompileError::Revert("consensus timestamp exceeds u64".into()))
}

fn checked_u16(value: u64, field: &'static str) -> Result<u16> {
    u16::try_from(value)
        .map_err(|_| PrecompileError::Fatal(format!("{field} exceeds its canonical width")))
}

fn checked_u8(value: u64, field: &'static str) -> Result<u8> {
    u8::try_from(value)
        .map_err(|_| PrecompileError::Fatal(format!("{field} exceeds its canonical width")))
}

fn revert_codec(context: &'static str, error: impl std::fmt::Display) -> PrecompileError {
    PrecompileError::Revert(format!("{context}: {error}"))
}
