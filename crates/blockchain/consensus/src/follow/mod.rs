//! Lightweight follower: cold-sync finalized blocks from an upstream node and
//! verify them against the chain's committee, WITHOUT running consensus.
//!
//! **Trust model - committee-chaining.** outbe's finalize certificate is an
//! atomic aggregate of individual MinPk votes and a mandatory MinSig threshold
//! VRF proof over a *committee-bound* namespace. Both are verified with the
//! epoch-scoped committee material, which changes on every reshare. A follower
//! therefore:
//!
//! 1. anchors the START epoch's committee on the **genesis validator MinPk
//!    set**, read from the follower's OWN genesis state - the trust root;
//!    nothing the operator must provide;
//! 2. reads each later epoch's committee from a `CommitteePreAnnounce` in the
//!    previous epoch's last finalized block, verifies that block with the already
//!    trusted previous committee, and only then installs the next verifier.
//!
//! All inputs are public on-chain data carried in the boundary block
//! `extra_data` (the full DKG [`Output`] - players + polynomial); the follower
//! never holds any DKG secret. [`CommitteeChain`] implements this chaining; it
//! is exercised by `phase0_spike_*` (the de-risk gate) and the tests below.

use std::collections::BTreeMap;

use alloy_primitives::{keccak256, B256};
use commonware_consensus::{simplex::types::Finalization, types::Epoch};
use commonware_cryptography::bls12381;
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_parallel::Sequential;
use commonware_utils::ordered::Set;
use eyre::{bail, Result};

use crate::digest::Digest;
use crate::hybrid::{
    bls_batch_verification_rng, HybridScheme, HybridSchemeProvider, VrfMaterialProvider,
};

mod driver;
pub mod engine;
mod epocher;
mod resolver;
mod stubs;
pub mod upstream;

pub use engine::{run_follow_engine, FollowEngineConfig};
pub use epocher::FollowerEpocher;
pub use upstream::{
    decode_public_finalization, decode_public_finalized_block, CertifiedFinalizedBlock,
    FinalizedSource, LocalBlockSource, PublicFinalizedBlockDecodeError, TipSource,
};

/// Builds and chains per-epoch finalization verifiers from finalized boundary
/// blocks, anchored on the trusted genesis committee. Verifiers are kept in a
/// [`HybridSchemeProvider`] keyed by epoch - the same provider type the live
/// stack uses - so cert verification is byte-identical to the validator path.
///
/// **Trust root.** Consensus finality is a multisig over the committee's
/// individual MinPk keys. The mandatory MinSig VRF proof supplies the finalized
/// round seed but is not the committee identity authenticator. So the anchor is the **genesis validator
/// MinPk set**, read from the follower's OWN genesis state - not a VRF group
/// key, and nothing the operator has to provide. The start epoch's committee
/// (`output.players()`) must equal this set; each later epoch's committee is
/// trusted via the finalized-boundary chain.
pub struct CommitteeChain {
    /// The start epoch the anchor is rooted at (genesis = 0).
    anchor_epoch: Epoch,
    /// The trusted start-epoch committee: the genesis validator MinPk keys.
    anchor_participants: Set<bls12381::PublicKey>,
    scheme_provider: HybridSchemeProvider<MinSig>,
    /// Highest epoch whose committee verifier has been registered.
    highest_registered: Option<Epoch>,
    /// Exact authenticated outcome hash by epoch. Repeated pre-announces are
    /// idempotent; a conflicting outcome can never replace trusted material.
    outcome_hashes: BTreeMap<u64, B256>,
}

impl CommitteeChain {
    /// Create a chain anchored on the trusted genesis committee
    /// (`anchor_participants` = the genesis validator MinPk set, read from the
    /// follower's genesis state) at `anchor_epoch` (0 for a genesis anchor).
    pub fn new(anchor_epoch: Epoch, anchor_participants: Set<bls12381::PublicKey>) -> Self {
        Self {
            anchor_epoch,
            anchor_participants,
            scheme_provider: HybridSchemeProvider::new(),
            highest_registered: None,
            outcome_hashes: BTreeMap::new(),
        }
    }

    /// The epoch the anchor is rooted at (the first epoch the follower can verify).
    pub fn anchor_epoch(&self) -> u64 {
        self.anchor_epoch.get()
    }

    /// The per-epoch verifier provider, ready to hand to cert-verification paths.
    pub fn scheme_provider(&self) -> &HybridSchemeProvider<MinSig> {
        &self.scheme_provider
    }

    /// Highest epoch whose verifier is registered, if any.
    pub fn highest_registered(&self) -> Option<Epoch> {
        self.highest_registered
    }

    /// Register epoch `epoch`'s committee verifier from its finalized boundary
    /// `outcome` bytes (the ODKO-wrapped DKG output in the boundary block's
    /// `extra_data`).
    ///
    /// For the anchor epoch (`epoch == anchor.from_epoch`) the committee's group
    /// key MUST equal the trusted anchor identity - this is the trust root. For
    /// later epochs the caller is responsible for only registering committees
    /// from boundary blocks it has already verified as finalized by the prior
    /// (trusted) committee (the chaining link).
    ///
    /// Returns the epoch's ordered participant set.
    pub fn register_epoch_from_outcome(
        &mut self,
        epoch: Epoch,
        outcome: &[u8],
    ) -> Result<Set<bls12381::PublicKey>> {
        let output = crate::dkg_manager::decode_boundary_outcome(outcome)
            .ok_or_else(|| eyre::eyre!("boundary outcome is not a decodable full DKG output"))?;
        let encoded_epoch = u64::from_be_bytes(
            outcome[5..13]
                .try_into()
                .expect("a decoded ODKO outcome contains its fixed epoch field"),
        );
        if encoded_epoch != epoch.get() {
            bail!(
                "boundary outcome epoch label {} does not match registered epoch {}",
                encoded_epoch,
                epoch.get()
            );
        }
        let participants = output.players().clone();
        let polynomial = output.public().clone();
        let outcome_hash = keccak256(outcome);

        if let Some(existing) = self.outcome_hashes.get(&epoch.get()) {
            if *existing != outcome_hash {
                bail!(
                    "conflicting committee outcome replay for epoch {}",
                    epoch.get()
                );
            }
            return Ok(participants);
        }

        if let Some(highest) = self.highest_registered {
            let expected = highest.get().saturating_add(1);
            if epoch.get() != expected {
                bail!(
                    "committee epoch {} is not sequential after authenticated epoch {}",
                    epoch.get(),
                    highest.get()
                );
            }
        } else if epoch != self.anchor_epoch {
            bail!(
                "first registered committee epoch {} is not anchor epoch {}",
                epoch.get(),
                self.anchor_epoch.get()
            );
        }

        // Trust root: the anchor epoch's committee MUST be the trusted genesis
        // validator set. Consensus finality is a multisig over these MinPk keys,
        // so matching the participant set (NOT the VRF group key) authenticates
        // the committee. Compare as ordered sets (both pubkey-sorted).
        if epoch == self.anchor_epoch && participants != self.anchor_participants {
            bail!(
                "anchor mismatch: start-epoch {} committee ({} validators) does not match the \
                 trusted genesis validator set ({} validators)",
                epoch.get(),
                participants.len(),
                self.anchor_participants.len(),
            );
        }

        // The follower is anchored at genesis epoch/version 0, and every
        // successful DKG activation increments both counters exactly once.
        // Restore the authenticated epoch's material version explicitly:
        // `HybridScheme::verifier` defaults it to zero, which verifies the BLS
        // certificate but produces a non-canonical committee_set_hash_v2 after
        // epoch 0.
        let vrf_materials = VrfMaterialProvider::new(epoch.get(), polynomial, None);
        let verifier = HybridScheme::<MinSig>::verifier_with_vrf_provider(
            &crate::config::outbe_app_namespace(),
            participants.clone(),
            vrf_materials,
        )
        .ok_or_else(|| {
            eyre::eyre!(
                "failed to build committee verifier for epoch {}",
                epoch.get()
            )
        })?;
        self.scheme_provider.register(epoch, verifier);
        self.outcome_hashes.insert(epoch.get(), outcome_hash);
        self.highest_registered = Some(match self.highest_registered {
            Some(h) => h.max(epoch),
            None => epoch,
        });
        Ok(participants)
    }

    /// Advance the chain from a finalized block's `extra_data`, registering an
    /// epoch's committee verifier (the forward-chaining step). Returns the
    /// registered epoch, if any.
    ///
    /// Two carriers register a committee:
    /// - [`CommitteePreAnnounce`](outbe_primitives::reshare_artifact::ConsensusHeaderArtifact::CommitteePreAnnounce)
    ///   the Path A committee-chaining carrier: epoch `E`'s committee riding a
    ///   block finalized by the already-trusted `E-1` committee. This is the
    ///   authenticated path - the trust chains from genesis through each E-1.
    /// - [`BoundaryOutcome`](outbe_primitives::reshare_artifact::ConsensusHeaderArtifact::BoundaryOutcome)
    ///   the activating boundary at `E*L+1`, finalized by `E` ITSELF. We register
    ///   from it ONLY for a not-yet-known epoch (the genesis anchor; and, until the
    ///   pre-announce producer is wired, epochs lacking a pre-announce). We must NOT
    ///   let it OVERRIDE a committee already registered via its `E-1` pre-announce:
    ///   a self-finalized boundary overriding the chained committee is exactly the
    ///   D1 self-certification bug.
    ///
    /// Safe only for `extra_data` from blocks already verified as finalized by the
    /// trusted committee (the marshal enforces this via its `provider`), so the
    /// registered committee inherits that trust.
    pub fn advance_from_block_extra_data(&mut self, extra_data: &[u8]) -> Result<Option<Epoch>> {
        use outbe_primitives::reshare_artifact::ConsensusHeaderArtifact as CHA;
        let artifacts =
            outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(extra_data)
                .map_err(|e| eyre::eyre!("failed to decode block artifacts: {e:?}"))?;
        match artifacts.consensus_header_artifact {
            Some(CHA::CommitteePreAnnounce { epoch, outcome }) => {
                let epoch = Epoch::new(epoch);
                self.register_epoch_from_outcome(epoch, &outcome)?;
                Ok(Some(epoch))
            }
            Some(CHA::BoundaryOutcome(boundary)) => {
                let epoch = Epoch::new(boundary.epoch);
                if epoch == self.anchor_epoch && self.highest_registered.is_none() {
                    self.register_epoch_from_outcome(epoch, &boundary.outcome)?;
                    Ok(Some(epoch))
                } else {
                    // Later boundaries are self-finalized and never install or
                    // replace a committee. Their committee must already have been
                    // chained from an E-1 pre-announce.
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    /// Verify a finalization certificate for `epoch` against its registered
    /// committee verifier. Errors if no verifier is registered for `epoch` or the
    /// certificate fails verification.
    pub fn verify_finalization(
        &self,
        epoch: Epoch,
        finalization: &Finalization<HybridScheme<MinSig>, Digest>,
    ) -> Result<()> {
        let scheme =
            commonware_cryptography::certificate::Provider::scoped(&self.scheme_provider, epoch)
                .ok_or_else(|| {
                    eyre::eyre!("no committee verifier registered for epoch {}", epoch.get())
                })?;
        let mut rng = bls_batch_verification_rng();
        if !finalization.verify(&mut rng, scheme.as_ref(), &Sequential) {
            bail!(
                "finalization certificate failed verification for epoch {}",
                epoch.get()
            );
        }
        Ok(())
    }

    /// Drop every authenticated verifier/outcome except the current epoch.
    /// Admission streaming uses this after each verified successor so memory is
    /// independent of network age. It must only be called after the successor
    /// has been registered successfully.
    pub fn retain_only_highest(&mut self) {
        let Some(highest) = self.highest_registered else {
            return;
        };
        for epoch in self.outcome_hashes.keys().copied().collect::<Vec<_>>() {
            if epoch != highest.get() {
                self.scheme_provider.remove(&Epoch::new(epoch));
                self.outcome_hashes.remove(&epoch);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, convert::Infallible, sync::Arc};

    use alloy_primitives::Bytes;
    use commonware_codec::Encode as _;
    use commonware_consensus::marshal::store::{Blocks, Certificates};
    use commonware_consensus::simplex::types::{Finalization, Proposal, Subject};
    use commonware_consensus::types::{Epocher as _, Height, Round, View};
    use commonware_consensus::Heightable as _;
    use commonware_cryptography::certificate::Scheme as _;
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _};
    use commonware_storage::archive::Identifier;
    use commonware_utils::{
        ordered::{Quorum as _, Set as OrderedSet},
        N3f1, TryCollect as _,
    };

    /// A single committee + its DKG, used to build BOTH a boundary block's
    /// `extra_data` and a matching finalization signed by that committee. (The
    /// DKG dealing is randomized, so the boundary and the finalization MUST come
    /// from the same `Committee`.)
    struct Committee {
        keys: Vec<bls12381::PrivateKey>,
        participants: OrderedSet<bls12381::PublicKey>,
        dkg: crate::bls::ParticipantDkgBootstrapResult,
    }

    fn committee(seed_base: u8) -> Committee {
        let mut keys: Vec<bls12381::PrivateKey> = (0..4u8)
            .map(|i| bls12381::PrivateKey::from_seed((seed_base + i + 1) as u64))
            .collect();
        keys.sort_by_key(|k| k.public_key().encode());
        let participants: OrderedSet<bls12381::PublicKey> =
            keys.iter().map(|k| k.public_key()).try_collect().unwrap();
        let dkg = crate::bls::bootstrap_dkg_for_participants(participants.clone()).unwrap();
        Committee {
            keys,
            participants,
            dkg,
        }
    }

    impl Committee {
        /// The public boundary `outcome` bytes (the ODKO DKG output).
        fn outcome(&self, epoch: Epoch) -> Vec<u8> {
            crate::dkg_manager::encode_outcome(epoch, &self.dkg.output, false).to_vec()
        }

        /// A full boundary block's `extra_data` carrying this committee's outcome.
        fn boundary_block_extra_data(&self, epoch: Epoch) -> Vec<u8> {
            use outbe_primitives::reshare_artifact::{
                encode_outbe_block_artifacts, ConsensusHeaderArtifact, OutbeBlockArtifacts,
            };
            use outbe_primitives::validators::ValidatorP2pAddress;
            let vs = crate::validators::ValidatorSet {
                public_keys: self.participants.iter().cloned().collect(),
                addresses: (0..self.participants.len() as u8)
                    .map(|i| alloy_primitives::Address::repeat_byte(i + 1))
                    .collect(),
                p2p_addresses: vec![ValidatorP2pAddress::Missing; self.participants.len()],
            };
            let artifact = crate::dkg_manager::build_boundary_artifact(
                crate::dkg_manager::BoundaryArtifactInput {
                    epoch,
                    validator_set: &vs,
                    output: &self.dkg.output,
                    is_full_dkg: false,
                    dkg_cycle: 1,
                    freeze_height: 100,
                    planned_activation_height: 120,
                    vrf_material_version: 1,
                    is_validator_set_change: false,
                    tee_expired_target_exclusions: vec![],
                },
            )
            .unwrap();
            encode_outbe_block_artifacts(&OutbeBlockArtifacts {
                consensus_header_artifact: Some(ConsensusHeaderArtifact::BoundaryOutcome(artifact)),
                ..Default::default()
            })
            .unwrap()
            .to_vec()
        }

        /// An `E-1`-finalized block's `extra_data` pre-announcing this committee for
        /// `epoch` (the Path A committee-chaining carrier).
        fn preannounce_block_extra_data(&self, epoch: Epoch) -> Vec<u8> {
            use outbe_primitives::reshare_artifact::{
                encode_outbe_block_artifacts, ConsensusHeaderArtifact, OutbeBlockArtifacts,
            };
            encode_outbe_block_artifacts(&OutbeBlockArtifacts {
                consensus_header_artifact: Some(ConsensusHeaderArtifact::CommitteePreAnnounce {
                    epoch: epoch.get(),
                    outcome: alloy_primitives::Bytes::from(self.outcome(epoch)),
                }),
                ..Default::default()
            })
            .unwrap()
            .to_vec()
        }

        /// A finalization for `epoch` signed by this committee.
        fn finalization(&self, epoch: Epoch) -> Finalization<HybridScheme<MinSig>, Digest> {
            let digest = Digest::from(alloy_primitives::B256::from_slice(
                Sha256::hash(format!("blk-{}", epoch.get()).as_bytes()).as_ref(),
            ));
            self.finalization_for(epoch, digest)
        }

        fn finalization_for(
            &self,
            epoch: Epoch,
            digest: Digest,
        ) -> Finalization<HybridScheme<MinSig>, Digest> {
            let signer_indices: Vec<_> = (0..self.keys.len()).collect();
            self.finalization_for_signers(epoch, digest, &signer_indices)
        }

        fn finalization_for_signers(
            &self,
            epoch: Epoch,
            digest: Digest,
            signer_indices: &[usize],
        ) -> Finalization<HybridScheme<MinSig>, Digest> {
            let proposal = Proposal::new(Round::new(epoch, View::new(2)), View::new(1), digest);
            self.finalization_for_proposal(epoch, proposal, signer_indices)
        }

        fn finalization_for_proposal(
            &self,
            verifier_epoch: Epoch,
            proposal: Proposal<Digest>,
            signer_indices: &[usize],
        ) -> Finalization<HybridScheme<MinSig>, Digest> {
            let ns = crate::config::outbe_app_namespace();
            let verifier = HybridScheme::<MinSig>::verifier_with_vrf_provider(
                &ns,
                self.participants.clone(),
                VrfMaterialProvider::new(verifier_epoch.get(), self.dkg.polynomial.clone(), None),
            )
            .unwrap();
            let signers: Vec<HybridScheme<MinSig>> = self
                .keys
                .iter()
                .map(|key| {
                    let idx = self.participants.index(&key.public_key()).unwrap();
                    HybridScheme::signer_with_vrf_provider(
                        &ns,
                        self.participants.clone(),
                        key.clone(),
                        VrfMaterialProvider::new(
                            verifier_epoch.get(),
                            self.dkg.polynomial.clone(),
                            Some(self.dkg.shares[idx.get() as usize].clone()),
                        ),
                    )
                    .unwrap()
                })
                .collect();
            let subject = Subject::Finalize {
                proposal: &proposal,
            };
            let attestations: Vec<_> = signer_indices
                .iter()
                .map(|index| signers[*index].sign::<Digest>(subject).unwrap())
                .collect();
            let certificate = verifier
                .assemble::<_, N3f1>(attestations, &Sequential)
                .unwrap();
            Finalization {
                proposal,
                certificate,
            }
        }
    }

    #[derive(Clone, Default)]
    struct ArchivedFinalizedSource {
        by_height: Arc<BTreeMap<u64, CertifiedFinalizedBlock>>,
    }

    impl FinalizedSource for ArchivedFinalizedSource {
        fn get_finalization(
            &self,
            height: Height,
        ) -> impl std::future::Future<Output = Option<CertifiedFinalizedBlock>> + Send {
            std::future::ready(self.by_height.get(&height.get()).cloned())
        }
    }

    #[derive(Default)]
    struct MemoryCertificates {
        by_height: BTreeMap<u64, crate::marshal_types::Finalization>,
    }

    impl Certificates for MemoryCertificates {
        type BlockDigest = Digest;
        type Commitment = Digest;
        type Scheme = HybridScheme<MinSig>;
        type Error = Infallible;

        async fn put(
            &mut self,
            height: Height,
            _digest: Self::BlockDigest,
            finalization: crate::marshal_types::Finalization,
        ) -> Result<(), Self::Error> {
            self.by_height.entry(height.get()).or_insert(finalization);
            Ok(())
        }

        async fn sync(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn get(
            &self,
            id: Identifier<'_, Self::BlockDigest>,
        ) -> Result<Option<crate::marshal_types::Finalization>, Self::Error> {
            let value = match id {
                Identifier::Index(height) => self.by_height.get(&height).cloned(),
                Identifier::Key(digest) => self
                    .by_height
                    .values()
                    .find(|finalization| finalization.proposal.payload == *digest)
                    .cloned(),
            };
            Ok(value)
        }

        async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
            self.by_height.retain(|height, _| *height >= min.get());
            Ok(())
        }

        fn last_index(&self) -> Option<Height> {
            self.by_height
                .last_key_value()
                .map(|(height, _)| Height::new(*height))
        }

        fn ranges_from(&self, from: Height) -> impl Iterator<Item = (Height, Height)> {
            self.by_height
                .range(from.get()..)
                .map(|(height, _)| (Height::new(*height), Height::new(*height)))
        }
    }

    #[derive(Default)]
    struct MemoryBlocks {
        by_height: BTreeMap<u64, crate::block::ConsensusBlock>,
    }

    impl Blocks for MemoryBlocks {
        type Block = crate::block::ConsensusBlock;
        type Error = Infallible;

        async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
            self.by_height.entry(block.height().get()).or_insert(block);
            Ok(())
        }

        async fn sync(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn get(
            &self,
            id: Identifier<'_, Digest>,
        ) -> Result<Option<Self::Block>, Self::Error> {
            let value = match id {
                Identifier::Index(height) => self.by_height.get(&height).cloned(),
                Identifier::Key(digest) => self
                    .by_height
                    .values()
                    .find(|block| block.digest() == *digest)
                    .cloned(),
            };
            Ok(value)
        }

        async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
            self.by_height.retain(|height, _| *height >= min.get());
            Ok(())
        }

        fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
            let Some(last) = self.by_height.last_key_value().map(|(height, _)| *height) else {
                return Vec::new();
            };
            (start.get()..=last)
                .filter(|height| !self.by_height.contains_key(height))
                .take(max)
                .map(Height::new)
                .collect()
        }

        fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
            let current = self.by_height.contains_key(&value.get()).then_some(value);
            let next = self
                .by_height
                .range(value.get().saturating_add(1)..)
                .next()
                .map(|(height, _)| Height::new(*height));
            (current, next)
        }

        fn last_index(&self) -> Option<Height> {
            self.by_height
                .last_key_value()
                .map(|(height, _)| Height::new(*height))
        }
    }

    #[derive(Default)]
    struct DurableCrashBlocks {
        durable: BTreeMap<u64, crate::block::ConsensusBlock>,
        buffered: BTreeMap<u64, crate::block::ConsensusBlock>,
        fail_next_sync: bool,
    }

    impl Blocks for DurableCrashBlocks {
        type Block = crate::block::ConsensusBlock;
        type Error = std::io::Error;

        async fn put(&mut self, block: Self::Block) -> Result<(), Self::Error> {
            let height = block.height().get();
            if !self.durable.contains_key(&height) {
                self.buffered.entry(height).or_insert(block);
            }
            Ok(())
        }

        async fn sync(&mut self) -> Result<(), Self::Error> {
            if std::mem::take(&mut self.fail_next_sync) {
                return Err(std::io::Error::other("injected block sync crash"));
            }
            self.durable.append(&mut self.buffered);
            Ok(())
        }

        async fn get(
            &self,
            id: Identifier<'_, Digest>,
        ) -> Result<Option<Self::Block>, Self::Error> {
            let value = match id {
                Identifier::Index(height) => self
                    .buffered
                    .get(&height)
                    .or_else(|| self.durable.get(&height)),
                Identifier::Key(digest) => self
                    .buffered
                    .values()
                    .chain(self.durable.values())
                    .find(|block| block.digest() == *digest),
            };
            Ok(value.cloned())
        }

        async fn prune(&mut self, min: Height) -> Result<(), Self::Error> {
            self.durable.retain(|height, _| *height >= min.get());
            self.buffered.retain(|height, _| *height >= min.get());
            Ok(())
        }

        fn missing_items(&self, start: Height, max: usize) -> Vec<Height> {
            let last = self
                .durable
                .keys()
                .chain(self.buffered.keys())
                .max()
                .copied();
            let Some(last) = last else {
                return Vec::new();
            };
            (start.get()..=last)
                .filter(|height| {
                    !self.durable.contains_key(height) && !self.buffered.contains_key(height)
                })
                .take(max)
                .map(Height::new)
                .collect()
        }

        fn next_gap(&self, value: Height) -> (Option<Height>, Option<Height>) {
            let contains =
                self.durable.contains_key(&value.get()) || self.buffered.contains_key(&value.get());
            let next = self
                .durable
                .keys()
                .chain(self.buffered.keys())
                .filter(|height| **height > value.get())
                .min()
                .copied()
                .map(Height::new);
            (contains.then_some(value), next)
        }

        fn last_index(&self) -> Option<Height> {
            self.durable
                .keys()
                .chain(self.buffered.keys())
                .max()
                .copied()
                .map(Height::new)
        }
    }

    fn certified_block(
        signer: &Committee,
        epoch: Epoch,
        height: u64,
        extra_data: Vec<u8>,
    ) -> CertifiedFinalizedBlock {
        use reth_ethereum::{primitives::SealedBlock, Block};

        let mut block = Block::default();
        block.header.number = height;
        block.header.extra_data = Bytes::from(extra_data);
        let block = crate::block::ConsensusBlock::from_sealed(SealedBlock::seal_slow(
            block.map_header(outbe_primitives::OutbeHeader::new),
        ));
        let finalization = signer.finalization_for(epoch, block.digest());
        CertifiedFinalizedBlock {
            finalization,
            block,
        }
    }

    fn fill_plain_finalized_range(
        records: &mut BTreeMap<u64, CertifiedFinalizedBlock>,
        signer: &Committee,
        epoch: Epoch,
        heights: impl Iterator<Item = u64>,
    ) {
        for height in heights {
            records
                .entry(height)
                .or_insert_with(|| certified_block(signer, epoch, height, Vec::new()));
        }
    }

    #[test]
    fn restart_authenticates_and_pairs_archive_suffix_across_epoch_boundary() {
        let c0 = committee(10);
        let c1 = committee(30);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (
                10,
                certified_block(&c0, e0, 10, c1.preannounce_block_extra_data(e1)),
            ),
            (
                11,
                certified_block(&c1, e1, 11, c1.boundary_block_extra_data(e1)),
            ),
            (12, certified_block(&c1, e1, 12, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..10);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        for height in [10_u64, 11, 12] {
            let record = records.get(&height).unwrap();
            certificates
                .by_height
                .insert(height, record.finalization.clone());
            blocks.by_height.insert(height, record.block.clone());
        }

        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(10),
            Height::new(12),
            &mut certificates,
            &mut blocks,
        ))
        .expect("paired suffix must authenticate through the epoch boundary");

        assert_eq!(chain.lock().unwrap().highest_registered(), Some(e1));
        assert_eq!(epocher.containing(Height::new(12)).unwrap().epoch(), e1);
        assert_eq!(certificates.last_index(), Some(Height::new(12)));
        assert_eq!(blocks.last_index(), Some(Height::new(12)));
    }

    #[test]
    fn restart_recovers_preannounce_before_suffix_lower_bound() {
        let c0 = committee(10);
        let c1 = committee(30);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (
                8,
                certified_block(&c0, e0, 8, c1.preannounce_block_extra_data(e1)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..8);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        for height in [8_u64, 9] {
            let record = records.get(&height).unwrap();
            certificates
                .by_height
                .insert(height, record.finalization.clone());
        }
        blocks.by_height.insert(9, records[&9].block.clone());

        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .expect("restart must recover an earlier authenticated successor preannounce");

        assert_eq!(chain.lock().unwrap().highest_registered(), Some(e1));

        let boundary = certified_block(&c1, e1, 11, c1.boundary_block_extra_data(e1));
        engine::authenticate_live_finalized(&chain, &epocher, Height::new(11), &boundary)
            .expect("the subsequent live boundary must verify with the recovered successor");
        assert_eq!(epocher.containing(Height::new(11)).unwrap().epoch(), e1);
    }

    #[test]
    fn restart_repairs_both_archive_halves_from_authenticated_suffix() {
        let c0 = committee(10);
        let c1 = committee(30);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (
                10,
                certified_block(&c0, e0, 10, c1.preannounce_block_extra_data(e1)),
            ),
            (
                11,
                certified_block(&c1, e1, 11, c1.boundary_block_extra_data(e1)),
            ),
            (12, certified_block(&c1, e1, 12, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..10);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        certificates
            .by_height
            .insert(10, records[&10].finalization.clone());
        certificates
            .by_height
            .insert(12, records[&12].finalization.clone());
        blocks.by_height.insert(10, records[&10].block.clone());
        blocks.by_height.insert(11, records[&11].block.clone());

        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(10),
            Height::new(12),
            &mut certificates,
            &mut blocks,
        ))
        .expect("authenticated suffix must repair either missing archive companion");

        for height in 10_u64..=12 {
            assert_eq!(
                certificates.by_height[&height].encode(),
                records[&height].finalization.encode()
            );
            assert_eq!(
                blocks.by_height[&height].encode(),
                records[&height].block.encode()
            );
        }
        assert_eq!(chain.lock().unwrap().highest_registered(), Some(e1));
    }

    #[test]
    fn restart_authenticates_multiple_epochs_in_one_replay_suffix() {
        let c0 = committee(10);
        let c1 = committee(30);
        let c2 = committee(50);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let e2 = Epoch::new(2);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (
                10,
                certified_block(&c0, e0, 10, c1.preannounce_block_extra_data(e1)),
            ),
            (
                11,
                certified_block(&c1, e1, 11, c1.boundary_block_extra_data(e1)),
            ),
            (
                20,
                certified_block(&c1, e1, 20, c2.preannounce_block_extra_data(e2)),
            ),
            (
                21,
                certified_block(&c2, e2, 21, c2.boundary_block_extra_data(e2)),
            ),
            (22, certified_block(&c2, e2, 22, Vec::new())),
        ]);
        for height in 12_u64..20 {
            records.insert(height, certified_block(&c1, e1, height, Vec::new()));
        }
        fill_plain_finalized_range(&mut records, &c0, e0, 2..10);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        for height in 10_u64..=22 {
            let record = &records[&height];
            certificates
                .by_height
                .insert(height, record.finalization.clone());
            blocks.by_height.insert(height, record.block.clone());
        }

        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(10),
            Height::new(22),
            &mut certificates,
            &mut blocks,
        ))
        .expect("one replay suffix may authenticate several epoch transitions");

        assert_eq!(chain.lock().unwrap().highest_registered(), Some(e2));
        assert_eq!(epocher.containing(Height::new(22)).unwrap().epoch(), e2);
    }

    #[test]
    fn restart_replay_suffix_rejects_missing_upstream_height() {
        let c0 = committee(10);
        let e0 = Epoch::new(0);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        certificates
            .by_height
            .insert(9, records[&9].finalization.clone());
        blocks.by_height.insert(9, records[&9].block.clone());

        let error = futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(10),
            &mut certificates,
            &mut blocks,
        ))
        .unwrap_err()
        .to_string();

        assert!(error.contains("upstream did not return follower replay suffix height 10"));
    }

    #[test]
    fn restart_replay_suffix_rejects_local_block_conflict() {
        let c0 = committee(10);
        let e0 = Epoch::new(0);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        certificates
            .by_height
            .insert(9, records[&9].finalization.clone());
        blocks
            .by_height
            .insert(9, certified_block(&c0, e0, 9, vec![0xFF]).block);

        let error = futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .unwrap_err()
        .to_string();

        assert!(error.contains(
            "local follower replay block differs from authenticated upstream at height 9"
        ));
    }

    #[test]
    fn restart_replay_suffix_accepts_distinct_valid_quorum_for_same_proposal() {
        let c0 = committee(10);
        let e0 = Epoch::new(0);
        let epocher = FollowerEpocher::new(10, 0);
        let mut height_nine = certified_block(&c0, e0, 9, Vec::new());
        height_nine.finalization =
            c0.finalization_for_signers(e0, height_nine.block.digest(), &[0, 1, 2]);
        let local_finalization =
            c0.finalization_for_signers(e0, height_nine.block.digest(), &[1, 2, 3]);
        assert_eq!(
            local_finalization.proposal,
            height_nine.finalization.proposal
        );
        assert_ne!(
            local_finalization.encode(),
            height_nine.finalization.encode()
        );

        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, height_nine),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        certificates.by_height.insert(9, local_finalization.clone());
        blocks.by_height.insert(9, records[&9].block.clone());

        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .expect("distinct valid quorum certificates for one proposal must reconcile");

        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .expect("restarting with the retained alternate certificate must be idempotent");

        assert_eq!(
            certificates.by_height[&9].encode(),
            local_finalization.encode(),
            "reconciliation must retain the already-valid local certificate"
        );
    }

    #[test]
    fn restart_replay_suffix_rejects_invalid_local_certificate_for_same_proposal() {
        let c0 = committee(10);
        let attacker = committee(50);
        let e0 = Epoch::new(0);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        let forged = attacker.finalization_for(e0, records[&9].block.digest());
        assert_eq!(forged.proposal, records[&9].finalization.proposal);
        certificates.by_height.insert(9, forged);
        blocks.by_height.insert(9, records[&9].block.clone());

        let error = futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .unwrap_err()
        .to_string();

        assert!(
            error.contains(
                "local follower replay finalization certificate failed verification at height 9"
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn restart_replay_suffix_rejects_local_finalization_conflict() {
        let c0 = committee(10);
        let e0 = Epoch::new(0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let digest = records[&9].block.digest();
        let signer_indices: Vec<_> = (0..c0.keys.len()).collect();
        let conflicts = [
            (
                "payload",
                certified_block(&c0, e0, 8, Vec::new()).finalization,
            ),
            (
                "parent view",
                c0.finalization_for_proposal(
                    e0,
                    Proposal::new(Round::new(e0, View::new(2)), View::new(0), digest),
                    &signer_indices,
                ),
            ),
            (
                "round view",
                c0.finalization_for_proposal(
                    e0,
                    Proposal::new(Round::new(e0, View::new(3)), View::new(1), digest),
                    &signer_indices,
                ),
            ),
            (
                "epoch",
                c0.finalization_for_proposal(
                    e0,
                    Proposal::new(
                        Round::new(Epoch::new(1), View::new(2)),
                        View::new(1),
                        digest,
                    ),
                    &signer_indices,
                ),
            ),
        ];

        for (name, conflict) in conflicts {
            let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
                e0,
                c0.participants.clone(),
            )));
            let epocher = FollowerEpocher::new(10, 0);
            let mut certificates = MemoryCertificates::default();
            let mut blocks = MemoryBlocks::default();
            certificates.by_height.insert(9, conflict);
            blocks.by_height.insert(9, records[&9].block.clone());

            let error =
                futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
                    &chain,
                    &source,
                    &epocher,
                    e0,
                    Height::new(9),
                    Height::new(9),
                    &mut certificates,
                    &mut blocks,
                ))
                .unwrap_err()
                .to_string();

            assert!(
                error.contains(
                    "local follower replay finalization proposal differs from authenticated upstream at height 9"
                ),
                "{name}: unexpected error: {error}"
            );
        }
    }

    #[test]
    fn restart_replay_suffix_rejects_conflicting_preannounces() {
        let c0 = committee(10);
        let c1 = committee(30);
        let conflicting_c1 = committee(50);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (
                7,
                certified_block(&c0, e0, 7, conflicting_c1.preannounce_block_extra_data(e1)),
            ),
            (
                8,
                certified_block(&c0, e0, 8, c1.preannounce_block_extra_data(e1)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..7);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();
        for height in [7_u64, 8, 9] {
            certificates
                .by_height
                .insert(height, records[&height].finalization.clone());
            blocks
                .by_height
                .insert(height, records[&height].block.clone());
        }

        let error = futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .unwrap_err()
        .to_string();

        assert!(error.contains("conflicting committee outcome replay for epoch 1"));
    }

    #[test]
    fn restart_replay_suffix_rejects_boundary_outcome_conflicting_with_preannounce() {
        let c0 = committee(10);
        let c1 = committee(30);
        let conflicting_c1 = committee(50);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (
                8,
                certified_block(&c0, e0, 8, c1.preannounce_block_extra_data(e1)),
            ),
            (
                11,
                certified_block(&c1, e1, 11, conflicting_c1.boundary_block_extra_data(e1)),
            ),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..8);
        fill_plain_finalized_range(&mut records, &c0, e0, 9..11);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();

        let error = futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(8),
            Height::new(11),
            &mut certificates,
            &mut blocks,
        ))
        .unwrap_err()
        .to_string();

        assert!(error.contains("boundary outcome conflicts with authenticated epoch 1 outcome"));
        assert!(epocher.activation_height(e1).is_none());
    }

    #[test]
    fn restart_replay_suffix_rejects_wrong_upstream_payload_before_archive_write() {
        let c0 = committee(10);
        let e0 = Epoch::new(0);
        let epocher = FollowerEpocher::new(10, 0);
        let honest = certified_block(&c0, e0, 9, Vec::new());
        let other = certified_block(&c0, e0, 8, Vec::new());
        let malformed = CertifiedFinalizedBlock {
            finalization: other.finalization,
            block: honest.block,
        };
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, malformed),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();

        let error = futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .unwrap_err()
        .to_string();

        assert!(error.contains("finalization payload differs from block at height 9"));
        assert!(!certificates.by_height.contains_key(&9));
        assert!(!blocks.by_height.contains_key(&9));
    }

    #[test]
    fn restart_replay_suffix_rejects_wrong_height_epoch_and_forged_certificate() {
        let c0 = committee(10);
        let c1 = committee(30);
        let e0 = Epoch::new(0);
        let wrong_height = certified_block(&c0, e0, 8, Vec::new());
        let wrong_epoch = certified_block(&c0, Epoch::new(2), 9, Vec::new());
        let honest = certified_block(&c0, e0, 9, Vec::new());
        let forged = CertifiedFinalizedBlock {
            finalization: c1.finalization_for(e0, honest.block.digest()),
            block: honest.block,
        };

        for (name, candidate, expected_error) in [
            (
                "wrong height",
                wrong_height,
                "certified block reports height 8, expected 9",
            ),
            (
                "wrong epoch",
                wrong_epoch,
                "recovered height 9 precedes activation window",
            ),
            (
                "forged certificate",
                forged,
                "finalization certificate failed verification for epoch 0",
            ),
        ] {
            let mut records = BTreeMap::from([
                (
                    1,
                    certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
                ),
                (9, candidate),
            ]);
            fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
            let source = ArchivedFinalizedSource {
                by_height: Arc::new(records),
            };
            let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
                e0,
                c0.participants.clone(),
            )));
            let epocher = FollowerEpocher::new(10, 0);
            let mut certificates = MemoryCertificates::default();
            let mut blocks = MemoryBlocks::default();

            let error =
                futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
                    &chain,
                    &source,
                    &epocher,
                    e0,
                    Height::new(9),
                    Height::new(9),
                    &mut certificates,
                    &mut blocks,
                ))
                .unwrap_err()
                .to_string();

            assert!(error.contains(expected_error), "{name}: {error}");
            assert!(certificates.by_height.is_empty(), "{name}");
            assert!(blocks.by_height.is_empty(), "{name}");
        }
    }

    #[test]
    fn restart_repairs_both_durable_archive_crash_cuts() {
        let c0 = committee(10);
        let e0 = Epoch::new(0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };

        // Crash cut 1: the finalization sync committed, then block sync failed.
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let epocher = FollowerEpocher::new(10, 0);
        let mut certificates = MemoryCertificates::default();
        let mut blocks = DurableCrashBlocks {
            fail_next_sync: true,
            ..Default::default()
        };
        let error = futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .unwrap_err()
        .to_string();
        assert!(error.contains("failed to sync repaired follower replay blocks"));
        assert!(certificates.by_height.contains_key(&9));
        assert!(!blocks.durable.contains_key(&9));

        // Restart sees the durable finalization-only tail and repairs its block.
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let epocher = FollowerEpocher::new(10, 0);
        let mut blocks = DurableCrashBlocks::default();
        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .expect("restart must repair a durable finalization-only crash cut");
        assert!(blocks.durable.contains_key(&9));

        // Crash cut 2: a block-only durable tail is repaired symmetrically.
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let epocher = FollowerEpocher::new(10, 0);
        let mut certificates = MemoryCertificates::default();
        let mut blocks = DurableCrashBlocks {
            durable: BTreeMap::from([(9, records[&9].block.clone())]),
            ..Default::default()
        };
        futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(9),
            Height::new(9),
            &mut certificates,
            &mut blocks,
        ))
        .expect("restart must repair a durable block-only crash cut");
        assert_eq!(
            certificates.by_height[&9].encode(),
            records[&9].finalization.encode()
        );
        assert_eq!(blocks.durable.len(), 1);
    }

    #[test]
    fn restart_replay_suffix_reconciliation_is_idempotent() {
        let c0 = committee(10);
        let e0 = Epoch::new(0);
        let epocher = FollowerEpocher::new(10, 0);
        let mut records = BTreeMap::from([
            (
                1,
                certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
            ),
            (9, certified_block(&c0, e0, 9, Vec::new())),
        ]);
        fill_plain_finalized_range(&mut records, &c0, e0, 2..9);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(records.clone()),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        let mut certificates = MemoryCertificates::default();
        let mut blocks = MemoryBlocks::default();

        for _ in 0..2 {
            futures::executor::block_on(engine::authenticate_and_reconcile_replay_suffix(
                &chain,
                &source,
                &epocher,
                e0,
                Height::new(9),
                Height::new(9),
                &mut certificates,
                &mut blocks,
            ))
            .expect("repeated authenticated repair must be idempotent");
        }

        assert_eq!(certificates.by_height.len(), 1);
        assert_eq!(blocks.by_height.len(), 1);
        assert_eq!(
            certificates.by_height[&9].encode(),
            records[&9].finalization.encode()
        );
        assert_eq!(blocks.by_height[&9].encode(), records[&9].block.encode());
    }

    #[test]
    fn restart_rebuilds_every_committee_from_prior_epoch_finality_before_current_epoch() {
        let c0 = committee(10);
        let c1 = committee(30);
        let c2 = committee(50);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let e2 = Epoch::new(2);
        let epocher = FollowerEpocher::new(10, 0);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(BTreeMap::from([
                (
                    1,
                    certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
                ),
                (
                    10,
                    certified_block(&c0, e0, 10, c1.preannounce_block_extra_data(e1)),
                ),
                (
                    11,
                    certified_block(&c1, e1, 11, c1.boundary_block_extra_data(e1)),
                ),
                (
                    20,
                    certified_block(&c1, e1, 20, c2.preannounce_block_extra_data(e2)),
                ),
                (
                    21,
                    certified_block(&c2, e2, 21, c2.boundary_block_extra_data(e2)),
                ),
            ])),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));

        futures::executor::block_on(engine::prepare_committee_chain(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(21),
        ))
        .expect("restart must rebuild the authenticated chain through the recovered epoch");

        let guard = chain.lock().unwrap();
        assert_eq!(guard.highest_registered(), Some(e2));
        guard
            .verify_finalization(e2, &c2.finalization(e2))
            .expect("current epoch finality must verify after restart reconstruction");
    }

    #[test]
    fn next_committee_preannounce_may_precede_prior_epoch_final_block() {
        let c0 = committee(10);
        let c1 = committee(30);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let epocher = FollowerEpocher::new(10, 0);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(BTreeMap::from([
                (
                    1,
                    certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
                ),
                (
                    8,
                    certified_block(&c0, e0, 8, c1.preannounce_block_extra_data(e1)),
                ),
                (10, certified_block(&c0, e0, 10, Vec::new())),
                (
                    11,
                    certified_block(&c1, e1, 11, c1.boundary_block_extra_data(e1)),
                ),
            ])),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));

        futures::executor::block_on(engine::prepare_committee_chain(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(11),
        ))
        .expect("trusted pre-announce before the epoch-final block must register epoch 1");

        chain
            .lock()
            .unwrap()
            .verify_finalization(e1, &c1.finalization(e1))
            .expect("epoch 1 finality verifies through the prior-epoch carrier");
    }

    #[test]
    fn restart_reconstructs_delayed_boundaries_and_ignores_a_later_preannounce_trap() {
        let c0 = committee(10);
        let c1 = committee(30);
        let c2 = committee(50);
        let c3 = committee(70);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let e2 = Epoch::new(2);
        let e3 = Epoch::new(3);
        let epocher = FollowerEpocher::new(10, 3);
        let source = ArchivedFinalizedSource {
            by_height: Arc::new(BTreeMap::from([
                (
                    1,
                    certified_block(&c0, e0, 1, c0.boundary_block_extra_data(e0)),
                ),
                (
                    12,
                    certified_block(&c0, e0, 12, c1.preannounce_block_extra_data(e1)),
                ),
                (
                    13,
                    certified_block(&c1, e1, 13, c1.boundary_block_extra_data(e1)),
                ),
                (
                    23,
                    certified_block(&c1, e1, 23, c2.preannounce_block_extra_data(e2)),
                ),
                (
                    25,
                    certified_block(&c2, e2, 25, c3.preannounce_block_extra_data(e3)),
                ),
                (
                    26,
                    certified_block(&c2, e2, 26, c2.boundary_block_extra_data(e2)),
                ),
                (28, certified_block(&c2, e2, 28, Vec::new())),
            ])),
        };
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));

        let recovered_epoch = futures::executor::block_on(engine::prepare_committee_chain(
            &chain,
            &source,
            &epocher,
            e0,
            Height::new(28),
        ))
        .expect("restart must derive both delayed boundaries from authenticated history");

        assert_eq!(recovered_epoch, e2);
        assert_eq!(epocher.first(e1), Some(Height::new(13)));
        assert_eq!(epocher.first(e2), Some(Height::new(26)));
        assert_eq!(epocher.last(e1), Some(Height::new(25)));
        assert_eq!(epocher.containing(Height::new(28)).unwrap().epoch(), e2);
        assert_eq!(chain.lock().unwrap().highest_registered(), Some(e2));
    }

    #[test]
    fn live_delivery_mutates_only_after_certificate_authentication() {
        let c0 = committee(10);
        let c1 = committee(30);
        let e0 = Epoch::new(0);
        let e1 = Epoch::new(1);
        let epocher = FollowerEpocher::new(10, 3);
        let chain = Arc::new(std::sync::Mutex::new(CommitteeChain::new(
            e0,
            c0.participants.clone(),
        )));
        chain
            .lock()
            .unwrap()
            .register_epoch_from_outcome(e0, &c0.outcome(e0))
            .unwrap();

        let forged_carrier = certified_block(&c1, e0, 10, c1.preannounce_block_extra_data(e1));
        assert!(engine::authenticate_live_finalized(
            &chain,
            &epocher,
            Height::new(10),
            &forged_carrier,
        )
        .is_err());
        assert_eq!(chain.lock().unwrap().highest_registered(), Some(e0));
        assert_eq!(epocher.first(e1), None);

        let carrier = certified_block(&c0, e0, 12, c1.preannounce_block_extra_data(e1));
        engine::authenticate_live_finalized(&chain, &epocher, Height::new(12), &carrier)
            .expect("prior-committee-certified preannounce must register epoch one");
        assert_eq!(chain.lock().unwrap().highest_registered(), Some(e1));

        let boundary = certified_block(&c1, e1, 13, c1.boundary_block_extra_data(e1));
        engine::authenticate_live_finalized(&chain, &epocher, Height::new(13), &boundary)
            .expect("registered next committee must authenticate its delayed boundary");
        assert_eq!(epocher.first(e1), Some(Height::new(13)));
    }

    #[test]
    fn committee_chain_anchors_then_chains_across_epochs() {
        let (e5, e6) = (Epoch::new(5), Epoch::new(6));
        let c5 = committee(10);
        let c6 = committee(50);
        let mut chain = CommitteeChain::new(e5, c5.participants.clone());

        chain
            .register_epoch_from_outcome(e5, &c5.outcome(e5))
            .unwrap();
        chain.verify_finalization(e5, &c5.finalization(e5)).unwrap();

        // Chain forward to epoch 6 (a different committee) and verify it.
        chain
            .register_epoch_from_outcome(e6, &c6.outcome(e6))
            .unwrap();
        chain.verify_finalization(e6, &c6.finalization(e6)).unwrap();
        assert_eq!(chain.highest_registered(), Some(e6));
        let verifier =
            commonware_cryptography::certificate::Provider::scoped(chain.scheme_provider(), e6)
                .expect("epoch-6 verifier is registered");
        assert_eq!(
            verifier.expected_vrf_material_version(),
            e6.get(),
            "the authenticated epoch must restore the canonical VRF material version"
        );

        // A finalization can't be verified for an unregistered epoch.
        assert!(chain
            .verify_finalization(Epoch::new(7), &c6.finalization(e6))
            .is_err());
    }

    #[test]
    fn admission_cursor_has_no_256_epoch_horizon_and_retains_one_verifier() {
        let committee = committee(10);
        let mut chain = CommitteeChain::new(Epoch::new(0), committee.participants.clone());

        for raw_epoch in 0..=300_u64 {
            let epoch = Epoch::new(raw_epoch);
            chain
                .register_epoch_from_outcome(epoch, &committee.outcome(epoch))
                .unwrap();
            chain.retain_only_highest();

            assert_eq!(chain.highest_registered(), Some(epoch));
            assert_eq!(chain.outcome_hashes.len(), 1);
            assert!(commonware_cryptography::certificate::Provider::scoped(
                chain.scheme_provider(),
                epoch,
            )
            .is_some());
            if raw_epoch > 0 {
                assert!(
                    commonware_cryptography::certificate::Provider::scoped(
                        chain.scheme_provider(),
                        Epoch::new(raw_epoch - 1),
                    )
                    .is_none(),
                    "the prior verifier must be pruned after epoch {raw_epoch}"
                );
            }
        }
    }

    #[test]
    fn preannounce_registers_and_self_finalized_boundary_cannot_override() {
        // The D1 fix, end to end at the follower: epoch 6's committee is registered
        // from its E-1 PRE-ANNOUNCE (carried in a block finalized by the trusted
        // epoch-5 committee - the chained path). A later self-finalized epoch-6
        // boundary announcing a DIFFERENT (forged) committee must NOT override it.
        let (e5, e6) = (Epoch::new(5), Epoch::new(6));
        let c5 = committee(10);
        let c6 = committee(50); // the real epoch-6 committee, pre-announced by trusted e5
        let forged6 = committee(77); // what a malicious self-finalized e6 boundary would claim
        let mut chain = CommitteeChain::new(e5, c5.participants.clone());
        chain
            .register_epoch_from_outcome(e5, &c5.outcome(e5))
            .unwrap();

        // Pre-announce epoch 6 in an e5-finalized block -> registered (chained trust).
        let pre6 = c6.preannounce_block_extra_data(e6);
        assert_eq!(
            chain.advance_from_block_extra_data(&pre6).unwrap(),
            Some(e6)
        );
        chain.verify_finalization(e6, &c6.finalization(e6)).unwrap();

        // A forged, self-finalized epoch-6 boundary is a NO-OP - it cannot overwrite
        // the chained committee (that overwrite would be the D1 bug).
        let forged_boundary = forged6.boundary_block_extra_data(e6);
        assert_eq!(
            chain
                .advance_from_block_extra_data(&forged_boundary)
                .unwrap(),
            None
        );
        // The forged committee's finalization is rejected; the real one still verifies.
        assert!(chain
            .verify_finalization(e6, &forged6.finalization(e6))
            .is_err());
        chain.verify_finalization(e6, &c6.finalization(e6)).unwrap();
    }

    #[test]
    fn committee_chain_rejects_anchor_mismatch() {
        let e5 = Epoch::new(5);
        let c5 = committee(10);
        let wrong = committee(99);
        let mut chain = CommitteeChain::new(e5, wrong.participants.clone());
        let err = chain
            .register_epoch_from_outcome(e5, &c5.outcome(e5))
            .unwrap_err()
            .to_string();
        assert!(err.contains("anchor mismatch"), "error: {err}");
    }

    #[test]
    fn committee_chain_rejects_noncanonical_or_mislabelled_outcomes() {
        let epoch = Epoch::new(5);
        let committee = committee(10);

        let mut trailing = committee.outcome(epoch);
        trailing.push(0);
        let mut chain = CommitteeChain::new(epoch, committee.participants.clone());
        assert!(chain.register_epoch_from_outcome(epoch, &trailing).is_err());

        let mut wrong_version = committee.outcome(epoch);
        wrong_version[4] ^= 1;
        let mut chain = CommitteeChain::new(epoch, committee.participants.clone());
        assert!(chain
            .register_epoch_from_outcome(epoch, &wrong_version)
            .is_err());

        let wrong_epoch = committee.outcome(Epoch::new(epoch.get() + 1));
        let mut chain = CommitteeChain::new(epoch, committee.participants.clone());
        assert!(chain
            .register_epoch_from_outcome(epoch, &wrong_epoch)
            .unwrap_err()
            .to_string()
            .contains("epoch label"));
    }

    #[test]
    fn committee_chain_advances_from_boundary_block_extra_data() {
        let e6 = Epoch::new(6);
        let c6 = committee(70);
        // Anchor on epoch 6 - the boundary block we process announces it.
        let mut chain = CommitteeChain::new(e6, c6.participants.clone());
        // Feeding the boundary block's extra_data registers epoch 6's committee.
        let extra = c6.boundary_block_extra_data(e6);
        assert_eq!(
            chain.advance_from_block_extra_data(&extra).unwrap(),
            Some(e6)
        );
        // That epoch's finalization now verifies.
        chain.verify_finalization(e6, &c6.finalization(e6)).unwrap();
        // A non-boundary block (empty extra_data) registers nothing.
        assert_eq!(chain.advance_from_block_extra_data(&[]).unwrap(), None);
    }

    /// The follow resolver serves a `Request::Finalized` delivery as the
    /// finalization certificate bytes immediately followed by the block bytes.
    /// The marshal decodes that exact layout by reading the `Finalization` with
    /// the epoch verifier's certificate codec config, then decoding the
    /// `ConsensusBlock` from the REMAINING buffer. This pins that two-step decode
    /// against the resolver's `finalization.encode() ++ block.encode()` wire
    /// format - the load-bearing interop contract between the follower's
    /// resolver and the marshal (a divergence here would compile clean but fail
    /// every backfill at runtime).
    #[test]
    fn finalized_delivery_wire_format_round_trips() {
        use crate::block::ConsensusBlock;
        use commonware_codec::Read as _;
        use commonware_cryptography::certificate::Scheme as _;

        let epoch = Epoch::new(3);
        let c = committee(20);

        // A certificate the marshal will decode with this verifier's config.
        let finalization = c.finalization(epoch);
        let verifier = HybridScheme::<MinSig>::verifier(
            &crate::config::outbe_app_namespace(),
            c.participants.clone(),
            c.dkg.polynomial.clone(),
        )
        .unwrap();
        let cert_cfg = verifier.certificate_codec_config();

        // An arbitrary valid block (its digest need not match the finalization
        // payload for the codec contract - the marshal checks that separately).
        let block = {
            use alloy_primitives::Bytes;
            use outbe_primitives::OutbeHeader;
            use reth_ethereum::primitives::SealedBlock;
            use reth_ethereum::Block;
            let mut b = Block::default();
            b.header.number = 42;
            b.header.extra_data = Bytes::from_static(b"wire-fmt");
            let b = b.map_header(OutbeHeader::new);
            ConsensusBlock::from_sealed(SealedBlock::seal_slow(b))
        };

        // Exactly what `resolver::resolve_one` builds for a Finalized delivery.
        let mut wire = finalization.encode().to_vec();
        wire.extend_from_slice(block.encode().as_ref());

        // Decode the marshal's way: certificate first (with its cfg), block from
        // the remaining bytes.
        let mut buf: &[u8] = &wire;
        let decoded_fin =
            Finalization::<HybridScheme<MinSig>, Digest>::read_cfg(&mut buf, &cert_cfg)
                .expect("finalization must decode from the delivery prefix");
        let decoded_block = ConsensusBlock::read_cfg(&mut buf, &())
            .expect("block must decode from the delivery suffix");

        assert_eq!(
            decoded_fin.proposal.payload, finalization.proposal.payload,
            "decoded finalization payload must match"
        );
        assert_eq!(
            decoded_block.digest(),
            block.digest(),
            "decoded block digest must match the served block"
        );
        assert!(
            buf.is_empty(),
            "the delivery buffer must be fully consumed (cert ++ block, nothing trailing)"
        );
    }

    /// Full `rudis_getFinalization` server->client interop. The SERVER side
    /// (drainer) encodes the certificate and block separately and hexes them
    /// (`FinalizedBlockBytes` -> `FinalizationProof`); the CLIENT side hex-decodes
    /// and decodes the certificate with the UNBOUNDED committee config (the
    /// engine `UpstreamRpcClient` path - it has no committee size yet), then the
    /// follower registers the epoch committee from the boundary block and the
    /// marshal-equivalent verification passes. This pins that:
    ///   (a) the unbounded cfg decodes a real committee-length certificate, and
    ///   (b) the decoded `(finalization, block)` is exactly what the resolver
    ///       registers + the `CommitteeChain` verifies - i.e. a follower accepts
    ///       what a validator serves, end to end.
    #[test]
    fn served_finalization_round_trips_to_verified_certified_block() {
        use crate::block::ConsensusBlock;
        use commonware_codec::Read as _;
        use commonware_cryptography::certificate::Scheme as _;

        let epoch = Epoch::new(4);
        let c = committee(40);

        // Anchor a chain on this committee and register epoch 4 from its boundary
        // block - exactly what the follower does on the fetch path.
        let mut chain = CommitteeChain::new(epoch, c.participants.clone());
        let boundary_extra = c.boundary_block_extra_data(epoch);
        assert_eq!(
            chain
                .advance_from_block_extra_data(&boundary_extra)
                .unwrap(),
            Some(epoch)
        );

        // SERVER: encode cert + block separately (the drainer's FinalizedBlockBytes)
        // and hex them (the FinalizationProof shipped over RPC).
        let finalization = c.finalization(epoch);
        let block = {
            use alloy_primitives::Bytes;
            use outbe_primitives::OutbeHeader;
            use reth_ethereum::primitives::SealedBlock;
            use reth_ethereum::Block;
            let mut b = Block::default();
            b.header.number = 4;
            b.header.extra_data = Bytes::from(boundary_extra.clone());
            let b = b.map_header(OutbeHeader::new);
            ConsensusBlock::from_sealed(SealedBlock::seal_slow(b))
        };
        let finalization_hex = format!("0x{}", hex::encode(finalization.encode()));
        let block_hex = format!("0x{}", hex::encode(block.encode()));

        // CLIENT: hex-decode and decode the certificate with the UNBOUNDED
        // committee config (the engine UpstreamRpcClient path).
        let fin_bytes = hex::decode(finalization_hex.trim_start_matches("0x")).unwrap();
        let block_bytes = hex::decode(block_hex.trim_start_matches("0x")).unwrap();
        let unbounded_cfg = HybridScheme::<MinSig>::certificate_codec_config_unbounded();
        let mut fin_reader: &[u8] = &fin_bytes;
        let decoded_fin =
            Finalization::<HybridScheme<MinSig>, Digest>::read_cfg(&mut fin_reader, &unbounded_cfg)
                .expect("client must decode the served finalization with the unbounded cfg");
        assert!(
            fin_reader.is_empty(),
            "no trailing bytes after finalization"
        );
        let mut block_reader: &[u8] = &block_bytes;
        let _decoded_block = ConsensusBlock::read_cfg(&mut block_reader, &())
            .expect("client must decode the served block");
        assert!(block_reader.is_empty(), "no trailing bytes after block");

        // The decoded certificate verifies against the committee the follower
        // registered from the boundary block - a follower accepts what the
        // validator served.
        chain
            .verify_finalization(epoch, &decoded_fin)
            .expect("the round-tripped certificate must verify against the registered committee");
    }

    #[test]
    fn public_finalization_decoder_requires_exact_canonical_record() {
        use commonware_codec::Encode as _;

        let committee = committee(44);
        let finalization = committee.finalization(Epoch::new(7));
        let encoded = finalization.encode();

        let decoded = decode_public_finalization(&encoded, committee.participants.len()).unwrap();
        assert_eq!(decoded.proposal, finalization.proposal);

        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_public_finalization(&trailing, committee.participants.len()),
            Err(PublicFinalizedBlockDecodeError::TrailingFinalization)
        ));
        assert!(matches!(
            decode_public_finalization(&encoded, 0),
            Err(PublicFinalizedBlockDecodeError::ZeroCommitteeBound)
        ));
    }
}
