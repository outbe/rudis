//! Hybrid signing scheme: BLS12-381 individual attribution + decoupled threshold VRF.
//!
//! Combines BLS individual signatures (MinPk - attributable, aggregatable) with
//! BLS12-381 threshold signatures (MinSig - VRF for unpredictable leader election).
//!
//! Each validator produces a BLS individual vote signature and, when VRF
//! material is available, a BLS threshold seed partial. The consensus
//! certificate aggregates individual vote signatures into a single 96-byte
//! aggregate signature. A recovered threshold seed proof is carried as an
//! optional sidecar and is not required for finality verification.
//!
//! Properties:
//! - `is_attributable() = true` - signer bitmap provides per-validator evidence
//! - `is_batchable() = false` - current Outbe path verifies attestations sequentially
//! - VRF seed extractable from verified certificate sidecars for randomness
//! - Certificate size: ~162 bytes for any number of validators (vs ~9,300 for ed25519 variant)
//!
//! ## Signature Verification Timing
//!
//! Commonware's batcher stores votes BEFORE cryptographic verification for batch
//! efficiency. Votes are queued and batch-verified periodically via `verify_notarizes()`.
//! Invalid signers are blocked after batch verification completes. This creates a
//! bounded timing window where a malicious vote temporarily occupies a slot in
//! `pending_votes` - mitigated by fast batch cycles and immediate peer blocking
//! on verification failure. This is Commonware's intentional design choice for
//! throughput optimization.

use bytes::{Buf, BufMut};
use commonware_codec::{Encode, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    simplex::{scheme::Namespace, types::Subject},
    types::{Epoch, Round},
};
use commonware_cryptography::{
    bls12381::{
        self,
        primitives::{
            group::Share,
            ops::aggregate,
            sharing::Sharing,
            variant::{MinPk, PartialSignature, Variant},
        },
    },
    certificate::{self, Attestation, Signers, Subject as CertificateSubject, Verification},
    Digest, Signer as _, Verifier as _,
};
use commonware_parallel::Strategy;
use commonware_utils::{
    ordered::{Quorum, Set},
    Faults, Participant,
};
use rand_core::{CryptoRngCore, OsRng};
use std::sync::Arc;

/// VRF-based leader election for the hybrid scheme (lifted out of this file).
pub mod election;
#[cfg(test)]
pub(crate) mod test_support;
mod vrf_material;

pub use vrf_material::VrfMaterialProvider;
use vrf_material::VrfPartialVerification;

/// CSPRNG allowed only for Commonware BLS batch-verification weights.
///
/// Commonware's batch verifier samples unpredictable scalar weights to prevent
/// invalid signatures from cancelling out in aggregate. This RNG must not feed
/// VRF seed derivation, leader election, header fields, metadata encoding, or
/// any consensus state transition.
pub(crate) fn bls_batch_verification_rng() -> OsRng {
    OsRng
}

/// Combined BLS individual vote + BLS threshold seed partial emitted by each validator.
///
/// Contains two components:
/// - BLS MinPk individual signature over the vote message (attributable, aggregatable)
/// - BLS MinSig threshold partial over the seed message (for VRF seed recovery)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HybridSignature<V: Variant> {
    /// BLS individual vote signature (MinPk, 96 bytes).
    pub bls_individual_vote: bls12381::Signature,
    /// Version of the VRF material used for `bls_seed_partial`.
    pub vrf_material_version: u64,
    /// BLS threshold partial over the seed message (MinSig, 48 bytes for V=MinSig).
    pub bls_seed_partial: V::Signature,
    /// MinPk identity signature (96 bytes) binding `bls_seed_partial` to the
    /// signer's identity key over `(round, vrf_material_version, partial)` under
    /// [`crate::proof::seed_attest_namespace`]. Makes the partial
    /// non-repudiably attributable so a byzantine/equivocating partial is
    /// slashable (see [`crate::proof::seed_partial`]). NOT aggregated into the
    /// certificate and never reaches on-chain certificate bytes; it rides the
    /// per-vote P2P gossip only and is consulted for attribution when the
    /// complete vote+partial pair is excluded from quorum admission.
    pub seed_partial_identity_sig: bls12381::Signature,
}

impl<V: Variant> Write for HybridSignature<V> {
    fn write(&self, writer: &mut impl BufMut) {
        self.bls_individual_vote.write(writer);
        writer.put_u64(self.vrf_material_version);
        self.bls_seed_partial.write(writer);
        self.seed_partial_identity_sig.write(writer);
    }
}

impl<V: Variant> Read for HybridSignature<V> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let bls_individual_vote = bls12381::Signature::read(reader)?;
        if reader.remaining() < 8 {
            return Err(Error::Invalid(
                "HybridSignature",
                "missing VRF material version",
            ));
        }
        let vrf_material_version = reader.get_u64();
        let bls_seed_partial = V::Signature::read(reader)?;
        let seed_partial_identity_sig = bls12381::Signature::read(reader)?;

        Ok(Self {
            bls_individual_vote,
            vrf_material_version,
            bls_seed_partial,
            seed_partial_identity_sig,
        })
    }
}

impl<V: Variant> FixedSize for HybridSignature<V> {
    const SIZE: usize =
        bls12381::Signature::SIZE + 8 + V::Signature::SIZE + bls12381::Signature::SIZE;
}

// Wire codec for `VrfProof` and `HybridCertificate` lives in `outbe-consensus-proof`.
// Both types are re-exported below so existing call sites at
// `crate::hybrid::{VrfProof, HybridCertificate}` continue to compile and serialize
// byte-identically. There must be exactly one definition of each in the workspace
// (enforced by `audit_targets` / `codec_reuse` tests).
pub use crate::proof::hybrid_wire::{HybridCertificate, VrfProof};

/// The committee binding shared by both roles: the ordered participant set, the
/// versioned VRF threshold material, and the pre-computed committee-bound
/// namespaces. These three always travel together - embedding them as one value
/// makes that invariant structural (a `Signer` cannot carry a different
/// shared-field shape than a `Verifier`) instead of re-stating it at every match
/// site. The signer-only capability fields (`individual_key`, `index`) stay on
/// `Signer`, so "only a signer can sign" remains enforced by the variant.
#[derive(Clone, Debug)]
struct RoleFields<V: Variant> {
    /// Participants in the committee (BLS MinPk identity keys).
    participants: Set<bls12381::PublicKey>,
    /// Shared versioned VRF threshold material.
    vrf_materials: VrfMaterialProvider<V>,
    /// Immutable material version owned by this epoch-scoped scheme.
    expected_vrf_material_version: u64,
    /// Pre-computed namespaces.
    namespace: Namespace,
    /// Test-harness fault injection. Production schemes always leave this false.
    #[cfg(any(test, feature = "test-utils"))]
    invalid_seed_partial_for_test: bool,
}

/// The role-specific data for a hybrid scheme participant.
#[derive(Clone, Debug)]
enum Role<V: Variant> {
    Signer {
        /// Committee binding shared with the verifier role.
        fields: RoleFields<V>,
        /// BLS individual private key (MinPk) for signing votes.
        individual_key: bls12381::PrivateKey,
        /// Participant index in the ordered set.
        index: Participant,
    },
    Verifier {
        /// Committee binding shared with the signer role.
        fields: RoleFields<V>,
    },
}

/// Hybrid signing scheme: BLS MinPk individual attribution + BLS MinSig threshold VRF.
///
/// Identity keys are BLS MinPk (48-byte G1 pubkeys), used for participant ordering,
/// P2P identity, and aggregatable vote signatures.
/// BLS MinSig threshold keys provide VRF-based randomness for leader election.
#[derive(Clone, Debug)]
pub struct HybridScheme<V: Variant> {
    role: Role<V>,
}

/// Build the per-scheme `Namespace` with the committee-bound vote
/// sub-namespaces: notarize/nullify/finalize bind `participant_set_commitment`
/// (so an individual vote cannot cross-verify under a different committee), while
/// seed stays chain-only (already committee-bound by the threshold group key).
/// Both the signer and verifier constructors use this, so they sign and verify
/// votes under byte-identical namespaces, and every external verifier
/// (`proof::verifier`, `proof::late_finalize`, SlashIndicator evidence) derives
/// the same bytes from the same committee via `crate::proof::constants`.
fn committee_bound_namespace(
    base: &[u8],
    participants: &Set<bls12381::PublicKey>,
) -> commonware_consensus::simplex::scheme::Namespace {
    let mut ns = commonware_consensus::simplex::scheme::Namespace::new(base);
    ns.notarize = crate::proof::constants::notarize_namespace(participants);
    ns.nullify = crate::proof::constants::nullify_namespace(participants);
    ns.finalize = crate::proof::constants::finalize_namespace(participants);
    ns
}

impl<V: Variant> HybridScheme<V> {
    /// Creates a signer instance.
    ///
    /// * `namespace` - base namespace for domain separation
    /// * `participants` - ordered set of BLS MinPk identity keys
    /// * `individual_key` - BLS MinPk private key for this participant
    /// * `polynomial` - BLS MinSig public polynomial for threshold operations
    /// * `share` - BLS MinSig share for producing partial signatures
    ///
    /// Returns `None` if:
    /// - The BLS public key is not in the participant set
    /// - The BLS threshold share doesn't match the polynomial
    pub fn signer(
        namespace: &[u8],
        participants: Set<bls12381::PublicKey>,
        individual_key: bls12381::PrivateKey,
        polynomial: Sharing<V>,
        share: Share,
    ) -> Option<Self> {
        let vrf_materials = VrfMaterialProvider::new(0, polynomial, Some(share));
        Self::signer_with_vrf_provider(namespace, participants, individual_key, vrf_materials)
    }

    pub fn signer_with_vrf_provider(
        namespace: &[u8],
        participants: Set<bls12381::PublicKey>,
        individual_key: bls12381::PrivateKey,
        vrf_materials: VrfMaterialProvider<V>,
    ) -> Option<Self> {
        let expected_vrf_material_version = vrf_materials.active_version();
        if vrf_materials.polynomial_total(expected_vrf_material_version)? as usize
            != participants.len()
        {
            tracing::error!(
                polynomial_total = vrf_materials.polynomial_total(expected_vrf_material_version)?,
                participants = participants.len(),
                "polynomial total must equal participant count"
            );
            return None;
        }

        // Verify BLS individual key is in participants
        let bls_public_key = individual_key.public_key();
        let index = participants.index(&bls_public_key)?;

        // Verify share.index matches participant index.
        // If they diverge, threshold partial signatures will use the wrong
        // evaluation point and threshold::recover will fail.
        let share = vrf_materials.share(expected_vrf_material_version)?;
        if index != share.index {
            tracing::error!(
                participant_index = index.get(),
                share_index = share.index.get(),
                "share.index does not match participant index"
            );
            return None;
        }

        // Verify BLS threshold share matches polynomial
        let expected_public =
            vrf_materials.partial_public(expected_vrf_material_version, share.index)?;
        if expected_public != share.public::<V>() {
            return None;
        }

        let scheme_namespace = committee_bound_namespace(namespace, &participants);
        Some(Self {
            role: Role::Signer {
                fields: RoleFields {
                    participants,
                    vrf_materials,
                    expected_vrf_material_version,
                    namespace: scheme_namespace,
                    #[cfg(any(test, feature = "test-utils"))]
                    invalid_seed_partial_for_test: false,
                },
                individual_key,
                index,
            },
        })
    }

    /// Creates a verifier instance (cannot sign).
    ///
    /// Returns `None` if the polynomial total doesn't match participant count.
    pub fn verifier(
        namespace: &[u8],
        participants: Set<bls12381::PublicKey>,
        polynomial: Sharing<V>,
    ) -> Option<Self> {
        let vrf_materials = VrfMaterialProvider::new(0, polynomial, None);
        Self::verifier_with_vrf_provider(namespace, participants, vrf_materials)
    }

    pub fn verifier_with_vrf_provider(
        namespace: &[u8],
        participants: Set<bls12381::PublicKey>,
        vrf_materials: VrfMaterialProvider<V>,
    ) -> Option<Self> {
        let expected_vrf_material_version = vrf_materials.active_version();
        if vrf_materials.polynomial_total(expected_vrf_material_version)? as usize
            != participants.len()
        {
            tracing::error!(
                polynomial_total = vrf_materials.polynomial_total(expected_vrf_material_version)?,
                participants = participants.len(),
                "polynomial total must equal participant count"
            );
            return None;
        }

        let scheme_namespace = committee_bound_namespace(namespace, &participants);
        Some(Self {
            role: Role::Verifier {
                fields: RoleFields {
                    participants,
                    vrf_materials,
                    expected_vrf_material_version,
                    namespace: scheme_namespace,
                    #[cfg(any(test, feature = "test-utils"))]
                    invalid_seed_partial_for_test: false,
                },
            },
        })
    }

    /// Make this signer emit an identity-attributable seed partial over the
    /// wrong message. Used only by the real Simplex engine test harness.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_invalid_seed_partial_for_test(mut self) -> Self {
        if let Role::Signer { fields, .. } = &mut self.role {
            fields.invalid_seed_partial_for_test = true;
        }
        self
    }

    #[cfg(any(test, feature = "test-utils"))]
    fn invalid_seed_partial_for_test(&self) -> bool {
        match &self.role {
            Role::Signer { fields, .. } | Role::Verifier { fields } => {
                fields.invalid_seed_partial_for_test
            }
        }
    }

    /// The committee binding for this scheme, regardless of role - the single
    /// owner of the `Signer`/`Verifier` discrimination for shared-field access.
    fn fields(&self) -> &RoleFields<V> {
        match &self.role {
            Role::Signer { fields, .. } | Role::Verifier { fields, .. } => fields,
        }
    }

    fn participants_ref(&self) -> &Set<bls12381::PublicKey> {
        &self.fields().participants
    }

    fn vrf_materials(&self) -> &VrfMaterialProvider<V> {
        &self.fields().vrf_materials
    }

    fn namespace_ref(&self) -> &Namespace {
        &self.fields().namespace
    }

    /// Returns the public identity of the committee (BLS MinSig group public key).
    pub fn identity(&self) -> Option<V::Public> {
        self.vrf_materials()
            .public(self.expected_vrf_material_version())
    }

    /// Returns the immutable VRF material version pinned when this epoch scheme was built.
    pub fn expected_vrf_material_version(&self) -> u64 {
        self.fields().expected_vrf_material_version
    }

    pub fn verified_vrf_seed_for_round<R>(
        &self,
        _rng: &mut R,
        seed_round: Round,
        certificate: &HybridCertificate<V>,
        _strategy: &impl Strategy,
    ) -> Option<Vec<u8>>
    where
        R: CryptoRngCore,
    {
        let proof = &certificate.vrf_proof;
        if proof.material_version != self.expected_vrf_material_version() {
            return None;
        }
        // The consensus seed namespace is scheme-relative: it MUST match the
        // namespace this scheme's signer used (`namespace_ref().seed`), which
        // equals the global `hybrid_seed_namespace()` only when the scheme is
        // built with `outbe_app_namespace()` (production). The proof-side global
        // verifiers (`seed_partial`, `verifier`) use the constant instead.
        let namespace = self.namespace_ref();
        let seed_message = seed_round.encode();
        if self
            .vrf_materials()
            .verify_proof(proof, &namespace.seed, seed_message.as_ref())
        {
            Some(proof.threshold_signature.encode().to_vec())
        } else {
            None
        }
    }

    pub fn verify_vrf_partial<R, D>(
        &self,
        _rng: &mut R,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
    {
        let Some(signature) = attestation.signature.get() else {
            return false;
        };
        // Scheme-relative namespace (see `verified_vrf_seed_for_round`): match
        // this scheme's signer, not the global proof constant.
        let namespace = self.namespace_ref();
        let seed_message = seed_message_from_subject(&subject);
        self.vrf_materials().verify_partial(VrfPartialVerification {
            version: signature.vrf_material_version,
            signer: attestation.signer,
            namespace: &namespace.seed,
            seed_message: seed_message.as_ref(),
            signature: signature.bls_seed_partial,
        })
    }

    /// Verify the seed-partial identity attestation rides correctly with the
    /// attestation: `true` iff `seed_partial_identity_sig` is the MinPk identity
    /// signature of the participant at `attestation.signer` over
    /// `(round, vrf_material_version, bls_seed_partial)`.
    ///
    /// Deterministic (plain MinPk verify, no batch RNG), so every honest node
    /// reaches the same verdict - required because this drives slashing
    /// attribution. A `true` result proves the signer deliberately emitted this
    /// partial (not a relay forgery); it does NOT assert the partial is valid.
    pub fn verify_seed_partial_identity_sig<D: Digest>(
        &self,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
    ) -> bool {
        let participants = self.participants_ref();
        let Some(public_key) = participants.key(attestation.signer) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };
        let round = round_from_subject(&subject);
        let partial_bytes = signature.bls_seed_partial.encode();
        crate::proof::verify_seed_partial_attest(
            public_key,
            round.epoch().get(),
            round.view().get(),
            signature.vrf_material_version,
            partial_bytes.as_ref(),
            &signature.seed_partial_identity_sig,
        )
    }

    /// Record a non-valid seed-partial verdict after the complete attestation is
    /// excluded from quorum admission. The signer is never returned through the
    /// p2p-invalid channel solely because of a partial problem.
    fn record_seed_partial_drop<D>(
        &self,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        verdict: SeedPartialVerdict,
    ) where
        D: Digest,
    {
        let Some(signature) = attestation.signature.get() else {
            return;
        };
        let round = round_from_subject(&subject);
        crate::metrics::record_vrf_partial_drop(verdict.label(), attestation.signer.get());
        tracing::warn!(
            target: "outbe::hybrid::vrf_partial",
            verdict = verdict.label(),
            signer_index = attestation.signer.get(),
            epoch = round.epoch().get(),
            view = round.view().get(),
            expected_material_version = self.expected_vrf_material_version(),
            received_material_version = signature.vrf_material_version,
            "dropping vote and VRF partial from quorum admission"
        );

        match verdict {
            SeedPartialVerdict::Valid => {}
            SeedPartialVerdict::AttributableInvalid => {
                crate::metrics::record_invalid_vrf_partial();
                // Emit the attributable facts for an external slashing watcher to
                // pack into a SlashIndicator evidence transaction (see README
                // "Slashing"). The node reports facts, not packed wire - keeping
                // the consensus crate independent of the evidence codec. The
                // identity signature makes "this signer emitted this partial"
                // non-repudiable and re-verifiable on chain from the committee
                // snapshot, so the watcher's submission cannot frame an honest
                // node.
                let signer_pubkey = self
                    .participants_ref()
                    .key(attestation.signer)
                    .map(|pk| hex::encode(pk.encode()))
                    .unwrap_or_default();
                tracing::warn!(
                    target: "outbe::slashing::seed_partial",
                    offense = "invalid_seed_partial",
                    signer_index = attestation.signer.get(),
                    signer_pubkey,
                    epoch = round.epoch().get(),
                    view = round.view().get(),
                    vrf_material_version = signature.vrf_material_version,
                    partial = hex::encode(signature.bls_seed_partial.encode()),
                    identity_sig = hex::encode(signature.seed_partial_identity_sig.encode()),
                    "attributable invalid VRF seed partial - slashable; external watcher should submit evidence"
                );
            }
            SeedPartialVerdict::Unattributable => {
                crate::metrics::record_forged_seed_partial();
            }
            SeedPartialVerdict::StaleVersion => {}
        }
    }

    /// Classify a seed partial for attestation verification / slashing
    /// attribution. Deterministic with respect to the identity-sig outcome
    /// (every honest node reaches the same verdict on whether to attribute),
    /// which is required because the attributable verdict feeds slashing.
    pub fn classify_seed_partial<R, D>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        strategy: &impl Strategy,
    ) -> SeedPartialVerdict
    where
        R: CryptoRngCore,
        D: Digest,
    {
        let Some(signature) = attestation.signature.get() else {
            return SeedPartialVerdict::Valid;
        };
        if signature.vrf_material_version != self.expected_vrf_material_version() {
            return SeedPartialVerdict::StaleVersion;
        }
        if self.verify_vrf_partial(rng, subject, attestation, strategy) {
            return SeedPartialVerdict::Valid;
        }
        if self.verify_seed_partial_identity_sig(subject, attestation) {
            SeedPartialVerdict::AttributableInvalid
        } else {
            SeedPartialVerdict::Unattributable
        }
    }
}

/// Verdict for a `bls_seed_partial` observed during attestation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedPartialVerdict {
    /// Active-version partial that verifies against the committee polynomial.
    Valid,
    /// Partial tagged with a non-active material version - legitimately stale
    /// after a reshare; excluded from recovery, not byzantine.
    StaleVersion,
    /// Active-version partial that fails verification, with a valid rider
    /// identity signature proving the signer authored it - slashable byzantine.
    AttributableInvalid,
    /// Active-version partial that fails verification but whose rider identity
    /// signature does not verify - probable relay forgery; drop, do not attribute.
    Unattributable,
}

impl SeedPartialVerdict {
    const fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::StaleVersion => "stale_version",
            Self::AttributableInvalid => "attributable_invalid",
            Self::Unattributable => "unattributable",
        }
    }
}

/// Extracts the consensus round from a Subject (the round the seed partial commits
/// to). This is the single Subject-matching core; the seed message is derived from
/// it (see [`seed_message_from_subject`]) so the round and its seed message can
/// never diverge.
fn round_from_subject<D: Digest>(subject: &Subject<'_, D>) -> Round {
    match subject {
        Subject::Notarize { proposal } | Subject::Finalize { proposal } => proposal.round,
        Subject::Nullify { round } => *round,
    }
}

/// The VRF seed message for a Subject: the canonical `Round::encode()` bytes of the
/// round the seed partial commits to. Derived from [`round_from_subject`], so it
/// stays byte-identical to the proof-side recipe
/// (`proof::constants::seed_namespace_and_message`) - pinned by
/// `seed_message_matches_proof_side_recipe`.
fn seed_message_from_subject<D: Digest>(subject: &Subject<'_, D>) -> bytes::Bytes {
    round_from_subject(subject).encode()
}

impl<V: Variant> certificate::Scheme for HybridScheme<V> {
    type Subject<'a, D: Digest> = Subject<'a, D>;
    type PublicKey = bls12381::PublicKey;
    type Signature = HybridSignature<V>;
    type Certificate = HybridCertificate<V>;

    fn me(&self) -> Option<Participant> {
        match &self.role {
            Role::Signer { index, .. } => Some(*index),
            Role::Verifier { .. } => None,
        }
    }

    fn participants(&self) -> &Set<Self::PublicKey> {
        self.participants_ref()
    }

    fn sign<D: Digest>(&self, subject: Subject<'_, D>) -> Option<Attestation<Self>> {
        let (individual_key, index, vrf_materials, vrf_material_version, namespace) =
            match &self.role {
                Role::Signer {
                    fields,
                    individual_key,
                    index,
                } => (
                    individual_key,
                    *index,
                    &fields.vrf_materials,
                    fields.expected_vrf_material_version,
                    &fields.namespace,
                ),
                Role::Verifier { .. } => return None,
            };

        // BLS individual vote signature (MinPk)
        let vote_namespace = subject.namespace(namespace);
        let message = subject.message();
        let bls_individual_vote = individual_key.sign(vote_namespace, &message);

        // BLS threshold seed partial (MinSig)
        let seed_message = seed_message_from_subject(&subject);
        #[cfg(any(test, feature = "test-utils"))]
        let seed_message = if self.invalid_seed_partial_for_test() {
            b"outbe-test/invalid-seed-partial".to_vec()
        } else {
            seed_message.to_vec()
        };
        let bls_seed_partial =
            vrf_materials.sign_seed(vrf_material_version, &namespace.seed, &seed_message)?;

        // MinPk identity attestation binding the partial to this validator's
        // identity key over (round, version, partial). Makes the partial
        // non-repudiably attributable for slashing (see proof::seed_partial).
        let round = round_from_subject(&subject);
        let seed_partial_identity_sig = {
            let partial_bytes = bls_seed_partial.encode();
            let attest_message = crate::proof::seed_partial_attest_message(
                round.epoch().get(),
                round.view().get(),
                vrf_material_version,
                partial_bytes.as_ref(),
            );
            individual_key.sign(&crate::proof::seed_attest_namespace(), &attest_message)
        };

        let signature = HybridSignature {
            bls_individual_vote,
            vrf_material_version,
            bls_seed_partial,
            seed_partial_identity_sig,
        };

        Some(Attestation {
            signer: index,
            signature: signature.into(),
        })
    }

    fn verify_attestation<R, D>(
        &self,
        _rng: &mut R,
        subject: Subject<'_, D>,
        attestation: &Attestation<Self>,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
    {
        let participants = self.participants_ref();
        let namespace = self.namespace_ref();

        let Some(public_key) = participants.key(attestation.signer) else {
            return false;
        };
        let Some(signature) = attestation.signature.get() else {
            return false;
        };

        // Verify BLS individual vote (MinPk)
        let vote_namespace = subject.namespace(namespace);
        let message = subject.message();
        public_key.verify(vote_namespace, &message, &signature.bls_individual_vote)
    }

    fn verify_attestations<R, D, I>(
        &self,
        rng: &mut R,
        subject: Subject<'_, D>,
        attestations: I,
        strategy: &impl Strategy,
    ) -> Verification<Self>
    where
        R: CryptoRngCore,
        D: Digest,
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
    {
        let mut verified = Vec::new();
        let mut invalid = Vec::new();

        for attestation in attestations {
            if !self.verify_attestation(rng, subject, &attestation, strategy) {
                invalid.push(attestation.signer);
                continue;
            }
            let verdict = self.classify_seed_partial(rng, subject, &attestation, strategy);
            if verdict == SeedPartialVerdict::Valid {
                verified.push(attestation);
            } else {
                self.record_seed_partial_drop(subject, &attestation, verdict);
            }
        }

        Verification::new(verified, invalid)
    }

    fn assemble<I, M>(&self, attestations: I, strategy: &impl Strategy) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Attestation<Self>>,
        I::IntoIter: Send,
        M: Faults,
    {
        let participants = self.participants_ref();

        // Collect and validate attestations
        let mut entries = Vec::new();
        for Attestation { signer, signature } in attestations {
            if usize::from(signer) >= participants.len() {
                return None;
            }
            let sig = signature.get().cloned()?;
            entries.push((signer, sig));
        }

        if entries.len() < participants.quorum::<M>() as usize {
            return None;
        }

        // Sort by signer index
        entries.sort_by_key(|(signer, _)| *signer);
        if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return None;
        }

        let signers_vec: Vec<Participant> = entries.iter().map(|(s, _)| *s).collect();

        // Aggregate individual BLS MinPk vote signatures
        let vote_sigs: Vec<&<MinPk as Variant>::Signature> = entries
            .iter()
            .map(|(_, sig)| sig.bls_individual_vote.as_ref())
            .collect();
        let bls_aggregated_vote = aggregate::combine_signatures::<MinPk, _>(vote_sigs);

        // Every attestation reaching assembly is either locally produced by
        // this pinned scheme or was admitted by `verify_attestations` for the
        // exact subject. Keep the version check fail-closed so a future caller
        // cannot assemble a certificate from a heterogeneous set.
        let expected_vrf_version = self.expected_vrf_material_version();
        let seed_partials: Vec<PartialSignature<V>> = entries
            .iter()
            .filter_map(|(signer, sig)| {
                (sig.vrf_material_version == expected_vrf_version).then_some(PartialSignature {
                    index: *signer,
                    value: sig.bls_seed_partial,
                })
            })
            .collect();
        let quorum = participants.quorum::<M>() as usize;
        if seed_partials.len() < quorum {
            crate::metrics::record_vrf_recover_failed_under_quorum();
            tracing::warn!(
                target: "outbe::hybrid",
                expected_vrf_version,
                quorum,
                seed_partials = seed_partials.len(),
                "refusing to assemble a certificate without a VRF quorum"
            );
            return None;
        }
        let Some(vrf_proof) =
            self.vrf_materials()
                .recover_proof::<M>(expected_vrf_version, &seed_partials, strategy)
        else {
            crate::metrics::record_vrf_recover_failed_under_quorum();
            tracing::warn!(
                target: "outbe::hybrid",
                expected_vrf_version,
                quorum,
                seed_partials = seed_partials.len(),
                "refusing to assemble a certificate after VRF recovery failed"
            );
            return None;
        };

        let signers = Signers::from(participants.len(), signers_vec);

        Some(HybridCertificate {
            signers,
            bls_aggregated_vote,
            vrf_proof,
        })
    }

    fn verify_certificate<R, D, M>(
        &self,
        _rng: &mut R,
        subject: Subject<'_, D>,
        certificate: &Self::Certificate,
        _strategy: &impl Strategy,
    ) -> bool
    where
        R: CryptoRngCore,
        D: Digest,
        M: Faults,
    {
        let participants = self.participants_ref();
        let namespace = self.namespace_ref();

        // Structural checks
        if certificate.signers.len() != participants.len() {
            return false;
        }
        if certificate.signers.count() < participants.quorum::<M>() as usize {
            return false;
        }

        // 1. Verify aggregated BLS MinPk vote signature.
        //    Collect signer public keys, aggregate them, and verify.
        let vote_namespace = subject.namespace(namespace);
        let message = subject.message();

        let signer_pubkeys: Vec<&<MinPk as Variant>::Public> = certificate
            .signers
            .iter()
            .filter_map(|signer| participants.key(signer).map(|pk| pk.as_ref()))
            .collect();

        if signer_pubkeys.len() != certificate.signers.count() {
            return false;
        }

        let aggregate_pk = aggregate::combine_public_keys::<MinPk, _>(signer_pubkeys);
        if aggregate::verify_same_message::<MinPk>(
            &aggregate_pk,
            vote_namespace,
            &message,
            &certificate.bls_aggregated_vote,
        )
        .is_err()
        {
            return false;
        }

        let proof = &certificate.vrf_proof;
        if proof.material_version != self.expected_vrf_material_version() {
            return false;
        }
        let seed_message = seed_message_from_subject(&subject);
        self.vrf_materials()
            .verify_proof(proof, &namespace.seed, seed_message.as_ref())
    }

    fn is_attributable() -> bool {
        true
    }

    fn is_batchable() -> bool {
        false
    }

    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg {
        self.participants_ref().len()
    }

    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg {
        u32::MAX as usize
    }
}

// Seed extraction helpers (`HybridCertificate::seed`, `raw_vrf_seed_bytes`) now
// live in `outbe_consensus::proof::hybrid_wire` alongside the type definition.

// ---------------------------------------------------------------------------
// SchemeProvider for HybridScheme
// ---------------------------------------------------------------------------

/// Epoch-scoped provider of hybrid schemes. Thin typed wrapper over a shared
/// [`EpochRegistry`](crate::epoch_registry::EpochRegistry); it keeps the
/// `certificate::Provider` impl, which the generic registry cannot carry.
#[derive(Clone, Debug)]
pub struct HybridSchemeProvider<V: Variant> {
    inner: crate::epoch_registry::EpochRegistry<HybridScheme<V>>,
}

impl<V: Variant> HybridSchemeProvider<V> {
    /// Create an empty provider.
    pub fn new() -> Self {
        Self {
            inner: crate::epoch_registry::EpochRegistry::new(),
        }
    }

    /// Register a scheme for the given epoch (insert-once).
    pub fn register(&self, epoch: Epoch, scheme: HybridScheme<V>) -> bool {
        self.inner.register(epoch, scheme)
    }

    /// Remove the scheme for the given epoch.
    pub fn remove(&self, epoch: &Epoch) -> bool {
        self.inner.remove(epoch)
    }
}

impl<V: Variant> Default for HybridSchemeProvider<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Variant> certificate::Provider for HybridSchemeProvider<V> {
    type Scope = Epoch;
    type Scheme = HybridScheme<V>;

    fn scoped(&self, scope: Self::Scope) -> Option<Arc<Self::Scheme>> {
        self.inner.get(&scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::bootstrap_dkg;
    use commonware_consensus::{
        simplex::types::{Proposal, Subject},
        types::{Epoch, View},
    };
    use commonware_cryptography::{
        bls12381::primitives::variant::MinSig, certificate::Scheme as _,
        sha256::Digest as Sha256Digest, Hasher, Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::N3f1;
    use rand_core::{CryptoRng, Error as RngError, RngCore};

    use super::test_support::{test_participants, TestScheme, NAMESPACE};

    fn sample_proposal(epoch: Epoch, view: View, tag: u8) -> Proposal<Sha256Digest> {
        Proposal::new(
            Round::new(epoch, view),
            view.previous().unwrap(),
            Sha256::hash(&[tag]),
        )
    }

    struct ZeroRng;

    impl RngCore for ZeroRng {
        fn next_u32(&mut self) -> u32 {
            0
        }

        fn next_u64(&mut self) -> u64 {
            0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ZeroRng {}

    #[test]
    fn test_hybrid_sign_and_verify_attestation() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let scheme0 = HybridScheme::<MinSig>::signer(
            NAMESPACE,
            participants.clone(),
            keys[0].clone(),
            dkg.polynomial.clone(),
            dkg.shares[participants
                .index(&bls12381::PublicKey::from(keys[0].clone()))
                .unwrap()
                .get() as usize]
                .clone(),
        );
        assert!(scheme0.is_some(), "signer scheme should be created");
        let scheme0 = scheme0.unwrap();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let epoch = Epoch::new(1);
        let view = View::new(2);
        let proposal = sample_proposal(epoch, view, 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        // Sign
        let attestation = scheme0.sign::<Sha256Digest>(subject);
        assert!(attestation.is_some());
        let attestation = attestation.unwrap();

        // Verify
        let mut rng = rand_core::OsRng;
        assert!(verifier.verify_attestation(&mut rng, subject, &attestation, &Sequential));
    }

    #[test]
    fn test_hybrid_assemble_and_verify_certificate() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        // Create signer schemes for all participants
        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let epoch = Epoch::new(1);
        let view = View::new(2);
        let proposal = sample_proposal(epoch, view, 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        // Collect attestations from all signers
        let attestations: Vec<Attestation<TestScheme>> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        // Assemble certificate
        let certificate = verifier.assemble::<_, N3f1>(attestations, &Sequential);
        assert!(certificate.is_some(), "certificate assembly should succeed");
        let certificate = certificate.unwrap();

        // Verify certificate structure
        assert_eq!(certificate.signers.count(), 3);

        // Verify certificate
        let mut rng = rand_core::OsRng;
        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            subject,
            &certificate,
            &Sequential
        ));
    }

    #[test]
    fn test_hybrid_is_attributable() {
        assert!(TestScheme::is_attributable());
    }

    #[test]
    fn test_hybrid_is_batchable() {
        assert!(!TestScheme::is_batchable());
    }

    #[test]
    fn test_assemble_rejects_duplicate_signer_without_panic() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let proposal = sample_proposal(Epoch::new(1), View::new(2), 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        let duplicated = vec![
            schemes[0].sign::<Sha256Digest>(subject).unwrap(),
            schemes[0].sign::<Sha256Digest>(subject).unwrap(),
            schemes[1].sign::<Sha256Digest>(subject).unwrap(),
        ];

        assert!(
            verifier
                .assemble::<_, N3f1>(duplicated, &Sequential)
                .is_none(),
            "duplicate signer attestations must be rejected"
        );
    }

    #[test]
    fn test_hybrid_bad_vote_attestation_rejected() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let pk0 = bls12381::PublicKey::from(keys[0].clone());
        let idx0 = participants.index(&pk0).unwrap();
        let scheme0 = HybridScheme::<MinSig>::signer(
            NAMESPACE,
            participants.clone(),
            keys[0].clone(),
            dkg.polynomial.clone(),
            dkg.shares[idx0.get() as usize].clone(),
        )
        .unwrap();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let epoch = Epoch::new(1);
        let view = View::new(2);
        let proposal = sample_proposal(epoch, view, 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        let attestation = scheme0.sign::<Sha256Digest>(subject).unwrap();

        // Tamper with the BLS individual vote - use a different key to produce wrong sig
        let wrong_key = bls12381::PrivateKey::from_seed(99);
        let wrong_sig = wrong_key.sign(b"wrong", b"wrong");
        let mut tampered_sig = attestation.signature.get().cloned().unwrap();
        tampered_sig.bls_individual_vote = wrong_sig;
        let tampered = Attestation {
            signer: attestation.signer,
            signature: commonware_codec::types::lazy::Lazy::from(tampered_sig),
        };

        let mut rng = rand_core::OsRng;
        assert!(!verifier.verify_attestation(&mut rng, subject, &tampered, &Sequential));
    }

    #[test]
    fn assemble_rejects_quorum_without_active_version_partials() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let proposal = sample_proposal(Epoch::new(1), View::new(2), 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        let attestations: Vec<_> = schemes
            .iter()
            .map(|scheme| {
                let mut attestation = scheme.sign::<Sha256Digest>(subject).unwrap();
                let mut signature = attestation.signature.get().cloned().unwrap();
                signature.vrf_material_version = 999;
                attestation.signature = commonware_codec::types::lazy::Lazy::from(signature);
                attestation
            })
            .collect();

        let mut rng = rand_core::OsRng;
        assert!(attestations
            .iter()
            .all(|attestation| verifier.verify_attestation(
                &mut rng,
                subject,
                attestation,
                &Sequential
            )));

        assert!(verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .is_none());
    }

    #[test]
    fn verify_certificate_rejects_wrong_vrf_material_version() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let proposal = sample_proposal(Epoch::new(1), View::new(2), 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };
        let attestations: Vec<_> = schemes
            .iter()
            .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        let mut certificate = verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        certificate.vrf_proof.material_version = 999;

        let mut rng = rand_core::OsRng;
        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            subject,
            &certificate,
            &Sequential
        ));
        assert!(verifier
            .verified_vrf_seed_for_round(
                &mut rng,
                Round::new(Epoch::new(1), View::new(2)),
                &certificate,
                &Sequential
            )
            .is_none());
    }

    #[test]
    fn verify_certificate_rejects_vrf_proof_for_a_different_subject() {
        let (schemes, verifier) = signers_and_verifier(4);
        let proposal = sample_proposal(Epoch::new(1), View::new(2), 42);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let mut certificate = verifier
            .assemble::<_, N3f1>(
                schemes
                    .iter()
                    .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap()),
                &Sequential,
            )
            .unwrap();

        let other_proposal = sample_proposal(Epoch::new(1), View::new(3), 43);
        let other_subject = Subject::Finalize {
            proposal: &other_proposal,
        };
        certificate.vrf_proof = verifier
            .assemble::<_, N3f1>(
                schemes
                    .iter()
                    .map(|scheme| scheme.sign::<Sha256Digest>(other_subject).unwrap()),
                &Sequential,
            )
            .unwrap()
            .vrf_proof;

        assert!(!verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut bls_batch_verification_rng(),
            subject,
            &certificate,
            &Sequential,
        ));
    }

    /// Build `n` signer schemes and a matching verifier from one DKG.
    fn signers_and_verifier(n: u8) -> (Vec<TestScheme>, TestScheme) {
        let (_keys, signers, verifier) = signers_keys_and_verifier(n);
        (signers, verifier)
    }

    #[test]
    fn epoch_scheme_keeps_material_version_after_provider_activation() {
        let (keys, participants) = test_participants(4);
        let dkg = bootstrap_dkg(4).unwrap();
        let public_key = bls12381::PublicKey::from(keys[0].clone());
        let index = participants.index(&public_key).unwrap();
        let share = dkg.shares[index.get() as usize].clone();
        let provider = VrfMaterialProvider::new(0, dkg.polynomial.clone(), Some(share.clone()));
        let scheme = HybridScheme::signer_with_vrf_provider(
            NAMESPACE,
            participants,
            keys[0].clone(),
            provider.clone(),
        )
        .unwrap();

        provider.activate(1, dkg.polynomial, Some(share));

        assert_eq!(
            scheme.expected_vrf_material_version(),
            0,
            "an epoch-scoped scheme must not follow later provider activation"
        );
    }

    #[test]
    fn epoch_scheme_keeps_identity_and_signing_material_after_provider_activation() {
        let (keys, participants) = test_participants(4);
        let initial = bootstrap_dkg(4).unwrap();
        let replacement = bootstrap_dkg(4).unwrap();
        let public_key = bls12381::PublicKey::from(keys[0].clone());
        let index = participants.index(&public_key).unwrap();
        let initial_share = initial.shares[index.get() as usize].clone();
        let replacement_share = replacement.shares[index.get() as usize].clone();
        let expected_identity = *initial.polynomial.public();
        let provider = VrfMaterialProvider::new(0, initial.polynomial, Some(initial_share));
        let scheme = HybridScheme::signer_with_vrf_provider(
            NAMESPACE,
            participants,
            keys[0].clone(),
            provider.clone(),
        )
        .unwrap();

        provider.activate(1, replacement.polynomial, Some(replacement_share));

        assert_eq!(scheme.identity(), Some(expected_identity));
        let proposal = sample_proposal(Epoch::new(1), View::new(2), 42);
        let attestation = scheme
            .sign::<Sha256Digest>(Subject::Finalize {
                proposal: &proposal,
            })
            .unwrap();
        assert_eq!(
            attestation.signature.get().unwrap().vrf_material_version,
            0,
            "the old epoch signer must keep signing with its pinned material"
        );
    }

    #[test]
    fn epoch_scheme_rejects_later_material_proof_retained_by_provider() {
        let (keys, participants) = test_participants(4);
        let initial = bootstrap_dkg(4).unwrap();
        let replacement = bootstrap_dkg(4).unwrap();
        let verifier_provider = VrfMaterialProvider::new(0, initial.polynomial, None);
        let old_verifier = HybridScheme::verifier_with_vrf_provider(
            NAMESPACE,
            participants.clone(),
            verifier_provider.clone(),
        )
        .unwrap();
        verifier_provider.activate(1, replacement.polynomial.clone(), None);

        let replacement_signers: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let public_key = bls12381::PublicKey::from(key.clone());
                let index = participants.index(&public_key).unwrap();
                HybridScheme::signer_with_vrf_provider(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    VrfMaterialProvider::new(
                        1,
                        replacement.polynomial.clone(),
                        Some(replacement.shares[index.get() as usize].clone()),
                    ),
                )
                .unwrap()
            })
            .collect();
        let round = Round::new(Epoch::new(1), View::new(2));
        let proposal = sample_proposal(round.epoch(), round.view(), 42);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let certificate = replacement_signers[0]
            .assemble::<_, N3f1>(
                replacement_signers
                    .iter()
                    .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap()),
                &Sequential,
            )
            .unwrap();
        assert_eq!(certificate.vrf_proof.material_version, 1);

        let mut rng = bls_batch_verification_rng();
        assert!(
            old_verifier
                .verified_vrf_seed_for_round(&mut rng, round, &certificate, &Sequential)
                .is_none(),
            "an epoch verifier must reject a proof from a later retained material version"
        );
    }

    /// Like [`signers_and_verifier`] but also returns the signer private keys
    /// (from the same single DKG, so they match the schemes). Needed to craft
    /// attestations with a hand-built identity signature.
    fn signers_keys_and_verifier(
        n: u8,
    ) -> (Vec<bls12381::PrivateKey>, Vec<TestScheme>, TestScheme) {
        let (keys, participants) = test_participants(n);
        let dkg = bootstrap_dkg(n as u32).unwrap();
        let signers = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();
        let verifier =
            HybridScheme::<MinSig>::verifier(NAMESPACE, participants, dkg.polynomial).unwrap();
        (keys, signers, verifier)
    }

    /// Overwrite `attestation`'s `bls_seed_partial` with `replacement`'s,
    /// keeping the active material version and the individual vote intact. This
    /// is the byzantine partial of the C-02 attack: a well-formed value that
    /// does not verify at this index. `replacement` must be a partial over a
    /// *different* seed message (e.g. a different round) so the grafted value is
    /// distinct from every honest partial - recovery dedups by index but not by
    /// value, and a value equal to a sibling's would be a no-op at this index.
    fn corrupt_seed_partial(
        attestation: &mut Attestation<TestScheme>,
        replacement: &Attestation<TestScheme>,
    ) {
        let other = replacement.signature.get().cloned().unwrap();
        let mut sig = attestation.signature.get().cloned().unwrap();
        sig.bls_seed_partial = other.bls_seed_partial;
        attestation.signature = commonware_codec::types::lazy::Lazy::from(sig);
    }

    /// A byzantine partial for `scheme`: its own valid partial but over a
    /// *different* round, so it is well-formed yet fails verification against
    /// the real round's seed message.
    fn foreign_round_attestation(scheme: &TestScheme) -> Attestation<TestScheme> {
        let foreign = sample_proposal(Epoch::new(1), View::new(98), 0xCC);
        scheme
            .sign::<Sha256Digest>(Subject::Finalize { proposal: &foreign })
            .unwrap()
    }

    /// A vote and its seed partial are one atomic quorum contribution. A single
    /// byzantine partial removes that complete attestation while the remaining
    /// clean n=4 quorum still assembles a valid certificate.
    #[test]
    fn test_byzantine_seed_partial_excluded_keeps_valid_vrf_proof() {
        let (schemes, verifier) = signers_and_verifier(4);
        let round = Round::new(Epoch::new(1), View::new(2));
        let proposal = sample_proposal(round.epoch(), round.view(), 42);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };

        let honest: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        // Corrupt a partial that lands in `threshold::recover`'s interpolation
        // set, with a well-formed-but-wrong value (signer 1's partial over a
        // foreign round). `recover` truncates to `required` partials by index;
        // the control assertion below guards that the chosen index actually
        // poisons recovery, so the regression cannot silently pick a
        // truncated-out index.
        let mut corrupted = honest.clone();
        corrupt_seed_partial(&mut corrupted[1], &foreign_round_attestation(&schemes[1]));

        let mut rng = bls_batch_verification_rng();

        // Control: assembling directly from the corrupted attestations (without
        // admission verification) yields a certificate whose proof does NOT verify - the
        // poison the attack relied on.
        let poisoned = verifier
            .assemble::<_, N3f1>(corrupted.clone(), &Sequential)
            .unwrap();
        assert_eq!(poisoned.vrf_proof.material_version, 0);
        assert!(
            verifier
                .verified_vrf_seed_for_round(&mut rng, round, &poisoned, &Sequential)
                .is_none(),
            "control: the unverified garbage partial poisons the recovered proof"
        );

        // Production path: the batcher drops the whole vote+partial pair.
        let verification = verifier.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject,
            corrupted,
            &Sequential,
        );
        assert!(
            verification.invalid.is_empty(),
            "a partial problem must not p2p-block the authenticated signer"
        );
        assert_eq!(
            verification.verified.len(),
            3,
            "only the three complete valid attestations count"
        );

        let certificate = verifier
            .assemble::<_, N3f1>(verification.verified, &Sequential)
            .unwrap();
        assert_eq!(certificate.signers.count(), 3, "the bad pair is excluded");
        assert_eq!(certificate.vrf_proof.material_version, 0);
        assert!(
            verifier
                .verified_vrf_seed_for_round(&mut rng, round, &certificate, &Sequential)
                .is_some(),
            "the recovered proof must verify against the group key - no halt at N+1"
        );
        assert!(verifier.verify_certificate::<_, Sha256Digest, N3f1>(
            &mut rng,
            subject,
            &certificate,
            &Sequential
        ));
    }

    /// When more than `f` partials are unusable, fewer than quorum complete
    /// attestations remain and no certificate is assembled.
    #[test]
    fn excess_invalid_seed_partials_prevent_certificate_assembly() {
        let (schemes, verifier) = signers_and_verifier(4);
        let round = Round::new(Epoch::new(1), View::new(2));
        let proposal = sample_proposal(round.epoch(), round.view(), 7);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };

        let honest: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        // Corrupt two partials -> only two honest remain (< required = 3).
        let mut corrupted = honest.clone();
        corrupt_seed_partial(&mut corrupted[1], &foreign_round_attestation(&schemes[1]));
        corrupt_seed_partial(&mut corrupted[2], &foreign_round_attestation(&schemes[2]));

        let mut rng = bls_batch_verification_rng();
        let verification = verifier.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject,
            corrupted,
            &Sequential,
        );
        assert!(
            verification.invalid.is_empty(),
            "partial drops do not p2p-block"
        );
        assert_eq!(verification.verified.len(), 2);
        assert!(
            verifier
                .assemble::<_, N3f1>(verification.verified, &Sequential)
                .is_none(),
            "too few complete attestations must never produce a certificate"
        );
    }

    /// Honest path through `verify_attestations` is unchanged: every valid
    /// partial is retained (not retagged), recovery succeeds, and the proof
    /// verifies.
    #[test]
    fn valid_seed_partials_form_a_verifiable_certificate() {
        let (schemes, verifier) = signers_and_verifier(4);
        let round = Round::new(Epoch::new(1), View::new(2));
        let proposal = sample_proposal(round.epoch(), round.view(), 9);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let attestations: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        let mut rng = bls_batch_verification_rng();
        let verification = verifier.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject,
            attestations,
            &Sequential,
        );
        assert_eq!(verification.verified.len(), 4);
        let certificate = verifier
            .assemble::<_, N3f1>(verification.verified, &Sequential)
            .unwrap();
        assert_eq!(certificate.vrf_proof.material_version, 0);
        assert!(
            verifier
                .verified_vrf_seed_for_round(&mut rng, round, &certificate, &Sequential)
                .is_some(),
            "untouched honest partials recover a verifying proof"
        );
    }

    /// Tamper a single field of an attestation's signature, preserving the
    /// signer index. Used to prove the identity-sig binding.
    fn tamper_signature(
        attestation: &Attestation<TestScheme>,
        mutate: impl FnOnce(&mut HybridSignature<MinSig>),
    ) -> Attestation<TestScheme> {
        let mut sig = attestation.signature.get().cloned().unwrap();
        mutate(&mut sig);
        Attestation {
            signer: attestation.signer,
            signature: commonware_codec::types::lazy::Lazy::from(sig),
        }
    }

    #[test]
    fn test_hybrid_signature_size_includes_identity_sig() {
        // MinPk vote (96) + version (8) + MinSig partial (48) + MinPk identity (96).
        assert_eq!(HybridSignature::<MinSig>::SIZE, 96 + 8 + 48 + 96);
    }

    #[test]
    fn test_hybrid_signature_codec_roundtrip_preserves_identity_sig() {
        let (schemes, _verifier) = signers_and_verifier(3);
        let proposal = sample_proposal(Epoch::new(1), View::new(2), 5);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let attestation = schemes[0].sign::<Sha256Digest>(subject).unwrap();
        let sig = attestation.signature.get().cloned().unwrap();
        let encoded = sig.encode();
        assert_eq!(encoded.len(), HybridSignature::<MinSig>::SIZE);
        let decoded = HybridSignature::<MinSig>::read(&mut encoded.as_ref()).unwrap();
        assert_eq!(sig, decoded);
        assert_eq!(
            sig.seed_partial_identity_sig,
            decoded.seed_partial_identity_sig
        );
    }

    #[test]
    fn test_seed_partial_identity_sig_binds_round_version_partial() {
        let (schemes, verifier) = signers_and_verifier(3);
        let proposal = sample_proposal(Epoch::new(1), View::new(2), 7);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let attestation = schemes[0].sign::<Sha256Digest>(subject).unwrap();

        // Happy path: the rider identity sig verifies for the real signer.
        assert!(verifier.verify_seed_partial_identity_sig(subject, &attestation));

        // Different round (different subject) breaks the binding.
        let other_proposal = sample_proposal(Epoch::new(1), View::new(3), 7);
        let other_subject = Subject::Finalize {
            proposal: &other_proposal,
        };
        assert!(!verifier.verify_seed_partial_identity_sig(other_subject, &attestation));

        // Tampered version breaks the binding.
        let bad_version = tamper_signature(&attestation, |s| s.vrf_material_version ^= 1);
        assert!(!verifier.verify_seed_partial_identity_sig(subject, &bad_version));

        // Tampered partial breaks the binding (graft signer 1's partial).
        let other = schemes[1].sign::<Sha256Digest>(subject).unwrap();
        let other_partial = other.signature.get().unwrap().bls_seed_partial;
        let bad_partial = tamper_signature(&attestation, |s| s.bls_seed_partial = other_partial);
        assert!(!verifier.verify_seed_partial_identity_sig(subject, &bad_partial));

        // Re-attributing signer 0's attestation to index 1 fails (wrong key).
        let misattributed = Attestation {
            signer: Participant::new(1),
            signature: attestation.signature.clone(),
        };
        assert!(!verifier.verify_seed_partial_identity_sig(subject, &misattributed));
    }

    #[test]
    fn test_garbage_identity_sig_does_not_censor_the_vote() {
        // A relay that strips/corrupts seed_partial_identity_sig must NOT get the
        // vote rejected - verify_attestation only gates on the MinPk vote.
        let (schemes, verifier) = signers_and_verifier(3);
        let proposal = sample_proposal(Epoch::new(1), View::new(2), 11);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let attestation = schemes[0].sign::<Sha256Digest>(subject).unwrap();
        let wrong_sig = bls12381::PrivateKey::from_seed(424242).sign(b"x", b"y");
        let tampered = tamper_signature(&attestation, |s| s.seed_partial_identity_sig = wrong_sig);

        let mut rng = bls_batch_verification_rng();
        assert!(
            verifier.verify_attestation(&mut rng, subject, &tampered, &Sequential),
            "vote must still verify despite a garbage identity sig"
        );
        assert!(
            !verifier.verify_seed_partial_identity_sig(subject, &tampered),
            "but the identity sig itself must be rejected (no attribution)"
        );
    }

    #[test]
    fn seed_partial_verdict_routes_only_valid_pairs_into_quorum() {
        use crate::proof::{seed_attest_namespace, seed_partial_attest_message};

        let (keys, schemes, verifier) = signers_keys_and_verifier(4);
        let proposal = sample_proposal(Epoch::new(1), View::new(2), 13);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let mut rng = bls_batch_verification_rng();

        let honest = schemes[0].sign::<Sha256Digest>(subject).unwrap();
        let honest_sig = honest.signature.get().cloned().unwrap();

        // Valid: an honest active-version partial.
        assert_eq!(
            verifier.classify_seed_partial(&mut rng, subject, &honest, &Sequential),
            SeedPartialVerdict::Valid
        );

        // StaleVersion: a non-active material version is excluded, not byzantine.
        let stale = tamper_signature(&honest, |s| s.vrf_material_version = 999);
        assert_eq!(
            verifier.classify_seed_partial(&mut rng, subject, &stale, &Sequential),
            SeedPartialVerdict::StaleVersion
        );

        // A well-formed-but-wrong partial value (signer 0 over a foreign round).
        let bad_partial = foreign_round_attestation(&schemes[0])
            .signature
            .get()
            .unwrap()
            .bls_seed_partial;
        let attest_msg = seed_partial_attest_message(1, 2, 0, bad_partial.encode().as_ref());

        // AttributableInvalid: bad partial bound by signer 0's own identity sig.
        let good_identity_sig = keys[0].sign(&seed_attest_namespace(), &attest_msg);
        let attributable = Attestation {
            signer: honest.signer,
            signature: commonware_codec::types::lazy::Lazy::from(HybridSignature::<MinSig> {
                bls_individual_vote: honest_sig.bls_individual_vote.clone(),
                vrf_material_version: 0,
                bls_seed_partial: bad_partial,
                seed_partial_identity_sig: good_identity_sig,
            }),
        };
        assert_eq!(
            verifier.classify_seed_partial(&mut rng, subject, &attributable, &Sequential),
            SeedPartialVerdict::AttributableInvalid
        );

        // Unattributable: same bad partial, but the identity sig is from the
        // WRONG key, so it cannot be attributed to signer 0 (relay-forgery case).
        let wrong_identity_sig =
            bls12381::PrivateKey::from_seed(999).sign(&seed_attest_namespace(), &attest_msg);
        let unattributable = Attestation {
            signer: honest.signer,
            signature: commonware_codec::types::lazy::Lazy::from(HybridSignature::<MinSig> {
                bls_individual_vote: honest_sig.bls_individual_vote.clone(),
                vrf_material_version: 0,
                bls_seed_partial: bad_partial,
                seed_partial_identity_sig: wrong_identity_sig,
            }),
        };
        assert_eq!(
            verifier.classify_seed_partial(&mut rng, subject, &unattributable, &Sequential),
            SeedPartialVerdict::Unattributable
        );

        let routed = verifier.verify_attestations::<_, Sha256Digest, _>(
            &mut rng,
            subject,
            [honest, stale, attributable, unattributable],
            &Sequential,
        );
        assert_eq!(routed.verified.len(), 1, "only the Valid pair counts");
        assert!(
            routed.invalid.is_empty(),
            "partial verdicts are dropped without p2p-blocking the signer"
        );
    }

    #[test]
    fn invalid_seed_partial_verdict_does_not_depend_on_batch_rng_weights() {
        let (keys, schemes, verifier) = signers_keys_and_verifier(4);
        let proposal = sample_proposal(Epoch::new(1), View::new(2), 14);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let honest = schemes[0].sign::<Sha256Digest>(subject).unwrap();
        let honest_signature = honest.signature.get().cloned().unwrap();
        let bad_partial = foreign_round_attestation(&schemes[0])
            .signature
            .get()
            .unwrap()
            .bls_seed_partial;
        let attest_message =
            crate::proof::seed_partial_attest_message(1, 2, 0, bad_partial.encode().as_ref());
        let attributable = Attestation {
            signer: honest.signer,
            signature: commonware_codec::types::lazy::Lazy::from(HybridSignature::<MinSig> {
                bls_individual_vote: honest_signature.bls_individual_vote,
                vrf_material_version: 0,
                bls_seed_partial: bad_partial,
                seed_partial_identity_sig: keys[0]
                    .sign(&crate::proof::seed_attest_namespace(), &attest_message),
            }),
        };

        assert_eq!(
            verifier.classify_seed_partial(&mut ZeroRng, subject, &attributable, &Sequential,),
            SeedPartialVerdict::AttributableInvalid
        );
        assert_eq!(
            verifier.classify_seed_partial(
                &mut bls_batch_verification_rng(),
                subject,
                &attributable,
                &Sequential,
            ),
            SeedPartialVerdict::AttributableInvalid
        );
    }

    #[test]
    fn test_hybrid_certificate_codec_roundtrip() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let epoch = Epoch::new(1);
        let view = View::new(2);
        let proposal = sample_proposal(epoch, view, 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        let attestations: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        let certificate = verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        // Encode and decode
        let encoded = commonware_codec::Encode::encode(&certificate);
        let decoded = HybridCertificate::<MinSig>::read_cfg(
            &mut encoded.as_ref(),
            &verifier.certificate_codec_config(),
        )
        .unwrap();

        assert_eq!(certificate, decoded);
    }

    #[test]
    fn test_hybrid_scheme_provider() {
        let (_, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let provider = HybridSchemeProvider::<MinSig>::new();

        let verifier = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        )
        .unwrap();

        let epoch = Epoch::new(1);
        assert!(provider.register(epoch, verifier));

        // Lookup
        assert!(certificate::Provider::scoped(&provider, epoch).is_some());
        assert!(certificate::Provider::scoped(&provider, Epoch::new(2)).is_none());

        // Remove
        assert!(provider.remove(&epoch));
        assert!(certificate::Provider::scoped(&provider, epoch).is_none());
    }

    #[test]
    fn test_hybrid_certificate_size_small() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    NAMESPACE,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();

        let epoch = Epoch::new(1);
        let view = View::new(2);
        let proposal = sample_proposal(epoch, view, 42);
        let subject = Subject::Notarize {
            proposal: &proposal,
        };

        let attestations: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        let encoded = certificate.encode();
        // Certificate should be much smaller than ed25519 variant.
        // Signers bitmap + aggregated vote + mandatory VRF proof stays compact.
        assert!(
            encoded.len() < 200,
            "certificate should be compact, got {} bytes",
            encoded.len()
        );
    }

    #[test]
    fn test_signer_returns_none_on_polynomial_participant_mismatch() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(4).unwrap(); // 4-validator polynomial

        // 3 participants but 4-validator polynomial -> mismatch -> None
        let result = HybridScheme::<MinSig>::signer(
            NAMESPACE,
            participants.clone(),
            keys[0].clone(),
            dkg.polynomial.clone(),
            dkg.shares[0].clone(),
        );
        assert!(
            result.is_none(),
            "signer should return None on polynomial/participant mismatch"
        );
    }

    #[test]
    fn test_verifier_returns_none_on_polynomial_participant_mismatch() {
        let (_, participants) = test_participants(3);
        let dkg = bootstrap_dkg(4).unwrap(); // 4-validator polynomial

        // 3 participants but 4-validator polynomial -> mismatch -> None
        let result = HybridScheme::<MinSig>::verifier(
            NAMESPACE,
            participants.clone(),
            dkg.polynomial.clone(),
        );
        assert!(
            result.is_none(),
            "verifier should return None on polynomial/participant mismatch"
        );
    }

    #[test]
    fn test_signer_returns_none_on_invalid_key() {
        let (_, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        // Use a key that is NOT in the participant set
        let foreign_key = bls12381::PrivateKey::from_seed(999);
        let result = HybridScheme::<MinSig>::signer(
            NAMESPACE,
            participants.clone(),
            foreign_key,
            dkg.polynomial.clone(),
            dkg.shares[0].clone(),
        );
        assert!(
            result.is_none(),
            "signer should return None when key not in participant set"
        );
    }

    #[test]
    fn test_signer_returns_none_on_share_public_mismatch() {
        let (keys, participants) = test_participants(3);

        // Create two different DKG outputs - shares from dkg2 won't match
        // polynomial from dkg1.
        let dkg1 = bootstrap_dkg(3).unwrap();
        let dkg2 = bootstrap_dkg(3).unwrap();

        // Use key[0] with dkg1's polynomial but dkg2's share[0].
        // share[0] from dkg2 has the same index but different public key
        // because it was generated from a different polynomial.
        let result = HybridScheme::<MinSig>::signer(
            NAMESPACE,
            participants.clone(),
            keys[0].clone(),
            dkg1.polynomial.clone(),
            dkg2.shares[0].clone(), // share from different DKG -> public mismatch
        );
        assert!(
            result.is_none(),
            "signer should return None when share public doesn't match polynomial"
        );
    }

    // Insert-once and poisoned-mutex recovery for the providers' shared storage
    // mechanism are tested directly on `EpochRegistry` (crate::epoch_registry).

    // -----------------------------------------------------------------------
    // signer() rejects share.index != participant index
    // -----------------------------------------------------------------------

    /// signer() with mismatched share.index returns None.
    #[test]
    fn test_signer_share_index_mismatch_returns_none() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let pk0 = bls12381::PublicKey::from(keys[0].clone());
        let correct_idx = participants.index(&pk0).unwrap();

        // Get a share that belongs to a DIFFERENT participant index
        let wrong_share_idx = if correct_idx.get() == 0 {
            1usize
        } else {
            0usize
        };
        let wrong_share = dkg.shares[wrong_share_idx].clone();

        // Verify: the share's index does NOT match participant 0's index
        assert_ne!(
            correct_idx, wrong_share.index,
            "test setup: share must have wrong index"
        );

        let result = HybridScheme::<MinSig>::signer(
            NAMESPACE,
            participants,
            keys[0].clone(),
            dkg.polynomial.clone(),
            wrong_share,
        );
        assert!(
            result.is_none(),
            "signer with mismatched share.index must return None"
        );
    }

    /// signer() with correct share.index succeeds (positive case).
    #[test]
    fn test_signer_correct_share_index_succeeds() {
        let (keys, participants) = test_participants(3);
        let dkg = bootstrap_dkg(3).unwrap();

        let pk0 = bls12381::PublicKey::from(keys[0].clone());
        let idx = participants.index(&pk0).unwrap();
        let correct_share = dkg.shares[idx.get() as usize].clone();

        let result = HybridScheme::<MinSig>::signer(
            NAMESPACE,
            participants,
            keys[0].clone(),
            dkg.polynomial.clone(),
            correct_share,
        );
        assert!(
            result.is_some(),
            "signer with correct share.index must succeed"
        );
    }

    /// The Subject seed message must be byte-identical to the proof-side canonical
    /// recipe `proof::constants::seed_namespace_and_message`, so the hybrid signer,
    /// the hybrid verifier, and the proof-side slashing / next-height-gate verifiers
    /// all derive the same VRF seed message for a given round. Locks this cross-path
    /// determinism invariant against drift in either side.
    #[test]
    fn seed_message_matches_proof_side_recipe() {
        let epoch = Epoch::new(7);
        let view = View::new(42);
        let subject: Subject<'_, Sha256Digest> = Subject::Nullify {
            round: Round::new(epoch, view),
        };

        let hybrid_seed_message = seed_message_from_subject(&subject);
        let (_, proof_seed_message) =
            crate::proof::constants::seed_namespace_and_message(epoch.get(), view.get());

        assert_eq!(hybrid_seed_message.as_ref(), proof_seed_message.as_slice());
        // The seed message is exactly the round's canonical bytes - no path can make
        // the round and its seed message diverge now that one derives from the other.
        assert_eq!(hybrid_seed_message, round_from_subject(&subject).encode());
    }
}
