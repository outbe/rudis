//! VRF-based leader election for the hybrid consensus scheme.
//!
//! Lifted out of `hybrid.rs`: `HybridRandom` (elector config), the
//! `HybridRandomElector` it builds, and the epoch-scoped
//! `HybridElectorConfigProvider`. The dependency is one-way - election consumes
//! `HybridScheme` / `HybridCertificate` / `VrfMaterialProvider` from the parent
//! module; the scheme/materials never reference election.

use commonware_codec::Encode;
use commonware_consensus::simplex::elector;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381::{
    self,
    primitives::variant::{MinSig, Variant},
};
use commonware_utils::{modulo, ordered::Set, Participant};
use std::sync::Arc;

use super::{HybridCertificate, HybridScheme, VrfMaterialProvider};

/// Configuration for hybrid VRF-based leader election.
///
/// Uses the BLS seed from `HybridCertificate` for unpredictable leader selection.
/// The very first produced view after chain genesis has no previous certificate and
/// therefore falls back to round-robin. Epoch restarts can provide a bootstrap seed
/// from the last finalized certificate of the previous epoch so that view 1 of later
/// epochs keeps using VRF-derived leader selection.
#[derive(Clone, Debug)]
pub struct HybridRandom<V: Variant = MinSig> {
    bootstrap_seed: Option<Vec<u8>>,
    vrf_materials: Option<VrfMaterialProvider<V>>,
    expected_vrf_material_version: Option<u64>,
}

impl<V: Variant> Default for HybridRandom<V> {
    fn default() -> Self {
        Self {
            bootstrap_seed: None,
            vrf_materials: None,
            expected_vrf_material_version: None,
        }
    }
}

impl<V: Variant> HybridRandom<V> {
    pub fn with_vrf_materials(vrf_materials: VrfMaterialProvider<V>) -> Self {
        let expected_vrf_material_version = vrf_materials.active_version();
        Self {
            bootstrap_seed: None,
            vrf_materials: Some(vrf_materials),
            expected_vrf_material_version: Some(expected_vrf_material_version),
        }
    }

    /// Use a previous finalized certificate's seed bytes to bootstrap view 1
    /// leader selection for a newly started epoch.
    pub fn with_bootstrap_seed(seed: Vec<u8>) -> Self {
        Self {
            bootstrap_seed: Some(seed),
            vrf_materials: None,
            expected_vrf_material_version: None,
        }
    }

    pub fn with_bootstrap_seed_and_vrf_materials(
        seed: Vec<u8>,
        vrf_materials: VrfMaterialProvider<V>,
    ) -> Self {
        let expected_vrf_material_version = vrf_materials.active_version();
        Self {
            bootstrap_seed: Some(seed),
            vrf_materials: Some(vrf_materials),
            expected_vrf_material_version: Some(expected_vrf_material_version),
        }
    }
}

impl<V: Variant> elector::Config<HybridScheme<V>> for HybridRandom<V> {
    type Elector = HybridRandomElector<V>;

    fn build(self, participants: &Set<bls12381::PublicKey>) -> HybridRandomElector<V> {
        assert!(!participants.is_empty(), "no participants");
        HybridRandomElector {
            n: participants.len() as u32,
            bootstrap_seed: self.bootstrap_seed,
            vrf_materials: self.vrf_materials,
            expected_vrf_material_version: self.expected_vrf_material_version,
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Initialized hybrid random elector.
#[derive(Clone, Debug)]
pub struct HybridRandomElector<V: Variant> {
    n: u32,
    bootstrap_seed: Option<Vec<u8>>,
    vrf_materials: Option<VrfMaterialProvider<V>>,
    expected_vrf_material_version: Option<u64>,
    _phantom: std::marker::PhantomData<V>,
}

/// Largest descending span [`elect`] probes to recover a certificate's true
/// certified seed-round. Equal to `MAX_MISSED_PROPOSERS` (`reporter.rs`), the cap
/// on a view gap, so any anchor certificate that can legitimately reach `elect`
/// via the missed-proposer recompute loop is within range; a gap wider than this
/// is already truncated by that loop, and `elect` degrades safely (fail-closed).
const SEED_ROUND_WINDOW: u64 = u8::MAX as u64;

impl<V: Variant> elector::Elector<HybridScheme<V>> for HybridRandomElector<V> {
    fn elect(&self, round: Round, certificate: Option<&HybridCertificate<V>>) -> Participant {
        let verified_seed = match (
            certificate,
            &self.vrf_materials,
            self.expected_vrf_material_version,
        ) {
            (Some(certificate), Some(provider), Some(expected_version)) => {
                let proof = &certificate.vrf_proof;
                (proof.material_version == expected_version)
                    .then_some(proof)
                    .and_then(|proof| {
                        // The certificate's VRF proof is a threshold BLS signature
                        // over the round its seed-partials signed; it verifies for
                        // EXACTLY that one round (single-message property), so no
                        // attacker can make it pass for a different round. `elect`
                        // is not handed the certificate's own round, so recover it
                        // by probing a bounded descending window of candidate
                        // seed-rounds and taking the first (hence only) match.
                        //
                        // LIVE consensus path: commonware always supplies the cert
                        // of the immediately preceding view, so dv == 1 matches and
                        // this is a single verify - byte-identical leader to the
                        // previous single-guess code. Larger dv occurs ONLY in the
                        // missed-proposer attribution recompute
                        // (`missed_proposers::elected_leaders_for_gap`), which feeds
                        // one finalized anchor certificate (from an earlier view) to
                        // `elect` for every interior view of a multi-view gap. The
                        // old code mis-verified that anchor against `view - 1` and
                        // spuriously degraded; the probe recovers the anchor's true
                        // round instead, so the recompute no longer trips the
                        // `outbe_vrf_degraded_leader_selection_total` alarm (which is
                        // now reserved for a genuinely unverifiable live cert).
                        let namespace = crate::config::simplex_namespace();
                        let cur_view = round.view().get();
                        (1..=SEED_ROUND_WINDOW)
                            .find_map(|dv| {
                                let v = cur_view.checked_sub(dv).filter(|&v| v != 0)?;
                                let seed_round = Round::new(round.epoch(), View::new(v));
                                provider
                                    .verify_proof(
                                        proof,
                                        &namespace.seed,
                                        seed_round.encode().as_ref(),
                                    )
                                    .then_some(dv)
                            })
                            .map(|dv| {
                                let mut seed = proof.threshold_signature.encode().to_vec();
                                // When the anchor certificate is older than view - 1
                                // (dv > 1 - the recompute case), one certificate
                                // serves multiple gap views; bind the seed to the
                                // ELECTED round so each view gets a distinct leader
                                // instead of collapsing to one. The live path
                                // (dv == 1) keeps the raw threshold-signature seed,
                                // so its leader selection is unchanged.
                                if dv > 1 {
                                    seed.extend_from_slice(round.encode().as_ref());
                                }
                                seed
                            })
                    })
            }
            _ => None,
        };

        let seed_bytes = verified_seed
            .or_else(|| {
                (round.view() == commonware_consensus::types::View::new(1))
                    .then(|| self.bootstrap_seed.clone())
                    .flatten()
            })
            .or_else(|| self.degraded_seed(round, certificate));

        let Some(seed_bytes) = seed_bytes else {
            let leader = Participant::new(
                (round.epoch().get().wrapping_add(round.view().get())) as u32 % self.n,
            );
            tracing::debug!(
                epoch = round.epoch().get(),
                view = round.view().get(),
                leader = leader.get(),
                "leader elected via round-robin (no usable VRF seed)"
            );
            return leader;
        };

        let leader = Participant::new(modulo(seed_bytes.as_ref(), self.n as u64) as u32);
        tracing::debug!(
            epoch = round.epoch().get(),
            view = round.view().get(),
            leader = leader.get(),
            has_certificate = certificate.is_some(),
            has_bootstrap_seed = self.bootstrap_seed.is_some(),
            "leader elected via verified/degraded VRF seed"
        );
        leader
    }
}

impl<V: Variant> HybridRandomElector<V> {
    fn degraded_seed(
        &self,
        round: Round,
        certificate: Option<&HybridCertificate<V>>,
    ) -> Option<Vec<u8>> {
        let _certificate = certificate?;
        crate::metrics::record_vrf_degraded_leader_selection();
        let mut seed = self.bootstrap_seed.clone().unwrap_or_default();
        if seed.is_empty() {
            return None;
        }
        seed.extend_from_slice(&round.encode());
        tracing::warn!(
            epoch = round.epoch().get(),
            view = round.view().get(),
            "verified VRF proof missing or invalid; using deterministic degraded leader seed"
        );
        Some(seed)
    }
}

/// Epoch-scoped provider of leader elector configs.
///
/// The config includes the epoch bootstrap seed used by the Simplex elector.
/// Metadata validation uses this to recompute missed-proposer attribution with
/// the same deterministic inputs as the reporter path.
#[derive(Clone, Debug)]
pub struct HybridElectorConfigProvider<V: Variant> {
    inner: crate::epoch_registry::EpochRegistry<HybridRandom<V>>,
}

impl<V: Variant> HybridElectorConfigProvider<V> {
    /// Create an empty provider.
    pub fn new() -> Self {
        Self {
            inner: crate::epoch_registry::EpochRegistry::new(),
        }
    }

    /// Register the elector config for the given epoch (insert-once).
    pub fn register(&self, epoch: Epoch, config: HybridRandom<V>) -> bool {
        self.inner.register(epoch, config)
    }

    /// Remove the config for the given epoch.
    pub fn remove(&self, epoch: &Epoch) -> bool {
        self.inner.remove(epoch)
    }

    /// Return the registered config for an epoch.
    pub fn scoped(&self, epoch: Epoch) -> Option<Arc<HybridRandom<V>>> {
        self.inner.get(&epoch)
    }
}

impl<V: Variant> Default for HybridElectorConfigProvider<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::bootstrap_dkg;
    use crate::hybrid::test_support::{test_participants, TestScheme, NAMESPACE};
    use commonware_consensus::simplex::elector::{Config as _, Elector as _};
    use commonware_consensus::{simplex::types::Subject, types::View};
    use commonware_cryptography::{certificate::Scheme as _, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::{ordered::Quorum as _, N3f1};

    #[test]
    fn test_hybrid_elector() {
        let (_, participants) = test_participants(3);

        let elector: HybridRandomElector<MinSig> = HybridRandom::default().build(&participants);

        // View 1 should fall back to round-robin (no certificate)
        let round = Round::new(Epoch::new(0), View::new(1));
        let leader = elector.elect(round, None);
        assert!(leader.get() < 3);
    }

    #[test]
    fn test_hybrid_elector_epoch_view_one_uses_bootstrap_seed() {
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

        let epoch = Epoch::new(0);
        let view = View::new(2);
        let subject = Subject::Nullify {
            round: Round::new(epoch, view),
        };

        let attestations: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        let seed = certificate.raw_vrf_seed_bytes();

        let elector: HybridRandomElector<MinSig> =
            HybridRandom::with_bootstrap_seed(seed.clone()).build(&participants);

        let leader = elector.elect(Round::new(Epoch::new(1), View::new(1)), None);
        let expected = Participant::new(modulo(seed.as_ref(), participants.len() as u64) as u32);

        assert_eq!(leader, expected);
    }

    #[test]
    fn test_hybrid_elector_with_certificate() {
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
        let subject = Subject::Nullify {
            round: Round::new(epoch, view),
        };

        let attestations: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();

        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();

        let elector: HybridRandomElector<MinSig> = HybridRandom::default().build(&participants);

        // With certificate, should get deterministic leader
        let round = Round::new(epoch, View::new(3));
        let leader1 = elector.elect(round, Some(&certificate));
        let leader2 = elector.elect(round, Some(&certificate));
        assert_eq!(leader1, leader2, "same certificate should give same leader");
    }

    // --- seed-round recovery (multi-view-gap) regression tests --------------
    // These exercise the verify branch (which needs vrf_materials, unlike the
    // tests above that use HybridRandom::default()). They reproduce the S2
    // membership-change scenario where the missed-proposer recompute feeds ONE
    // anchor certificate to elect() for every interior view of a multi-view gap.

    /// Build `n` signer schemes over a fresh DKG and assemble a certificate whose
    /// VRF proof certifies `cert_round`, plus a verifier-side material provider
    /// (version 0, matching `HybridScheme::signer`). Returns the participant set,
    /// the provider, and the certificate.
    fn cert_over_round(
        n: u8,
        cert_round: Round,
    ) -> (
        commonware_utils::ordered::Set<bls12381::PublicKey>,
        VrfMaterialProvider<MinSig>,
        HybridCertificate<MinSig>,
    ) {
        let (keys, participants) = test_participants(n);
        let dkg = bootstrap_dkg(n as u32).unwrap();
        // Build under the production base namespace (not the test NAMESPACE): the
        // seed sub-namespace derives from the base (committee_bound_namespace only
        // rebinds notarize/nullify/finalize), and `elect` verifies the proof under
        // `simplex_namespace().seed = Namespace::new(outbe_app_namespace()).seed`.
        // Matching the base makes the scheme's seed-partials verify in `elect`,
        // exactly as in production.
        let base_ns = crate::proof::constants::outbe_app_namespace();
        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = participants.index(&pk).unwrap();
                HybridScheme::signer(
                    &base_ns,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();
        let subject = Subject::Nullify { round: cert_round };
        let attestations: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<Sha256Digest>(subject).unwrap())
            .collect();
        let certificate = schemes[0]
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        let provider = VrfMaterialProvider::<MinSig>::new(0, dkg.polynomial.clone(), None);
        (participants, provider, certificate)
    }

    /// Reference leader: `modulo(raw_seed [++ encode(elected)], n)`. `mix` mirrors
    /// the production rule - the elected round is appended only for the recompute
    /// (dv > 1) case, never the live (dv == 1) case.
    fn expected_leader(raw: &[u8], mix: Option<Round>, n: usize) -> Participant {
        let mut seed = raw.to_vec();
        if let Some(r) = mix {
            seed.extend_from_slice(r.encode().as_ref());
        }
        Participant::new(modulo(seed.as_ref(), n as u64) as u32)
    }

    fn round_robin_leader(round: Round, n: usize) -> Participant {
        Participant::new((round.epoch().get().wrapping_add(round.view().get())) as u32 % n as u32)
    }

    #[test]
    fn epoch_elector_rejects_later_material_after_shared_provider_activation() {
        let epoch = Epoch::new(1);
        let cert_round = Round::new(epoch, View::new(10));
        let (keys, participants) = test_participants(4);
        let dkg = bootstrap_dkg(4).unwrap();
        let base_ns = crate::proof::constants::outbe_app_namespace();
        let schemes: Vec<TestScheme> = keys
            .iter()
            .map(|key| {
                let public_key = bls12381::PublicKey::from(key.clone());
                let index = participants.index(&public_key).unwrap();
                HybridScheme::signer(
                    &base_ns,
                    participants.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[index.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();
        let subject = Subject::Nullify { round: cert_round };
        let mut certificate = schemes[0]
            .assemble::<_, N3f1>(
                schemes
                    .iter()
                    .map(|scheme| scheme.sign::<Sha256Digest>(subject).unwrap()),
                &Sequential,
            )
            .unwrap();
        let provider = VrfMaterialProvider::new(0, dkg.polynomial.clone(), None);
        let raw_proof = certificate.raw_vrf_seed_bytes();
        let proof_leader = expected_leader(&raw_proof, None, participants.len());
        let bootstrap_seed = vec![0xA5; 32];
        let elected_round = (11_u64..=255)
            .map(|view| Round::new(epoch, View::new(view)))
            .find(|round| {
                expected_leader(
                    &[bootstrap_seed.as_slice(), round.encode().as_ref()].concat(),
                    None,
                    participants.len(),
                ) != proof_leader
            })
            .unwrap();
        let expected_degraded = expected_leader(
            &[bootstrap_seed.as_slice(), elected_round.encode().as_ref()].concat(),
            None,
            participants.len(),
        );
        let config =
            HybridRandom::with_bootstrap_seed_and_vrf_materials(bootstrap_seed, provider.clone());

        provider.activate(1, dkg.polynomial, None);
        certificate.vrf_proof.material_version = 1;
        let elector = config.build(&participants);

        assert_eq!(
            elector.elect(elected_round, Some(&certificate)),
            expected_degraded,
            "an old epoch elector must not accept a proof retagged to a later material version"
        );
    }

    #[test]
    fn elect_live_path_dv1_is_unchanged_raw_seed() {
        // dv == 1: certificate of view V-1, electing V - the live consensus path.
        // Must use the RAW threshold-signature seed (no round mix): byte-identical
        // leader to the pre-fix single-guess code.
        let epoch = Epoch::new(1);
        let (participants, provider, cert) = cert_over_round(4, Round::new(epoch, View::new(10)));
        let n = participants.len();
        let elector = HybridRandom::with_vrf_materials(provider).build(&participants);
        let raw = cert.raw_vrf_seed_bytes();

        let elected = Round::new(epoch, View::new(11)); // dv == 1
        assert_eq!(
            elector.elect(elected, Some(&cert)),
            expected_leader(raw.as_ref(), None, n),
        );
    }

    #[test]
    fn elect_recompute_dv_gt_1_recovers_round_and_does_not_degrade() {
        // dv == 3: one anchor cert over view V, electing V+3 (an interior view of a
        // multi-view gap). Pre-fix this verified against V+2 != V and degraded;
        // post-fix the window recovers V and elects via the verified, round-mixed
        // seed. Pinning the exact verified value proves no degrade occurred.
        let epoch = Epoch::new(1);
        let (participants, provider, cert) = cert_over_round(4, Round::new(epoch, View::new(10)));
        let n = participants.len();
        let elector = HybridRandom::with_vrf_materials(provider).build(&participants);
        let raw = cert.raw_vrf_seed_bytes();

        let elected = Round::new(epoch, View::new(13)); // dv == 3
        let verified = expected_leader(raw.as_ref(), Some(elected), n);
        // Precondition: with these params the verified leader differs from the
        // degraded/round-robin leader, so the equality below genuinely proves the
        // verified path was taken (and not a coincidental round-robin match).
        assert_ne!(verified, round_robin_leader(elected, n));
        assert_eq!(elector.elect(elected, Some(&cert)), verified);
    }

    #[test]
    fn elect_recompute_gap_views_do_not_collapse_to_one_leader() {
        // The interior views of a gap, served by ONE anchor cert, must be bound to
        // their own elected round (per-view seed mix) and not all collapse to a
        // single leader. Verify each matches its per-view reference, and that the
        // dv>1 views are distinct from the raw-seed value.
        let epoch = Epoch::new(1);
        let (participants, provider, cert) = cert_over_round(7, Round::new(epoch, View::new(20)));
        let n = participants.len();
        let elector = HybridRandom::with_vrf_materials(provider).build(&participants);
        let raw = cert.raw_vrf_seed_bytes();

        let v21 = Round::new(epoch, View::new(21)); // dv 1 -> raw
        let v22 = Round::new(epoch, View::new(22)); // dv 2 -> raw ++ encode(v22)
        let v23 = Round::new(epoch, View::new(23)); // dv 3 -> raw ++ encode(v23)
        assert_eq!(
            elector.elect(v21, Some(&cert)),
            expected_leader(raw.as_ref(), None, n)
        );
        assert_eq!(
            elector.elect(v22, Some(&cert)),
            expected_leader(raw.as_ref(), Some(v22), n)
        );
        assert_eq!(
            elector.elect(v23, Some(&cert)),
            expected_leader(raw.as_ref(), Some(v23), n)
        );
        // Determinism (reporter == verifier recompute): re-electing is stable.
        assert_eq!(
            elector.elect(v22, Some(&cert)),
            elector.elect(v22, Some(&cert))
        );
    }

    #[test]
    fn elect_gap_beyond_window_degrades_fail_closed() {
        // A gap wider than SEED_ROUND_WINDOW: the anchor's true round lies outside
        // the probe window, so no candidate verifies and elect falls through to the
        // round-robin path (fail-closed) rather than accepting a wrong-round seed.
        let epoch = Epoch::new(1);
        let (participants, provider, cert) = cert_over_round(4, Round::new(epoch, View::new(2)));
        let n = participants.len();
        let elector = HybridRandom::with_vrf_materials(provider).build(&participants);

        // Smallest probed view is (elected - WINDOW) = cert_view + 1, so the true
        // round (cert_view) is never reached.
        let elected = Round::new(epoch, View::new(2 + SEED_ROUND_WINDOW + 1));
        assert_eq!(
            elector.elect(elected, Some(&cert)),
            round_robin_leader(elected, n),
        );
    }
}
