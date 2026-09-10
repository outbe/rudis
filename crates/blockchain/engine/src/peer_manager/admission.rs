//! Serialized publication of transport admission; DKG membership lives elsewhere.
use commonware_actor::Feedback;
use commonware_p2p::{Address, AddressableManager, AddressableTrackedPeers};
use commonware_utils::ordered::Map;
use eyre::{ensure, eyre, Result};

use super::ingress::PublicKey;

type Peers = AddressableTrackedPeers<PublicKey>;

/// Owns every runtime write to the lookup oracle. Canonical admission and the
/// last published transport set are distinct: DKG temporarily adds its frozen
/// players, but must never replace admission with only that target committee.
pub(super) struct PeerAdmission<O> {
    pub(super) oracle: O,
    index: u64,
    canonical_height: u64,
    canonical: Peers,
    published: Option<Peers>,
}

impl<O: AddressableManager<PublicKey = PublicKey>> PeerAdmission<O> {
    /// Index zero has already been seeded before the network starts.
    pub(super) fn new(oracle: O, canonical_height: u64, canonical: Peers) -> Self {
        Self {
            oracle,
            index: 0,
            canonical_height,
            published: Some(canonical.clone()),
            canonical,
        }
    }

    fn next_index(&self) -> Result<u64> {
        self.index
            .checked_add(1)
            .ok_or_else(|| eyre!("peer-set index exhausted"))
    }

    fn publish(&mut self, index: u64, peers: Peers) -> Result<()> {
        ensure!(index > self.index, "non-increasing P2P peer-set index");
        ensure!(
            self.oracle.track(index, peers.clone()) == Feedback::Ok,
            "P2P oracle closed"
        );
        self.index = index;
        self.published = Some(peers);
        Ok(())
    }

    /// Apply a canonical executed snapshot. Comparing with the actual last
    /// publication (including DKG writes) prevents a false Unchanged cache hit.
    pub(super) fn refresh(&mut self, height: u64, peers: Peers) -> Result<()> {
        if height < self.canonical_height {
            return Ok(());
        }
        match self.published.as_ref() {
            Some(last)
                if last.primary.keys() == peers.primary.keys()
                    && last.secondary.keys() == peers.secondary.keys() =>
            {
                if last.primary.values() != peers.primary.values()
                    || last.secondary.values() != peers.secondary.values()
                {
                    ensure!(
                        self.oracle.overwrite(combine(&peers)) == Feedback::Ok,
                        "P2P oracle closed"
                    );
                }
            }
            _ => self.publish(self.next_index()?, peers.clone())?,
        }
        // Failed writes must leave both caches and the height watermark intact.
        self.published = Some(peers.clone());
        self.canonical = peers;
        self.canonical_height = height;
        Ok(())
    }

    fn with_canonical_admission(&self, peers: Peers) -> Peers {
        let primary = peers.primary;
        let mut secondary = std::collections::BTreeMap::new();
        for (key, address) in peers
            .secondary
            .iter_pairs()
            .chain(self.canonical.primary.iter_pairs())
            .chain(self.canonical.secondary.iter_pairs())
        {
            if primary.keys().position(key).is_none() {
                secondary.insert(key.clone(), address.clone());
            }
        }
        Peers::new(primary, Map::from_iter_dedup(secondary))
    }

    pub(super) fn prepare_dkg(&mut self, primary: Map<PublicKey, Address>) -> Result<u64> {
        let peers = self.with_canonical_admission(primary.into());
        // Preserve the previous retention cadence, but allocate indices in the
        // same owner as canonical refreshes, independent of their arrival order.
        for _ in 0..2 {
            self.publish(self.next_index()?, peers.clone())?;
        }
        Ok(self.index)
    }

    pub(super) fn track(&mut self, index: u64, peers: Peers) -> Result<()> {
        self.publish(index, self.with_canonical_admission(peers))
    }

    pub(super) fn overwrite(&mut self, peers: Map<PublicKey, Address>) -> Result<()> {
        ensure!(
            self.oracle.overwrite(peers) == Feedback::Ok,
            "P2P oracle closed"
        );
        // Recovery may supply addresses different from the cached snapshot. The
        // next canonical refresh must reconcile them rather than report Unchanged.
        self.published = None;
        Ok(())
    }
}

fn combine(peers: &Peers) -> Map<PublicKey, Address> {
    Map::from_iter_dedup(
        peers
            .primary
            .iter_pairs()
            .chain(peers.secondary.iter_pairs())
            .map(|(key, address)| (key.clone(), address.clone())),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{bls12381::PrivateKey, Signer as _};
    use commonware_p2p::{authenticated::lookup, Provider as _};
    use commonware_runtime::{Runner as _, Supervisor as _};
    use std::time::Duration;

    fn peers(seed: u64) -> Map<PublicKey, Address> {
        Map::from_iter_dedup([(
            PrivateKey::from_seed(seed).public_key(),
            Address::Symmetric(format!("127.0.0.{seed}:30400").parse().unwrap()),
        )])
    }

    #[test]
    fn secondary_survives_commonware_retention_across_dkg_rotations() {
        commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
            |context| async move {
                let cfg = lookup::Config::local(
                    PrivateKey::from_seed(1),
                    b"admission-regression",
                    "127.0.0.1:30400".parse().unwrap(),
                    1024,
                );
                let (network, mut oracle) = lookup::Network::new(context.child("network"), cfg);
                let canonical = AddressableTrackedPeers::new(peers(1), peers(5));
                assert_eq!(oracle.track(0, canonical.clone()), Feedback::Ok);
                let _network = network.start();
                let mut updates = oracle.subscribe().await;
                let first = updates.recv().await.unwrap();
                let joiner = PrivateKey::from_seed(5).public_key();
                assert!(first.all.secondary.position(&joiner).is_some());
                let mut admission = PeerAdmission::new(oracle, 0, canonical.clone());
                for rotation in 1..=6 {
                    admission
                        .refresh(rotation * 100, canonical.clone())
                        .unwrap();
                    let index = admission.prepare_dkg(peers(1)).unwrap();
                    let update = loop {
                        let update = updates.recv().await.unwrap();
                        if update.index == index {
                            break update;
                        }
                    };
                    assert!(
                        update.all.secondary.position(&joiner).is_some(),
                        "Commonware evicted secondary identity/IP after rotation {rotation}"
                    );
                    assert!(
                        update.all.primary.position(&joiner).is_none(),
                        "secondary must not become primary"
                    );
                }
            },
        );
    }

    #[test]
    fn canonical_refresh_reconciles_dkg_and_eviction_without_stale_rollback() {
        commonware_runtime::deterministic::Runner::timed(Duration::from_secs(30)).start(
            |context| async move {
                let cfg = lookup::Config::local(
                    PrivateKey::from_seed(1),
                    b"admission-removal",
                    "127.0.0.1:30400".parse().unwrap(),
                    1024,
                );
                let (network, mut oracle) = lookup::Network::new(context.child("network"), cfg);
                let canonical = AddressableTrackedPeers::new(peers(1), peers(5));
                oracle.track(0, canonical.clone());
                let _network = network.start();
                let mut updates = oracle.subscribe().await;
                updates.recv().await.unwrap();
                let mut admission = PeerAdmission::new(oracle, 0, canonical.clone());
                let dealer = PrivateKey::from_seed(1).public_key();
                let joiner = PrivateKey::from_seed(5).public_key();
                let target = PrivateKey::from_seed(6).public_key();
                let index = admission.prepare_dkg(peers(6)).unwrap();
                let dkg = admission.oracle.peer_set(index).await.unwrap();
                assert!(dkg.primary.position(&target).is_some());
                assert!(
                    dkg.secondary.position(&dealer).is_some(),
                    "outgoing dealer lost admission"
                );
                assert!(dkg.secondary.position(&joiner).is_some());

                admission.refresh(100, canonical.clone()).unwrap();
                let restored = admission.oracle.peer_set(index + 1).await.unwrap();
                assert!(
                    restored.primary.position(&dealer).is_some(),
                    "cache ignored intervening DKG write"
                );
                assert!(restored.secondary.position(&joiner).is_some());
                assert!(restored.primary.position(&target).is_none());

                // Registry removal must eventually revoke admission, despite old
                // retained sets and delayed finalized notifications.
                let removed = AddressableTrackedPeers::new(peers(1), Map::default());
                admission.refresh(200, removed.clone()).unwrap();
                admission.refresh(199, canonical).unwrap();
                let mut final_index = 0;
                for _ in 0..3 {
                    final_index = admission.prepare_dkg(peers(1)).unwrap();
                }
                let last = loop {
                    let update = updates.recv().await.unwrap();
                    if update.index == final_index {
                        break update;
                    }
                };
                assert!(
                    last.all.secondary.position(&joiner).is_none(),
                    "removed peer was retained indefinitely"
                );
                assert!(
                    last.all.primary.position(&target).is_none(),
                    "stale DKG target was retained indefinitely"
                );
                assert!(
                    admission.track(final_index, removed).is_err(),
                    "duplicate index accepted"
                );
            },
        );
    }

    #[test]
    fn restart_seed_is_not_rolled_back_by_an_older_finalized_block() {
        let current = Peers::new(peers(1), peers(5));
        let mut admission = PeerAdmission::new(RecordingOracle::default(), 100, current);
        admission
            .refresh(99, Peers::new(peers(1), Map::default()))
            .unwrap();
        admission.prepare_dkg(peers(1)).unwrap();
        let joiner = PrivateKey::from_seed(5).public_key();
        assert!(
            admission.oracle.tracked.iter().all(|(_, peers)| peers
                .secondary
                .keys()
                .position(&joiner)
                .is_some()),
            "restart lost secondary admission to a pre-startup snapshot"
        );
    }

    #[derive(Clone, Debug, Default)]
    struct RecordingOracle {
        closed: bool,
        tracked: Vec<(u64, Peers)>,
        overwritten: Vec<Map<PublicKey, Address>>,
    }

    impl commonware_p2p::Provider for RecordingOracle {
        type PublicKey = PublicKey;
        async fn peer_set(&mut self, _: u64) -> Option<commonware_p2p::TrackedPeers<PublicKey>> {
            None
        }
        async fn subscribe(&mut self) -> commonware_p2p::PeerSetSubscription<PublicKey> {
            commonware_utils::channel::mpsc::unbounded_channel().1
        }
    }

    impl AddressableManager for RecordingOracle {
        fn track<R: Into<Peers> + Send>(&mut self, id: u64, peers: R) -> Feedback {
            if self.closed {
                return Feedback::Closed;
            }
            self.tracked.push((id, peers.into()));
            Feedback::Ok
        }
        fn overwrite(&mut self, peers: Map<PublicKey, Address>) -> Feedback {
            if self.closed {
                return Feedback::Closed;
            }
            self.overwritten.push(peers);
            Feedback::Ok
        }
    }

    #[test]
    fn failed_publication_is_retried_and_addresses_reconcile_after_recovery() {
        let initial = Peers::new(peers(1), Map::default());
        let canonical = Peers::new(peers(1), peers(5));
        let oracle = RecordingOracle {
            closed: true,
            ..Default::default()
        };
        let mut admission = PeerAdmission::new(oracle, 0, initial.clone());
        assert!(admission.refresh(100, canonical.clone()).is_err());
        admission.oracle.closed = false;
        admission.refresh(50, initial).unwrap();
        admission.refresh(100, canonical.clone()).unwrap();
        assert_eq!(
            admission.oracle.tracked.len(),
            1,
            "failed publication poisoned cache"
        );
        assert_eq!(
            admission.oracle.tracked[0].0, 1,
            "failed write consumed index"
        );
        admission.refresh(101, canonical.clone()).unwrap();
        assert_eq!(
            admission.oracle.tracked.len(),
            1,
            "unchanged snapshot churned retention"
        );

        let moved = Map::from_iter_dedup([(
            PrivateKey::from_seed(5).public_key(),
            Address::Symmetric("127.0.0.15:30400".parse().unwrap()),
        )]);
        let moved = Peers::new(peers(1), moved);
        admission.oracle.closed = true;
        assert!(admission.refresh(102, moved.clone()).is_err());
        admission.oracle.closed = false;
        admission.refresh(102, moved.clone()).unwrap();
        assert_eq!(admission.oracle.overwritten.len(), 1);
        assert_eq!(
            admission.oracle.tracked.len(),
            1,
            "address change churned retention"
        );
        assert_eq!(admission.oracle.overwritten[0], combine(&moved));

        admission.overwrite(combine(&canonical)).unwrap();
        admission.refresh(103, moved.clone()).unwrap();
        assert_eq!(
            admission.oracle.tracked.len(),
            2,
            "recovery write left a false Unchanged cache hit"
        );
        assert_eq!(admission.oracle.tracked[1].1.secondary, moved.secondary);
    }
}
