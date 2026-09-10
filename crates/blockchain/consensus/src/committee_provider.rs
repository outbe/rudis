use alloy_primitives::Address;
use commonware_consensus::types::Epoch;
use std::sync::Arc;

use crate::epoch_registry::EpochRegistry;

/// Epoch-scoped provider of ordered committee snapshots.
///
/// The stored address ordering must match the participant ordering used by the
/// Hybrid certificate signers bitmap for that epoch. Thin typed wrapper over a
/// shared [`EpochRegistry`].
#[derive(Clone, Debug, Default)]
pub struct CommitteeProvider {
    inner: EpochRegistry<Vec<Address>>,
}

impl CommitteeProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, epoch: Epoch, committee: Vec<Address>) -> bool {
        self.inner.register(epoch, committee)
    }

    pub fn remove(&self, epoch: &Epoch) -> bool {
        self.inner.remove(epoch)
    }

    pub fn ordered_committee(&self, epoch: Epoch) -> Option<Arc<Vec<Address>>> {
        self.inner.get(&epoch)
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::address;
    use commonware_consensus::types::Epoch;

    use super::CommitteeProvider;

    #[test]
    fn register_lookup_and_remove() {
        let provider = CommitteeProvider::new();
        let epoch = Epoch::new(3);
        let committee = vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
        ];

        assert!(provider.register(epoch, committee.clone()));
        assert_eq!(
            provider
                .ordered_committee(epoch)
                .expect("committee should exist")
                .as_ref(),
            &committee
        );
        assert!(provider.remove(&epoch));
        assert!(provider.ordered_committee(epoch).is_none());
    }

    #[test]
    fn duplicate_registration_keeps_original_snapshot() {
        let provider = CommitteeProvider::new();
        let epoch = Epoch::new(3);
        let original = vec![address!("0x1111111111111111111111111111111111111111")];
        let replacement = vec![address!("0x2222222222222222222222222222222222222222")];

        assert!(provider.register(epoch, original.clone()));
        assert!(!provider.register(epoch, replacement));
        assert_eq!(
            provider
                .ordered_committee(epoch)
                .expect("committee should exist")
                .as_ref(),
            &original
        );
    }
}
