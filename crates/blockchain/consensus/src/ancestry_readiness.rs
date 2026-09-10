use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

/// Shared readiness gate for ancestry reads that may fall through to marshal.
///
/// The application handler uses this as a fast local guard before making
/// consensus-critical ancestry decisions. The executor actor advances
/// `ready_height` only after a finalized block has been successfully applied to
/// execution, so startup backfill exposes one source of truth instead of a
/// separate stack-level heuristic.
#[derive(Clone, Debug)]
pub struct AncestryReadiness {
    ready_height: Arc<AtomicU64>,
    target_height: Arc<AtomicU64>,
}

impl AncestryReadiness {
    pub fn new(ready_height: u64, target_height: u64) -> Self {
        Self {
            ready_height: Arc::new(AtomicU64::new(ready_height)),
            target_height: Arc::new(AtomicU64::new(target_height)),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready_height() >= self.target_height()
    }

    pub fn ready_height(&self) -> u64 {
        self.ready_height.load(Ordering::Acquire)
    }

    pub fn target_height(&self) -> u64 {
        self.target_height.load(Ordering::Acquire)
    }

    pub fn set_target_height(&self, height: u64) {
        self.target_height.store(height, Ordering::Release);
    }

    pub fn note_ready_height(&self, height: u64) {
        self.ready_height.fetch_max(height, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::AncestryReadiness;

    #[test]
    fn readiness_tracks_target_and_monotonic_ready_height() {
        let readiness = AncestryReadiness::new(2, 5);
        assert!(!readiness.is_ready());

        readiness.note_ready_height(4);
        assert!(!readiness.is_ready());

        readiness.note_ready_height(5);
        assert!(readiness.is_ready());

        readiness.note_ready_height(3);
        assert_eq!(readiness.ready_height(), 5);

        readiness.set_target_height(6);
        assert!(!readiness.is_ready());
    }
}
