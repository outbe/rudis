//! Generic epoch-scoped registry of `Arc<T>` with insert-once semantics and
//! mutex-poison recovery.
//!
//! Single home for the storage mechanism shared by `CommitteeProvider`,
//! `HybridSchemeProvider`, and `HybridElectorConfigProvider`: each is a thin
//! typed wrapper that adds only its own surface (`ordered_committee`, the
//! `certificate::Provider` impl, `scoped`) over an `EpochRegistry<T>`.

use commonware_consensus::types::Epoch;
use std::{
    collections::{hash_map::Entry, HashMap},
    sync::{Arc, Mutex, MutexGuard},
};

/// Epoch-indexed registry of `Arc<T>`.
///
/// `register` is insert-once: the first value for an epoch wins and a duplicate
/// registration is ignored (returns `false`). A poisoned mutex is recovered in
/// place - the stored map is plain data, so a panic-poisoned lock does not
/// corrupt it, and a panic on one path cannot wedge the providers.
pub struct EpochRegistry<T> {
    inner: Arc<Mutex<HashMap<Epoch, Arc<T>>>>,
}

impl<T> EpochRegistry<T> {
    pub fn new() -> Self {
        Self::default()
    }

    fn guard(&self) -> MutexGuard<'_, HashMap<Epoch, Arc<T>>> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            tracing::error!("EpochRegistry mutex poisoned, recovering");
            poisoned.into_inner()
        })
    }

    /// Insert-once: returns `true` if `value` was stored, `false` if an entry
    /// for `epoch` already existed (the original is kept).
    pub fn register(&self, epoch: Epoch, value: T) -> bool {
        match self.guard().entry(epoch) {
            Entry::Vacant(entry) => {
                entry.insert(Arc::new(value));
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Remove the entry for `epoch`; returns `true` if one was present.
    pub fn remove(&self, epoch: &Epoch) -> bool {
        self.guard().remove(epoch).is_some()
    }

    /// Return the `Arc<T>` registered for `epoch`, if any.
    pub fn get(&self, epoch: &Epoch) -> Option<Arc<T>> {
        self.guard().get(epoch).cloned()
    }
}

// Manual impls: the registry only holds an `Arc`, so it is `Clone`/`Default`
// regardless of whether `T` is - avoids spurious `T: Clone`/`T: Default` bounds
// the derives would add.
impl<T> Clone for EpochRegistry<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T> Default for EpochRegistry<T> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl<T> std::fmt::Debug for EpochRegistry<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochRegistry").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_is_insert_once_and_get_remove_work() {
        let reg: EpochRegistry<u32> = EpochRegistry::new();
        let e = Epoch::new(3);
        assert!(reg.register(e, 10));
        assert_eq!(reg.get(&e).as_deref(), Some(&10));
        // Duplicate registration is ignored; the original value is kept.
        assert!(!reg.register(e, 99));
        assert_eq!(reg.get(&e).as_deref(), Some(&10));
        assert!(reg.remove(&e));
        assert!(reg.get(&e).is_none());
        assert!(!reg.remove(&e));
    }

    #[test]
    fn clone_shares_the_same_map() {
        let a: EpochRegistry<u32> = EpochRegistry::new();
        let b = a.clone();
        assert!(a.register(Epoch::new(1), 7));
        // The clone shares the same Arc-backed map, so it sees a's registration.
        assert_eq!(b.get(&Epoch::new(1)).as_deref(), Some(&7));
    }

    #[test]
    fn recovers_from_a_poisoned_mutex() {
        let reg: EpochRegistry<u32> = EpochRegistry::new();
        assert!(reg.register(Epoch::new(1), 1));

        // Poison the mutex by panicking while holding the lock.
        let clone = reg.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = clone.inner.lock().unwrap();
            panic!("intentional poison");
        }));
        assert!(result.is_err());

        // Every operation recovers the lock in place.
        assert!(reg.register(Epoch::new(2), 2));
        assert_eq!(reg.get(&Epoch::new(2)).as_deref(), Some(&2));
        assert!(reg.remove(&Epoch::new(2)));
    }
}
