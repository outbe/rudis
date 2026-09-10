use alloy_primitives::{keccak256, B256};
use core::marker::PhantomData;

use crate::{
    error::Result,
    storage::{CheckpointGuard, StorageHandle},
};

/// Runtime tag used by the execution provider to grant exactly one class of
/// Metadosis mutation. The typed markers below keep command entrypoints from
/// accepting a lease issued for another cause.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MetadosisMutationPurposeTag {
    CycleLifecycle = 0,
    CertifiedFinality = 1,
    ForkProfile = 2,
    OcompLifecycle = 3,
    VerifiedResultVote = 4,
}

/// Compact executor-owned set of purposes admitted by one authenticated
/// dispatch route. It is not authority by itself; the provider consumes it
/// while issuing closure-bounded leases.
const MAX_EXACT_BINDINGS_PER_PURPOSE: usize = 4;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MetadosisMutationEntitlements {
    unbound_counts: [u8; 5],
    exact_bindings: [[Option<B256>; MAX_EXACT_BINDINGS_PER_PURPOSE]; 5],
}

impl MetadosisMutationEntitlements {
    pub const NONE: Self = Self {
        unbound_counts: [0; 5],
        exact_bindings: [[None; MAX_EXACT_BINDINGS_PER_PURPOSE]; 5],
    };

    #[must_use]
    pub const fn only(purpose: MetadosisMutationPurposeTag) -> Self {
        Self::repeated(purpose, 1)
    }

    /// Grants a fixed, route-owned number of sequential leases for one purpose.
    /// This exists because one authenticated system transaction can contain a
    /// small, statically bounded sequence of distinct Metadosis commands.
    #[must_use]
    pub const fn repeated(purpose: MetadosisMutationPurposeTag, count: u8) -> Self {
        let mut counts = [0; 5];
        counts[purpose as usize] = count;
        Self {
            unbound_counts: counts,
            exact_bindings: [[None; MAX_EXACT_BINDINGS_PER_PURPOSE]; 5],
        }
    }

    /// Grants one exact command identity for a provider-authenticated route.
    #[must_use]
    pub const fn exact(purpose: MetadosisMutationPurposeTag, binding: B256) -> Self {
        let mut exact_bindings = [[None; MAX_EXACT_BINDINGS_PER_PURPOSE]; 5];
        exact_bindings[purpose as usize][0] = Some(binding);
        Self {
            unbound_counts: [0; 5],
            exact_bindings,
        }
    }

    #[must_use]
    pub fn union(mut self, other: Self) -> Self {
        for purpose in 0..self.unbound_counts.len() {
            self.unbound_counts[purpose] =
                self.unbound_counts[purpose].saturating_add(other.unbound_counts[purpose]);
            for binding in other.exact_bindings[purpose].into_iter().flatten() {
                if self.exact_bindings[purpose].contains(&Some(binding)) {
                    continue;
                }
                if let Some(slot) = self.exact_bindings[purpose]
                    .iter_mut()
                    .find(|slot| slot.is_none())
                {
                    *slot = Some(binding);
                }
                // Overflow deliberately under-grants authority and therefore
                // fails closed at command entry. Production route inventories
                // are pinned below the fixed cap.
            }
        }
        self
    }

    #[must_use]
    pub const fn allows(self, purpose: MetadosisMutationPurposeTag) -> bool {
        self.unbound_counts[purpose as usize] != 0
            || has_exact_binding(self.exact_bindings[purpose as usize])
    }

    /// Consumes one route entitlement. Exact route bindings take precedence:
    /// when any are configured for the purpose, an unlisted caller-computed
    /// binding is rejected without consuming another command's authority.
    pub fn consume(&mut self, purpose: MetadosisMutationPurposeTag, binding: B256) -> bool {
        let exact = &mut self.exact_bindings[purpose as usize];
        if exact.iter().any(Option::is_some) {
            let Some(slot) = exact.iter_mut().find(|slot| **slot == Some(binding)) else {
                return false;
            };
            *slot = None;
            return true;
        }

        let count = &mut self.unbound_counts[purpose as usize];
        let allowed = *count != 0;
        *count = count.saturating_sub(1);
        allowed
    }

    #[must_use]
    pub fn expects(self, purpose: MetadosisMutationPurposeTag, binding: B256) -> bool {
        self.exact_bindings[purpose as usize].contains(&Some(binding))
    }
}

const fn has_exact_binding(bindings: [Option<B256>; MAX_EXACT_BINDINGS_PER_PURPOSE]) -> bool {
    let mut index = 0;
    while index < bindings.len() {
        if bindings[index].is_some() {
            return true;
        }
        index += 1;
    }
    false
}

/// Exact certificate-derived data accepted by the Metadosis finality command.
///
/// This value is not authority by itself: the EVM provider independently derives
/// and installs the same binding from its verified certificate and preloaded
/// finalized-parent summary before the command can enter its mutation frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadosisCertifiedFinalityBinding {
    chain_id: u64,
    current_block_number: u64,
    finalized_block_number: u64,
    finalized_block_hash: B256,
    finalized_state_root: B256,
    binding: B256,
}

impl MetadosisCertifiedFinalityBinding {
    #[must_use]
    pub fn new(
        chain_id: u64,
        current_block_number: u64,
        finalized_block_number: u64,
        finalized_block_hash: B256,
        finalized_state_root: B256,
    ) -> Self {
        let binding = metadosis_command_binding(
            b"METADOSIS_CERTIFIED_FINALITY_V1",
            &[
                &chain_id.to_be_bytes(),
                &current_block_number.to_be_bytes(),
                &finalized_block_number.to_be_bytes(),
                finalized_block_hash.as_slice(),
                finalized_state_root.as_slice(),
            ],
        );
        Self {
            chain_id,
            current_block_number,
            finalized_block_number,
            finalized_block_hash,
            finalized_state_root,
            binding,
        }
    }

    #[must_use]
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    #[must_use]
    pub const fn current_block_number(&self) -> u64 {
        self.current_block_number
    }

    #[must_use]
    pub const fn finalized_block_number(&self) -> u64 {
        self.finalized_block_number
    }

    #[must_use]
    pub const fn finalized_block_hash(&self) -> B256 {
        self.finalized_block_hash
    }

    #[must_use]
    pub const fn finalized_state_root(&self) -> B256 {
        self.finalized_state_root
    }

    #[must_use]
    pub const fn binding(&self) -> B256 {
        self.binding
    }
}

#[must_use]
pub fn metadosis_init_genesis_binding(chain_id: u64, block_number: u64, timestamp: u64) -> B256 {
    metadosis_block_binding(
        b"METADOSIS_CREATE_DAY_V1",
        chain_id,
        block_number,
        timestamp,
    )
}

#[must_use]
pub fn metadosis_cycle_allocation_binding(
    chain_id: u64,
    block_number: u64,
    timestamp: u64,
) -> B256 {
    metadosis_block_binding(
        b"METADOSIS_CYCLE_ALLOCATION_V1",
        chain_id,
        block_number,
        timestamp,
    )
}

#[must_use]
pub fn metadosis_process_ready_binding(chain_id: u64, block_number: u64, timestamp: u64) -> B256 {
    metadosis_block_binding(
        b"METADOSIS_PROCESS_READY_V1",
        chain_id,
        block_number,
        timestamp,
    )
}

#[must_use]
pub fn metadosis_advance_due_binding(chain_id: u64, block_number: u64, timestamp: u64) -> B256 {
    metadosis_block_binding(
        b"METADOSIS_ADVANCE_DUE_V1",
        chain_id,
        block_number,
        timestamp,
    )
}

#[must_use]
pub fn metadosis_late_settlement_binding(chain_id: u64, block_number: u64, timestamp: u64) -> B256 {
    metadosis_block_binding(
        b"METADOSIS_LATE_SETTLEMENT_HEADROOM_V1",
        chain_id,
        block_number,
        timestamp,
    )
}

#[must_use]
pub fn metadosis_ocomp_lifecycle_begin_binding(
    chain_id: u64,
    block_number: u64,
    timestamp: u64,
) -> B256 {
    metadosis_block_binding(
        b"METADOSIS_OCOMP_LIFECYCLE_BEGIN_V1",
        chain_id,
        block_number,
        timestamp,
    )
}

#[must_use]
pub fn metadosis_ocomp_terminal_request_binding(
    chain_id: u64,
    block_number: u64,
    timestamp: u64,
) -> B256 {
    metadosis_block_binding(
        b"METADOSIS_OCOMP_TERMINAL_REQUEST_V1",
        chain_id,
        block_number,
        timestamp,
    )
}

#[must_use]
pub fn metadosis_verified_vote_binding(data: &[u8]) -> B256 {
    let data_hash = keccak256(data);
    metadosis_command_binding(
        b"METADOSIS_VERIFIED_RESULT_VOTE_V1",
        &[data_hash.as_slice()],
    )
}

fn metadosis_block_binding(
    domain: &[u8],
    chain_id: u64,
    block_number: u64,
    timestamp: u64,
) -> B256 {
    metadosis_command_binding(
        domain,
        &[
            &chain_id.to_be_bytes(),
            &block_number.to_be_bytes(),
            &timestamp.to_be_bytes(),
        ],
    )
}

fn metadosis_command_binding(domain: &[u8], fields: &[&[u8]]) -> B256 {
    let mut encoded = Vec::with_capacity(
        domain.len()
            + fields
                .iter()
                .map(|field| 4usize.saturating_add(field.len()))
                .sum::<usize>(),
    );
    encoded.extend_from_slice(domain);
    for field in fields {
        encoded.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_be_bytes());
        encoded.extend_from_slice(field);
    }
    keccak256(encoded)
}

mod sealed {
    pub trait Sealed {}
}

/// Sealed type-level purpose for a Metadosis mutation lease.
pub trait MetadosisMutationPurpose: sealed::Sealed {
    const TAG: MetadosisMutationPurposeTag;
}

macro_rules! define_purpose {
    ($name:ident, $tag:ident) => {
        #[derive(Debug)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl MetadosisMutationPurpose for $name {
            const TAG: MetadosisMutationPurposeTag = MetadosisMutationPurposeTag::$tag;
        }
    };
}

define_purpose!(MetadosisCycleLifecycle, CycleLifecycle);
define_purpose!(MetadosisCertifiedFinality, CertifiedFinality);
define_purpose!(MetadosisForkProfile, ForkProfile);
define_purpose!(MetadosisOcompLifecycle, OcompLifecycle);
define_purpose!(MetadosisVerifiedResultVote, VerifiedResultVote);

/// Non-cloneable, non-serializable, closure-bounded authority for exactly one
/// Metadosis command class.
///
/// Construction is private to [`StorageHandle::with_metadosis_mutation`]. The
/// storage provider must independently grant the exact purpose for the current
/// executor route before the callback is entered. The lease is never passed to
/// that callback and cannot be obtained from a raw [`StorageHandle`].
///
/// A downstream crate cannot import or construct a lease:
///
/// ```compile_fail
/// use outbe_primitives::storage::MetadosisMutationLease;
/// ```
///
/// A raw storage handle cannot return the internal lease:
///
/// ```compile_fail
/// use alloy_primitives::B256;
/// use outbe_primitives::storage::{MetadosisCycleLifecycle, StorageHandle};
///
/// fn escape(storage: StorageHandle<'_>) {
///     let _escaped = storage.with_metadosis_mutation::<MetadosisCycleLifecycle, _>(
///         B256::ZERO,
///         |lease| Ok(lease),
///     );
/// }
/// ```
struct MetadosisMutationLease<P: MetadosisMutationPurpose> {
    binding: B256,
    chain_id: u64,
    block_number: u64,
    _purpose: PhantomData<P>,
}

impl<P: MetadosisMutationPurpose> MetadosisMutationLease<P> {
    fn new(binding: B256, chain_id: u64, block_number: u64) -> Self {
        Self {
            binding,
            chain_id,
            block_number,
            _purpose: PhantomData,
        }
    }
}

struct MetadosisMutationFrameGuard<'storage> {
    storage: StorageHandle<'storage>,
    purpose: MetadosisMutationPurposeTag,
    binding: B256,
    closed: bool,
}

impl<'storage> MetadosisMutationFrameGuard<'storage> {
    fn open<P: MetadosisMutationPurpose>(
        storage: &StorageHandle<'storage>,
        binding: B256,
        chain_id: u64,
        block_number: u64,
    ) -> Result<Self> {
        storage.with_provider(|provider| {
            provider.begin_metadosis_mutation_frame(P::TAG, binding, chain_id, block_number)
        })?;
        Ok(Self {
            storage: storage.clone(),
            purpose: P::TAG,
            binding,
            closed: false,
        })
    }

    fn close(mut self, completed: bool) -> Result<()> {
        self.closed = true;
        self.storage.with_provider(|provider| {
            provider.finish_metadosis_mutation_frame(self.purpose, self.binding, completed)
        })
    }
}

impl Drop for MetadosisMutationFrameGuard<'_> {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.storage.with_provider(|provider| {
                provider.finish_metadosis_mutation_frame(self.purpose, self.binding, false)
            });
        }
    }
}

impl<'storage> StorageHandle<'storage> {
    /// Runs one purpose-bound Metadosis command in a provider-granted frame and
    /// a journal checkpoint. Nested Metadosis mutation is rejected by the
    /// provider before the callback (and therefore before aggregate reads).
    pub fn with_metadosis_mutation<P, R>(
        &self,
        binding: B256,
        f: impl FnOnce() -> Result<R>,
    ) -> Result<R>
    where
        P: MetadosisMutationPurpose,
    {
        let chain_id = self.chain_id()?;
        let block_number = self.block_number()?;
        let checkpoint: CheckpointGuard<'storage> = self.checkpoint_guard();
        let frame = MetadosisMutationFrameGuard::open::<P>(self, binding, chain_id, block_number)?;
        let lease = MetadosisMutationLease::<P>::new(binding, chain_id, block_number);
        let outcome = f();
        // Keep the non-forgeable lease alive for the full command callback.
        let _ = (lease.binding, lease.chain_id, lease.block_number);
        frame.close(outcome.is_ok())?;
        let value = outcome?;
        checkpoint.commit();
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use alloy_primitives::{address, B256, U256};

    use super::*;
    use crate::{
        error::PrecompileError,
        storage::{hashmap::HashMapStorageProvider, MetadosisVerifiedResultVote},
    };

    const OWNER: alloy_primitives::Address = address!("0x0000000000000000000000000000000000001003");
    const SLOT: U256 = U256::from_limbs([7, 0, 0, 0]);

    #[test]
    fn matching_purpose_commits_and_binds_chain_and_block() {
        let mut provider = HashMapStorageProvider::new(42);
        provider.set_block_number(9);
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        let binding = B256::repeat_byte(0x11);

        provider
            .enter(|storage| {
                let command_storage = storage.clone();
                storage.with_metadosis_mutation::<MetadosisCycleLifecycle, _>(binding, || {
                    assert_eq!(command_storage.chain_id()?, 42);
                    assert_eq!(command_storage.block_number()?, 9);
                    command_storage.sstore(OWNER, SLOT, U256::from(7))
                })
            })
            .unwrap();

        assert_eq!(provider.storage.get(&(OWNER, SLOT)), Some(&U256::from(7)));
    }

    #[test]
    fn callback_error_reverts_the_entire_frame() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);

        let result = provider.enter(|storage| {
            let command_storage = storage.clone();
            storage.with_metadosis_mutation::<MetadosisCycleLifecycle, ()>(
                B256::repeat_byte(0x22),
                || {
                    command_storage.sstore(OWNER, SLOT, U256::from(9))?;
                    Err(PrecompileError::Fatal("reject".into()))
                },
            )
        });

        assert!(result.is_err());
        assert_eq!(provider.storage.get(&(OWNER, SLOT)), None);
    }

    #[test]
    fn mismatched_purpose_rejects_before_callback() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        let called = Cell::new(false);

        let result = provider.enter(|storage| {
            storage.with_metadosis_mutation::<MetadosisVerifiedResultVote, _>(
                B256::repeat_byte(0x33),
                || {
                    called.set(true);
                    Ok(())
                },
            )
        });

        assert!(result.is_err());
        assert!(!called.get());
    }

    #[test]
    fn nested_mutation_rejects_before_nested_callback() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);
        let nested_called = Cell::new(false);

        provider
            .enter(|storage| {
                let nested_storage = storage.clone();
                storage.with_metadosis_mutation::<MetadosisCycleLifecycle, _>(
                    B256::repeat_byte(0x44),
                    || {
                        let nested = nested_storage
                            .with_metadosis_mutation::<MetadosisCycleLifecycle, _>(
                                B256::repeat_byte(0x45),
                                || {
                                    nested_called.set(true);
                                    Ok(())
                                },
                            );
                        assert!(nested.is_err());
                        Ok(())
                    },
                )
            })
            .unwrap();

        assert!(!nested_called.get());
    }

    #[test]
    fn test_provider_entitlement_is_single_use_like_production() {
        let mut provider = HashMapStorageProvider::new(1);
        provider.enable_metadosis_mutation_frame(MetadosisMutationPurposeTag::CycleLifecycle);

        provider
            .enter(|storage| {
                storage.with_metadosis_mutation::<MetadosisCycleLifecycle, _>(
                    B256::repeat_byte(0x51),
                    || Ok(()),
                )
            })
            .unwrap();

        let called = Cell::new(false);
        let result = provider.enter(|storage| {
            storage.with_metadosis_mutation::<MetadosisCycleLifecycle, _>(
                B256::repeat_byte(0x52),
                || {
                    called.set(true);
                    Ok(())
                },
            )
        });
        assert!(result.is_err());
        assert!(!called.get());
    }
}
