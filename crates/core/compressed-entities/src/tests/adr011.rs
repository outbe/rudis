use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    addresses::COMPRESSED_ENTITIES_ADDRESS,
    error::{PrecompileError, Result},
    storage::{hashmap::HashMapStorageProvider, StorageHandle},
};

use crate::{
    begin_block, end_block, mint, retire_partition, sealed_root, AuthenticatedParentTree,
    AuthenticatedParentTreeFactory, BodyInput, Commitment, EntityRef, ExactParentIdentity,
    ExecutionScope, FinalLeafMutation, PartitionRef, ProvisionalTreeBatch, RetirementOutcome,
    TributeBodyV1, WwdEntityId, ACTIVE_COMMITMENT_SCHEME,
};

#[derive(Debug)]
struct PresentTree {
    root: B256,
    present: bool,
}

impl AuthenticatedParentTree for PresentTree {
    fn parent_block_hash(&self) -> B256 {
        B256::repeat_byte(0x41)
    }

    fn parent_root(&self) -> B256 {
        self.root
    }

    fn read_leaf_verified(
        &self,
        _entity: EntityRef,
        expected_parent_root: B256,
    ) -> Result<Option<Commitment>> {
        assert_eq!(expected_parent_root, self.root);
        Ok(None)
    }

    fn partition_present_verified(
        &self,
        _partition: PartitionRef,
        expected_parent_root: B256,
    ) -> Result<bool> {
        assert_eq!(expected_parent_root, self.root);
        Ok(self.present)
    }

    fn prepare_seal(
        &self,
        block_number: u64,
        _mutations: &[FinalLeafMutation],
        _retirements: &[PartitionRef],
    ) -> Result<ProvisionalTreeBatch> {
        ProvisionalTreeBatch::new_fixture_single_collection(
            block_number,
            B256::repeat_byte(0x41),
            self.root,
            self.root,
            Default::default(),
            Default::default(),
        )
        .map_err(|error| PrecompileError::Fatal(error.to_string()))
    }
}

#[derive(Debug)]
struct PresentFactory {
    root: B256,
    present: bool,
}

impl AuthenticatedParentTreeFactory for PresentFactory {
    fn open_parent(&self, parent: ExactParentIdentity) -> Result<Arc<dyn AuthenticatedParentTree>> {
        assert_eq!(parent.root, self.root);
        Ok(Arc::new(PresentTree {
            root: self.root,
            present: self.present,
        }))
    }
}

fn with_active_scope(present: bool, test: impl FnOnce(StorageHandle<'_>, &ExecutionScope)) {
    let root = sealed_root(B256::ZERO).unwrap();
    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(root.as_slice()),
            )
            .unwrap();
        let scope = ExecutionScope::new();
        scope
            .configure_parent_tree_factory(
                Arc::new(PresentFactory { root, present }),
                ACTIVE_COMMITMENT_SCHEME,
                7,
                B256::repeat_byte(0x41),
            )
            .unwrap();
        begin_block(storage.clone(), &scope).unwrap();
        test(storage, &scope);
    });
}

fn tribute(day: WorldwideDay) -> TributeBodyV1 {
    TributeBodyV1 {
        tribute_id: WwdEntityId::from_day_and_digest(day, [7; 32]),
        owner: Address::repeat_byte(7),
        worldwide_day: day,
        issuance_amount_minor: U256::from(1),
        issuance_currency: 840,
        nominal_amount_minor: U256::from(1),
        reference_currency: 840,
        tribute_price_minor: U256::from(1),
        exclude_from_intex_issuance: false,
    }
}

#[test]
fn duplicate_retirement_and_retirement_then_mutation_are_rejected() {
    with_active_scope(true, |storage, scope| {
        let day = WorldwideDay::new(20_260_717);
        assert_eq!(
            retire_partition(storage.clone(), scope, PartitionRef::TributeWwd(day)).unwrap(),
            RetirementOutcome::Requested
        );
        assert!(retire_partition(storage.clone(), scope, PartitionRef::TributeWwd(day)).is_err());
        assert!(mint(storage, scope, BodyInput::Tribute(&tribute(day))).is_err());
    });
}

#[test]
fn mutation_then_retirement_is_rejected() {
    with_active_scope(true, |storage, scope| {
        let day = WorldwideDay::new(20_260_717);
        mint(storage.clone(), scope, BodyInput::Tribute(&tribute(day))).unwrap();
        assert!(retire_partition(storage, scope, PartitionRef::TributeWwd(day)).is_err());
    });
}

#[test]
fn absent_partition_is_noop_and_checkpoint_reverts_the_complete_request() {
    with_active_scope(false, |storage, scope| {
        let day = WorldwideDay::new(20_260_717);
        assert_eq!(
            retire_partition(storage, scope, PartitionRef::TributeWwd(day)).unwrap(),
            RetirementOutcome::NotPresent
        );
    });

    with_active_scope(true, |storage, scope| {
        let day = WorldwideDay::new(20_260_717);
        let rolled_back: Result<()> = storage.with_checkpoint(|| {
            assert_eq!(
                retire_partition(storage.clone(), scope, PartitionRef::TributeWwd(day))?,
                RetirementOutcome::Requested
            );
            Err(PrecompileError::Revert("rollback retirement".into()))
        });
        assert!(rolled_back.is_err());
        assert_eq!(
            retire_partition(storage, scope, PartitionRef::TributeWwd(day)).unwrap(),
            RetirementOutcome::Requested
        );
    });
}

#[test]
fn invalid_wwd_and_calls_outside_the_active_phase_are_rejected_and_cleanup_is_complete() {
    with_active_scope(true, |storage, scope| {
        assert!(retire_partition(
            storage.clone(),
            scope,
            PartitionRef::TributeWwd(WorldwideDay::new(20_261_340)),
        )
        .is_err());

        let day = WorldwideDay::new(20_260_717);
        assert_eq!(
            retire_partition(storage.clone(), scope, PartitionRef::TributeWwd(day)).unwrap(),
            RetirementOutcome::Requested
        );
        end_block(storage.clone(), scope).unwrap();
        assert!(retire_partition(storage.clone(), scope, PartitionRef::TributeWwd(day)).is_err());

        let next_scope = ExecutionScope::new();
        next_scope
            .configure_parent_tree_factory(
                Arc::new(PresentFactory {
                    root: sealed_root(B256::ZERO).unwrap(),
                    present: true,
                }),
                ACTIVE_COMMITMENT_SCHEME,
                8,
                B256::repeat_byte(0x41),
            )
            .unwrap();
        begin_block(storage.clone(), &next_scope).unwrap();
        assert_eq!(
            retire_partition(storage, &next_scope, PartitionRef::TributeWwd(day)).unwrap(),
            RetirementOutcome::Requested,
            "the previous block must leave no retirement marker or touched-list entry"
        );
    });
}
