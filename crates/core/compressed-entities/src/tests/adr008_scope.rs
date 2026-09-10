use std::sync::{Arc, Mutex};

use alloy_primitives::B256;
use outbe_primitives::error::{PrecompileError, Result};

use crate::{
    AuthenticatedParentTree, AuthenticatedParentTreeFactory, Commitment, EntityRef,
    ExactParentIdentity, ExecutionScope, FinalLeafMutation, PartitionRef, ProvisionalTreeBatch,
    ACTIVE_COMMITMENT_SCHEME,
};

#[derive(Debug)]
struct RecordingFactory {
    opened: Mutex<Option<ExactParentIdentity>>,
}

impl RecordingFactory {
    fn new() -> Self {
        Self {
            opened: Mutex::new(None),
        }
    }
}

impl AuthenticatedParentTreeFactory for RecordingFactory {
    fn open_parent(
        &self,
        identity: ExactParentIdentity,
    ) -> Result<Arc<dyn AuthenticatedParentTree>> {
        *self.opened.lock().expect("recording lock") = Some(identity);
        Ok(Arc::new(RecordingTree { identity }))
    }
}

#[derive(Debug)]
struct RecordingTree {
    identity: ExactParentIdentity,
}

impl AuthenticatedParentTree for RecordingTree {
    fn parent_block_hash(&self) -> B256 {
        self.identity.block_hash
    }

    fn parent_root(&self) -> B256 {
        self.identity.root
    }

    fn read_leaf_verified(
        &self,
        _entity: EntityRef,
        expected_parent_root: B256,
    ) -> Result<Option<Commitment>> {
        if expected_parent_root != self.identity.root {
            return Err(PrecompileError::TreeUnavailable(
                "test parent root mismatch".into(),
            ));
        }
        Ok(None)
    }

    fn partition_present_verified(
        &self,
        _partition: PartitionRef,
        expected_parent_root: B256,
    ) -> Result<bool> {
        if expected_parent_root != self.identity.root {
            return Err(PrecompileError::TreeUnavailable(
                "test parent root mismatch".into(),
            ));
        }
        Ok(false)
    }

    fn prepare_seal(
        &self,
        _block_number: u64,
        _mutations: &[FinalLeafMutation],
        _retirements: &[PartitionRef],
    ) -> Result<ProvisionalTreeBatch> {
        Err(PrecompileError::Fatal(
            "test tree does not prepare candidates".into(),
        ))
    }
}

#[test]
fn configuring_factory_is_observed_by_an_existing_scope_clone() {
    let lifecycle_scope = Arc::new(ExecutionScope::new());
    let precompile_scope = Arc::clone(&lifecycle_scope);
    let factory = Arc::new(RecordingFactory::new());
    let parent = ExactParentIdentity {
        commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
        block_number: 41,
        block_hash: B256::repeat_byte(0x41),
        root: B256::repeat_byte(0x91),
    };

    lifecycle_scope
        .configure_parent_tree_factory(
            factory.clone(),
            parent.commitment_scheme_version,
            parent.block_number,
            parent.block_hash,
        )
        .unwrap();
    precompile_scope.activate().unwrap();
    precompile_scope.open_exact_parent(parent.root).unwrap();

    assert_eq!(precompile_scope.parent_root().unwrap(), parent.root);
    assert_eq!(*factory.opened.lock().unwrap(), Some(parent));
    precompile_scope.finish().unwrap();
}

#[test]
fn finalized_rpc_scope_reads_without_opening_mutation_lifecycle() {
    let factory = Arc::new(RecordingFactory::new());
    let block_hash = B256::repeat_byte(0x42);
    let root = B256::repeat_byte(0x92);
    let scope = ExecutionScope::for_finalized_rpc(
        factory.clone(),
        ACTIVE_COMMITMENT_SCHEME,
        42,
        block_hash,
    );

    assert_eq!(
        scope
            .read_parent_leaf_verified(
                EntityRef::Tribute(crate::WwdEntityId::from([7_u8; 32])),
                root,
            )
            .unwrap(),
        None
    );
    assert_eq!(
        *factory.opened.lock().unwrap(),
        Some(ExactParentIdentity {
            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
            block_number: 42,
            block_hash,
            root,
        })
    );
    assert!(matches!(scope.activate(), Err(PrecompileError::Fatal(_))));
}

#[test]
fn block_configuration_replaces_finalized_rpc_fallback() {
    let fallback = Arc::new(RecordingFactory::new());
    let execution = Arc::new(RecordingFactory::new());
    let scope = ExecutionScope::for_finalized_rpc(
        fallback,
        ACTIVE_COMMITMENT_SCHEME,
        10,
        B256::repeat_byte(0x10),
    );

    scope
        .configure_parent_tree_factory(
            execution,
            ACTIVE_COMMITMENT_SCHEME,
            11,
            B256::repeat_byte(0x11),
        )
        .unwrap();
    scope.activate().unwrap();
    scope.open_exact_parent(B256::repeat_byte(0x91)).unwrap();
    scope.finish().unwrap();
}

#[test]
fn factory_tree_identity_mismatch_is_corruption_not_readiness() {
    let requested_hash = B256::repeat_byte(0x51);
    let requested_root = B256::repeat_byte(0x61);
    // The factory accepts the requested identity but corrupts the returned
    // root, modelling a malformed local adapter.
    #[derive(Debug)]
    struct WrongRootFactory;
    impl AuthenticatedParentTreeFactory for WrongRootFactory {
        fn open_parent(
            &self,
            mut identity: ExactParentIdentity,
        ) -> Result<Arc<dyn AuthenticatedParentTree>> {
            identity.root = B256::repeat_byte(0x62);
            Ok(Arc::new(RecordingTree { identity }))
        }
    }

    let scope = ExecutionScope::new();
    scope
        .configure_parent_tree_factory(
            Arc::new(WrongRootFactory),
            ACTIVE_COMMITMENT_SCHEME,
            7,
            requested_hash,
        )
        .unwrap();
    assert!(matches!(
        scope.open_exact_parent(requested_root),
        Err(PrecompileError::Fatal(_))
    ));
}
