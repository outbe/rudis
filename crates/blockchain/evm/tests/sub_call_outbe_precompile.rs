//! sub-call -> outbe precompile visibility test.
//!
//! Verifies that after outbe-precompile propagation, a sub-call driven by
//! `sub_call::run` can reach an outbe stateful precompile and returns its
//! output. The target is the stateless Poseidon-BN254 hash precompile at
//! `ZKPROOF_POSEIDON_ADDRESS` (`0xEE07`), chosen because it needs no state or
//! contract setup: raw bytes in, 32-byte hash out.
//!
//! This proves the child frame uses `OutbeSubCallPrecompiles` (which dispatches
//! outbe addresses) rather than plain `EthPrecompiles`. With the old wiring the
//! call to `0xEE07` would fall through to an empty-account call and return
//! `Success` with empty returndata; here we assert the returndata equals the
//! Poseidon hash of the input.

use std::sync::Arc;

use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use outbe_compressed_entities::{
    begin_block, body_commitment, encode_nod_item_v1, AuthenticatedParentTree, CeWorkConfig,
    Commitment, EntityRef, ExecutionScope, FinalLeafMutation, PartitionRef, ProvisionalTreeBatch,
    ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};
use outbe_evm::sub_call;
use outbe_nod::{precompile::INod, NodBucketState, NodItemState, NodRepositoryWriter};
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle, StorageWriterHandle};
use outbe_primitives::addresses::{
    COMPRESSED_ENTITIES_ADDRESS, NOD_ADDRESS, STABLECOIN_POLICY_REGISTRY_ADDRESS, UPDATE_ADDRESS,
    ZKPROOF_POSEIDON_ADDRESS,
};
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::{
    block::BlockContext,
    storage::{direct::DirectStorageProvider, StorageHandle, SubCallInput, SubCallStatus},
};
use outbe_stablecoinpolicy::precompile::IStablecoinPolicyRegistry;
use revm::{
    database::{CacheDB, EmptyDB},
    handler::MainContext as _,
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Context,
};

const CALLER: Address = Address::new([0xC0; 20]);
const POSEIDON_CALLER: Address = Address::new([0xA7; 20]);

#[derive(Debug)]
struct StaticAuthenticatedParent {
    entity: EntityRef,
    commitment: Commitment,
}

impl AuthenticatedParentTree for StaticAuthenticatedParent {
    fn parent_block_hash(&self) -> B256 {
        B256::ZERO
    }

    fn parent_root(&self) -> B256 {
        outbe_compressed_entities::sealed_root(B256::ZERO).unwrap()
    }

    fn read_leaf_verified(
        &self,
        entity: EntityRef,
        expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<Option<Commitment>> {
        assert_eq!(
            expected_parent_root,
            outbe_compressed_entities::sealed_root(B256::ZERO).unwrap()
        );
        Ok((entity == self.entity).then_some(self.commitment))
    }

    fn partition_present_verified(
        &self,
        _partition: PartitionRef,
        _expected_parent_root: B256,
    ) -> outbe_primitives::error::Result<bool> {
        Ok(false)
    }

    fn prepare_seal(
        &self,
        block_number: u64,
        _mutations: &[FinalLeafMutation],
        _retirements: &[PartitionRef],
    ) -> outbe_primitives::error::Result<ProvisionalTreeBatch> {
        ProvisionalTreeBatch::new_identity(block_number, B256::ZERO, B256::ZERO)
            .map_err(|error| outbe_primitives::error::PrecompileError::Fatal(error.to_string()))
    }
}

#[test]
fn subcall_reaches_outbe_poseidon_precompile() {
    // No account is inserted for the precompile address: outbe precompiles are
    // dispatched by the provider, not backed by real accounts/bytecode.
    let mut ctx = Context::mainnet().with_db(CacheDB::new(EmptyDB::default()));

    // One 32-byte BN254 field element as Poseidon input.
    let mut input = [0u8; 32];
    input[31] = 0x2a;
    let calldata = Bytes::from(input.to_vec());

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        /* outer_is_static = */ false,
        SpecId::PRAGUE,
        None,
        Arc::new(ExecutionScope::new()),
        SubCallInput {
            target: ZKPROOF_POSEIDON_ADDRESS,
            value: U256::ZERO,
            calldata,
            gas_limit: 1_000_000,
            is_static: true,
        },
    )
    .expect("sub_call should not return a fatal error");

    assert!(
        matches!(result.status, SubCallStatus::Success),
        "expected Success, got {:?}",
        result.status,
    );

    // The child frame must have dispatched the outbe Poseidon precompile, so
    // the returndata is the 32-byte hash of the input (not an empty payload).
    let expected =
        outbe_evm::zk::poseidon_hash(&input).expect("poseidon hash over one field element");
    assert_eq!(
        result.returndata.as_ref(),
        expected.as_slice(),
        "sub-call returndata must equal the outbe Poseidon precompile output",
    );
    assert_eq!(result.returndata.len(), 32, "poseidon output is 32 bytes");

    assert!(
        result.gas_used > 0 && result.gas_used < 1_000_000,
        "gas_used must be within the requested budget, got {}",
        result.gas_used,
    );
}

#[test]
fn subcall_reaches_stablecoin_policy_registry_with_canonical_view_output() {
    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_storage(UPDATE_ADDRESS, U256::ZERO, U256::from(2u64))
        .unwrap();
    let mut ctx = Context::mainnet().with_db(db);
    let calldata = IStablecoinPolicyRegistry::policyExistsCall {
        policyId: U256::from(1u64),
    }
    .abi_encode();

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        false,
        SpecId::PRAGUE,
        None,
        Arc::new(ExecutionScope::new()),
        SubCallInput {
            target: STABLECOIN_POLICY_REGISTRY_ADDRESS,
            value: U256::ZERO,
            calldata: calldata.into(),
            gas_limit: 100_000,
            is_static: true,
        },
    )
    .expect("policy registry sub-call");

    assert!(matches!(result.status, SubCallStatus::Success));
    assert!(
        IStablecoinPolicyRegistry::policyExistsCall::abi_decode_returns(&result.returndata)
            .unwrap()
    );
}

#[test]
fn contract_originated_poseidon_call_preserves_empty_shared_buffer_behavior() {
    // The nested frame currently starts with an empty SharedMemory, so its input
    // range cannot materialize the caller's 32-byte memory. Poseidon therefore
    // rejects the empty calldata and CALL returns zero. SCF-020 characterizes this
    // pre-activation behavior; changing it requires an explicit protocol boundary.
    let mut code = vec![
        0x60, 0x01, // PUSH1 1
        0x60, 0x00, // PUSH1 0
        0x52, // MSTORE: one field element at memory[0..32]
        0x60, 0x20, // return size
        0x60, 0x20, // return offset
        0x60, 0x20, // input size
        0x60, 0x00, // input offset
        0x60, 0x00, // value
        0x73, // PUSH20 poseidon address
    ];
    code.extend_from_slice(ZKPROOF_POSEIDON_ADDRESS.as_slice());
    code.extend_from_slice(&[
        0x61, 0x07, 0x08, // PUSH2 1,800 gas
        0xf1, // CALL
        0x60, 0x40, // status output offset
        0x52, // MSTORE CALL status
        0x60, 0x20, // return size
        0x60, 0x40, // return offset
        0xf3, // RETURN
    ]);

    let mut db = CacheDB::new(EmptyDB::default());
    let bytecode = Bytecode::new_raw(Bytes::from(code));
    db.insert_account_info(
        POSEIDON_CALLER,
        AccountInfo {
            code_hash: bytecode.hash_slow(),
            code: Some(bytecode),
            ..Default::default()
        },
    );
    let mut ctx = Context::mainnet().with_db(db);

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        false,
        SpecId::PRAGUE,
        None,
        Arc::new(ExecutionScope::new()),
        SubCallInput {
            target: POSEIDON_CALLER,
            value: U256::ZERO,
            calldata: Bytes::new(),
            gas_limit: 100_000,
            is_static: false,
        },
    )
    .expect("outer contract call");

    assert!(matches!(result.status, SubCallStatus::Success));
    assert_eq!(result.returndata.len(), 32);
    assert_eq!(
        result.returndata[31], 0,
        "inner Poseidon CALL must preserve pre-activation failure"
    );
}

#[test]
fn subcall_reaches_nod_with_the_same_runtime_body_readers() {
    let adapter = Arc::new(MemoryStorage::new());
    let reader: StorageReaderHandle = adapter.clone();
    let writer: StorageWriterHandle = adapter;
    let readers = RuntimeBodyReaders::new(reader.clone());
    let owner = Address::repeat_byte(0x11);
    let day = WorldwideDay::new(20_260_715);
    let nod_id = outbe_nod::NodContract::generate_nod_id(owner, day).unwrap();
    let bucket_key = B256::repeat_byte(0x42);
    let repository = NodRepositoryWriter::new(reader, writer);
    repository
        .put_bucket(&NodBucketState {
            bucket_key,
            worldwide_day: day,
            floor_price_minor: U256::from(10),
            is_qualified: true,
            total_nods: 1,
            entry_price_minor: U256::from(9),
            reference_currency: 978,
        })
        .unwrap();
    let item = NodItemState {
        nod_id,
        owner,
        gratis_load_minor: U256::from(11),
        worldwide_day: day,
        league_id: 3,
        floor_price_minor: U256::from(10),
        bucket_key,
        issuance_currency: 840,
        reference_currency: 978,
        issued_at: 1_700_000_000,
    };
    repository.put_nod(&item).unwrap();
    let payload = encode_nod_item_v1(&outbe_nod::canonical_item(&item)).unwrap();
    let commitment =
        body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, nod_id, &payload).unwrap();
    let mut database = CacheDB::new(EmptyDB::default());
    let scope = Arc::new(ExecutionScope::with_parent_tree(
        Arc::new(StaticAuthenticatedParent {
            entity: EntityRef::NodItem(nod_id),
            commitment,
        }),
        CeWorkConfig::new(0, 0, u64::MAX),
    ));
    let block = BlockContext::new(1, 1, outbe_primitives::chain::CHAIN_ID, owner, vec![owner]);
    let mut provider = DirectStorageProvider::new(&mut database, block);
    StorageHandle::enter(&mut provider, |storage| {
        storage
            // Consensus EVM compressed-entity schema v4. This is distinct from
            // the node-local compressed-tree persistence schema.
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4_u64))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1_u64),
                U256::from_be_slice(
                    outbe_compressed_entities::sealed_root(B256::ZERO)
                        .unwrap()
                        .as_slice(),
                ),
            )
            .unwrap();
        begin_block(storage, scope.as_ref()).unwrap();
    });
    provider.flush().unwrap();

    let calldata = INod::ownerOfCall {
        nodId: nod_id.to_u256(),
    }
    .abi_encode();
    let mut ctx = Context::mainnet().with_db(database);

    let result = sub_call::run(
        &mut ctx,
        CALLER,
        false,
        SpecId::PRAGUE,
        Some(readers),
        scope,
        SubCallInput {
            target: NOD_ADDRESS,
            value: U256::ZERO,
            calldata: Bytes::from(calldata),
            gas_limit: 1_000_000,
            is_static: true,
        },
    )
    .expect("repository-backed Nod sub-call must execute");

    assert!(
        matches!(result.status, SubCallStatus::Success),
        "expected Success, got {:?} with returndata 0x{}",
        result.status,
        hex::encode(&result.returndata),
    );
    assert_eq!(
        INod::ownerOfCall::abi_decode_returns(&result.returndata).unwrap(),
        owner
    );
}
