use alloy_primitives::{address, Address, B256, U256};
use alloy_sol_types::SolCall;
use outbe_compressed_entities::{
    begin_block, end_block, EntityRef, ExecutionScope, IdPage, IdPageRequest, ParentBodySource,
    ParentBodySourceError, QueryRef, StoredBody,
};
use outbe_nod::NodRepositoryReader;
use outbe_offchain_storage::{MemoryStorage, StorageReaderHandle};
use outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS;
use outbe_primitives::block::{BlockContext, BlockRuntimeContext};
use outbe_primitives::storage::dsl::StorageRecord;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::{MetadosisMutationPurposeTag, StorageHandle};
use outbe_promislimit::PromisLimitContract;
use outbe_tribute::{TributeContract, TributeData, TributeRepositoryReader};
use std::sync::Arc;

use crate::constants::*;
use crate::fixture_kernel::FixtureKernelExt;
use crate::precompile::{dispatch as metadosis_dispatch, IMetadosis};
use crate::runtime::timestamp_to_date_key;
use crate::schema::{day_type, status, MetadosisContract, WorldwideDay, WorldwideDayEntryExt};

const CHAIN_ID: u64 = 1;

fn with_contract<R>(f: impl FnOnce(&mut MetadosisContract) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    outbe_fidelity::enclave_client::test_enclave::install();
    StorageHandle::enter(&mut storage, |storage| {
        let mut contract = MetadosisContract::new(storage.clone());
        f(&mut contract)
    })
}

fn with_storage<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enable_metadosis_mutation_frames(MetadosisMutationPurposeTag::CycleLifecycle, 64);
    outbe_fidelity::enclave_client::test_enclave::install();
    StorageHandle::enter(&mut storage, |storage| f(storage.clone()))
}

fn arm_genesis_ocomp(storage: &StorageHandle, chain_id: u64) {
    // Fidelity leagues are enclave-computed; every test thread that reaches the
    // OCOMP snapshot path needs the in-process dev enclave (thread-local).
    outbe_fidelity::enclave_client::test_enclave::install();
    let install = crate::fixture_kernel::fork_install_fixture(
        crate::ocomp::fork::OcompForkInstallClassification::Measurement,
        1,
        chain_id,
        B256::repeat_byte(0x11),
    );
    let mut metadosis = MetadosisContract::new(storage.clone());
    let limits = crate::ocomp::schema::poc_schema_limits();
    metadosis
        .initialize_ocomp_request_profile(&install.request_profile, &limits)
        .unwrap();
    metadosis
        .initialize_ocomp_activation_authority(&install.protocol_bundle, &limits)
        .unwrap();
}

fn form_due_fixture_day_limits(storage: &StorageHandle, timestamp: u64) {
    let mut metadosis = MetadosisContract::new(storage.clone());
    for wwd in metadosis.active_wwd.read_all().unwrap() {
        let day = metadosis.worldwide_days.entry(wwd);
        let current = day.status().read().unwrap();
        if current < status::OFFERING
            && timestamp >= day.offering_end().read().unwrap()
            && metadosis.ocomp_day_limit_formation(wwd).unwrap().is_none()
        {
            metadosis.fixture_seed_day_limit_formation(wwd).unwrap();
        }
    }
}

struct TestParent {
    tribute: TributeRepositoryReader,
    nod: NodRepositoryReader,
}

impl TestParent {
    fn empty() -> Self {
        let storage: StorageReaderHandle = Arc::new(MemoryStorage::new());
        Self {
            tribute: TributeRepositoryReader::new(storage.clone()),
            nod: NodRepositoryReader::new(storage),
        }
    }
}

impl ParentBodySource for TestParent {
    fn get(&self, entity: EntityRef) -> Result<Option<StoredBody>, ParentBodySourceError> {
        match entity {
            EntityRef::Tribute(_) => ParentBodySource::get(&self.tribute, entity),
            EntityRef::NodItem(_) | EntityRef::NodBucket(_) => {
                ParentBodySource::get(&self.nod, entity)
            }
        }
    }

    fn list(
        &self,
        query: QueryRef,
        request: IdPageRequest,
    ) -> Result<IdPage, ParentBodySourceError> {
        match query {
            QueryRef::TributeByOwner(_) | QueryRef::TributeByDay(_) => {
                ParentBodySource::list(&self.tribute, query, request)
            }
            QueryRef::NodByOwner(_) | QueryRef::NodAll => {
                ParentBodySource::list(&self.nod, query, request)
            }
        }
    }
}

fn with_active_scope<R>(
    storage: StorageHandle,
    f: impl FnOnce(&ExecutionScope, &TestParent) -> R,
) -> R {
    let parent = TestParent::empty();
    let scope = ExecutionScope::new();
    if storage
        .sload(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO)
        .unwrap()
        .is_zero()
    {
        storage
            .sstore(COMPRESSED_ENTITIES_ADDRESS, U256::ZERO, U256::from(4))
            .unwrap();
        storage
            .sstore(
                COMPRESSED_ENTITIES_ADDRESS,
                U256::from(1),
                U256::from_be_slice(
                    outbe_compressed_entities::sealed_root(B256::ZERO)
                        .unwrap()
                        .as_slice(),
                ),
            )
            .unwrap();
    }
    begin_block(storage.clone(), &scope).unwrap();
    let result = f(&scope, &parent);
    end_block(storage, &scope).unwrap();
    result
}

/// Price the day-type currency, which genesis lists as a reference: the brief needs a
/// price for it.
fn arm_reference_price(storage: &StorageHandle, timestamp: u64) {
    use outbe_oracle::schema::OracleContract;
    let index = match outbe_oracle::api::require_coen_pair(
        storage.clone(),
        outbe_oracle::constants::DAY_TYPE_ISO,
    ) {
        Ok((_, index)) => index,
        Err(_) => {
            outbe_oracle::api::register_pair(storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
                .unwrap()
        }
    };
    let oracle = OracleContract::new(storage.clone());
    if oracle.reference_currencies.len().unwrap() == 0 {
        oracle
            .reference_currencies
            .push(outbe_oracle::constants::DAY_TYPE_ISO)
            .unwrap();
    }
    let last_closed = outbe_primitives::time::previous_date_key(
        outbe_primitives::time::timestamp_to_date_key(timestamp),
    );
    oracle
        .utc_day_vwap_value
        .get_nested(&last_closed)
        .write(&index, U256::from(100u64))
        .unwrap();
}

/// Drive the WWD lifecycle the way the daily Cycle handler does: invoke `start_metadosis`
/// on a synthetic context. These tests exercise the state machine sub-day, so they call it
/// directly rather than through a per-block hook.
fn run_begin_block_with_chain_id(
    storage: StorageHandle,
    block_number: u64,
    timestamp: u64,
    chain_id: u64,
) {
    arm_genesis_ocomp(&storage, CHAIN_ID);
    arm_reference_price(&storage, timestamp);
    // The direct lifecycle fixture omits Cycle's daily allocation transaction.
    // Before a day can exercise the MissedOffering branch, model that preceding
    // production step by sealing its already-written limit as the immutable
    // OCOMP day-limit formation.
    form_due_fixture_day_limits(&storage, timestamp);
    let ctx = BlockRuntimeContext::new(
        BlockContext::empty_for_tests(block_number, timestamp, chain_id),
        storage,
    );
    with_active_scope(ctx.storage.clone(), |scope, parent| {
        crate::commands::start_metadosis(&ctx, scope, parent)
    })
    .unwrap();
}

fn run_begin_block(storage: StorageHandle, block_number: u64, timestamp: u64) {
    run_begin_block_with_chain_id(
        storage,
        block_number,
        timestamp,
        outbe_primitives::chain::CHAIN_ID,
    );
}

mod capacity;
mod league_snapshot;
mod lifecycle;
mod lysis_ingress;
mod ocomp_budget;
mod ocomp_request;
mod ocomp_semantic_migrations;
mod ocomp_storage;
mod pre_admission;
mod reducer;
mod state;
