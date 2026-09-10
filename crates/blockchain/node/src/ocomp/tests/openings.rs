use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use alloy_eips::{BlockNumHash, BlockNumberOrTag};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount, KECCAK_EMPTY};
use outbe_metadosis::config::poc_schema_limits;
use outbe_ocomp_protocol::{
    league_snapshot::{league_snapshot_slot, ordered_league_snapshot_slots},
    opening::OpeningSubjectsV1,
};
use outbe_oracle::{oracle_count_slot_plan_v1, oracle_opening_slot_plan_v1, ORACLE_COUNT_SLOTS_V1};
use outbe_primitives::addresses::{FIDELITY_ADDRESS, METADOSIS_ADDRESS, ORACLE_ADDRESS};
use outbe_primitives::time::WorldwideDay;
use reth_chainspec::ChainInfo;
use reth_primitives_traits::{Account, Bytecode};
use reth_storage_api::{
    errors::provider::ProviderResult, AccountReader, BlockHashReader, BlockIdReader,
    BlockNumReader, BytecodeReader, HashedPostStateProvider, StateProofProvider, StateProvider,
    StateProviderBox, StateProviderFactory, StateRootProvider, StorageRootProvider,
};
use reth_trie::{
    updates::TrieUpdates, AccountProof, ExecutionWitnessMode, HashedPostState, HashedStorage,
    KeccakKeyHasher, MultiProof, MultiProofTargets, StorageMultiProof, StorageProof, TrieInput,
};

use crate::ocomp::{
    finality::{build_verified_raw_contract_opening, verify_raw_contract_opening},
    openings::build_lysis_openings,
    retention::CandidatePinV1,
};

#[derive(Clone)]
struct OpeningStateProvider {
    state_root: B256,
    accounts: BTreeMap<Address, Account>,
    storage: BTreeMap<(Address, B256), U256>,
    proofs: BTreeMap<Address, AccountProof>,
    storage_reads: Arc<AtomicUsize>,
}

impl AccountReader for OpeningStateProvider {
    fn basic_account(&self, address: &Address) -> ProviderResult<Option<Account>> {
        Ok(self.accounts.get(address).copied())
    }
}

impl BlockHashReader for OpeningStateProvider {
    fn block_hash(&self, _number: u64) -> ProviderResult<Option<B256>> {
        Ok(None)
    }

    fn canonical_hashes_range(&self, _start: u64, _end: u64) -> ProviderResult<Vec<B256>> {
        Ok(Vec::new())
    }
}

impl BytecodeReader for OpeningStateProvider {
    fn bytecode_by_hash(&self, _code_hash: &B256) -> ProviderResult<Option<Bytecode>> {
        Ok(None)
    }
}

impl StateRootProvider for OpeningStateProvider {
    fn state_root(&self, _hashed_state: HashedPostState) -> ProviderResult<B256> {
        Ok(self.state_root)
    }

    fn state_root_from_nodes(&self, _input: TrieInput) -> ProviderResult<B256> {
        Ok(self.state_root)
    }

    fn state_root_with_updates(
        &self,
        _hashed_state: HashedPostState,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root, TrieUpdates::default()))
    }

    fn state_root_from_nodes_with_updates(
        &self,
        _input: TrieInput,
    ) -> ProviderResult<(B256, TrieUpdates)> {
        Ok((self.state_root, TrieUpdates::default()))
    }
}

impl StorageRootProvider for OpeningStateProvider {
    fn storage_root(
        &self,
        address: Address,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<B256> {
        Ok(self
            .proofs
            .get(&address)
            .map_or(B256::ZERO, |proof| proof.storage_root))
    }

    fn storage_proof(
        &self,
        address: Address,
        slot: B256,
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageProof> {
        Ok(self
            .proofs
            .get(&address)
            .and_then(|proof| proof.storage_proofs.iter().find(|proof| proof.key == slot))
            .cloned()
            .unwrap_or_else(|| StorageProof::new(slot)))
    }

    fn storage_multiproof(
        &self,
        _address: Address,
        _slots: &[B256],
        _hashed_storage: HashedStorage,
    ) -> ProviderResult<StorageMultiProof> {
        Ok(StorageMultiProof::empty())
    }
}

impl StateProofProvider for OpeningStateProvider {
    fn proof(
        &self,
        _input: TrieInput,
        address: Address,
        slots: &[B256],
    ) -> ProviderResult<AccountProof> {
        let mut proof = self
            .proofs
            .get(&address)
            .cloned()
            .unwrap_or_else(|| AccountProof::new(address));
        proof.storage_proofs = slots
            .iter()
            .map(|slot| {
                proof
                    .storage_proofs
                    .iter()
                    .find(|storage| storage.key == *slot)
                    .cloned()
                    .unwrap_or_else(|| StorageProof::new(*slot))
            })
            .collect();
        Ok(proof)
    }

    fn multiproof(
        &self,
        _input: TrieInput,
        _targets: MultiProofTargets,
    ) -> ProviderResult<MultiProof> {
        Ok(MultiProof::default())
    }

    fn witness(
        &self,
        _input: TrieInput,
        _target: HashedPostState,
        _mode: ExecutionWitnessMode,
    ) -> ProviderResult<Vec<Bytes>> {
        Ok(Vec::new())
    }
}

impl HashedPostStateProvider for OpeningStateProvider {
    fn hashed_post_state(&self, bundle_state: &revm::database::BundleState) -> HashedPostState {
        HashedPostState::from_bundle_state::<KeccakKeyHasher>(bundle_state.state())
    }
}

impl StateProvider for OpeningStateProvider {
    fn storage(&self, account: Address, storage_key: B256) -> ProviderResult<Option<U256>> {
        self.storage_reads.fetch_add(1, Ordering::Relaxed);
        Ok(self.storage.get(&(account, storage_key)).copied())
    }
}

#[derive(Clone)]
struct OpeningProvider {
    state: OpeningStateProvider,
    block_number: u64,
    block_hash: B256,
}

impl BlockHashReader for OpeningProvider {
    fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
        Ok((number == self.block_number).then_some(self.block_hash))
    }

    fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
        Ok((start..end)
            .filter_map(|number| (number == self.block_number).then_some(self.block_hash))
            .collect())
    }
}

impl BlockNumReader for OpeningProvider {
    fn chain_info(&self) -> ProviderResult<ChainInfo> {
        Ok(ChainInfo {
            best_hash: self.block_hash,
            best_number: self.block_number,
        })
    }

    fn best_block_number(&self) -> ProviderResult<u64> {
        Ok(self.block_number)
    }

    fn last_block_number(&self) -> ProviderResult<u64> {
        Ok(self.block_number)
    }

    fn block_number(&self, hash: B256) -> ProviderResult<Option<u64>> {
        Ok((hash == self.block_hash).then_some(self.block_number))
    }
}

impl BlockIdReader for OpeningProvider {
    fn pending_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(BlockNumHash::new(self.block_number, self.block_hash)))
    }

    fn safe_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(BlockNumHash::new(self.block_number, self.block_hash)))
    }

    fn finalized_block_num_hash(&self) -> ProviderResult<Option<BlockNumHash>> {
        Ok(Some(BlockNumHash::new(self.block_number, self.block_hash)))
    }
}

impl StateProviderFactory for OpeningProvider {
    fn latest(&self) -> ProviderResult<StateProviderBox> {
        Ok(Box::new(self.state.clone()))
    }

    fn state_by_block_number_or_tag(
        &self,
        _number_or_tag: BlockNumberOrTag,
    ) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn history_by_block_number(&self, _block: u64) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn history_by_block_hash(&self, _block: B256) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn state_by_block_hash(&self, block: B256) -> ProviderResult<StateProviderBox> {
        assert_eq!(
            block, self.block_hash,
            "opening builder must request the candidate's exact finalized block hash"
        );
        self.latest()
    }

    fn pending(&self) -> ProviderResult<StateProviderBox> {
        self.latest()
    }

    fn pending_state_by_hash(&self, _block_hash: B256) -> ProviderResult<Option<StateProviderBox>> {
        self.latest().map(Some)
    }

    fn maybe_pending(&self) -> ProviderResult<Option<StateProviderBox>> {
        self.latest().map(Some)
    }
}

fn storage_trie(slots: &[(U256, U256)]) -> (B256, Vec<Vec<Bytes>>) {
    let targets = slots
        .iter()
        .map(|(slot, _)| Nibbles::unpack(keccak256(slot.to_be_bytes::<32>())))
        .collect::<Vec<_>>();
    let mut leaves = BTreeMap::new();
    for ((_, word), target) in slots.iter().zip(&targets) {
        if !word.is_zero() {
            leaves.insert(*target, alloy_rlp::encode_fixed_size(word).to_vec());
        }
    }

    let mut builder =
        HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter(targets.clone()));
    for (path, value) in leaves {
        builder.add_leaf(path, &value);
    }
    let root = builder.root();
    let retained = builder.take_proof_nodes();
    let proofs = targets
        .iter()
        .map(|target| {
            retained
                .matching_nodes_sorted(target)
                .into_iter()
                .map(|(_, node)| node)
                .collect()
        })
        .collect();
    (root, proofs)
}

fn account_trie(accounts: &[(Address, TrieAccount)]) -> (B256, BTreeMap<Address, Vec<Bytes>>) {
    let targets = accounts
        .iter()
        .map(|(address, _)| (*address, Nibbles::unpack(keccak256(address))))
        .collect::<BTreeMap<_, _>>();
    let mut builder = HashBuilder::default()
        .with_proof_retainer(ProofRetainer::from_iter(targets.values().copied()));
    let mut leaves = accounts
        .iter()
        .map(|(address, account)| (targets[address], alloy_rlp::encode(*account)))
        .collect::<Vec<_>>();
    leaves.sort_by_key(|(path, _)| *path);
    for (path, value) in leaves {
        builder.add_leaf(path, &value);
    }
    let root = builder.root();
    let retained = builder.take_proof_nodes();
    let proofs = targets
        .into_iter()
        .map(|(address, target)| {
            (
                address,
                retained
                    .matching_nodes_sorted(&target)
                    .into_iter()
                    .map(|(_, node)| node)
                    .collect(),
            )
        })
        .collect();
    (root, proofs)
}

fn opening_state(contracts: &[(Address, Vec<(B256, U256)>)]) -> (OpeningStateProvider, B256) {
    let mut contract_tries = Vec::with_capacity(contracts.len());
    for (address, slots) in contracts {
        let words = slots
            .iter()
            .map(|(slot, value)| (U256::from_be_bytes(slot.0), *value))
            .collect::<Vec<_>>();
        let (storage_root, storage_proofs) = storage_trie(&words);
        contract_tries.push((
            *address,
            slots.clone(),
            TrieAccount {
                nonce: 1,
                balance: U256::from(10),
                storage_root,
                code_hash: KECCAK_EMPTY,
            },
            storage_proofs,
        ));
    }

    let trie_accounts = contract_tries
        .iter()
        .map(|(address, _, account, _)| (*address, *account))
        .collect::<Vec<_>>();
    let (state_root, account_proofs) = account_trie(&trie_accounts);
    let mut accounts = BTreeMap::new();
    let mut storage = BTreeMap::new();
    let mut proofs = BTreeMap::new();
    for (address, slots, trie_account, slot_proofs) in contract_tries {
        let account = Account {
            nonce: trie_account.nonce,
            balance: trie_account.balance,
            bytecode_hash: None,
        };
        accounts.insert(address, account);
        storage.extend(slots.iter().map(|(slot, value)| ((address, *slot), *value)));
        let storage_proofs = slots
            .iter()
            .zip(slot_proofs)
            .map(|((slot, value), nodes)| {
                StorageProof {
                    key: *slot,
                    value: *value,
                    ..StorageProof::new(*slot)
                }
                .with_proof(nodes)
            })
            .collect();
        proofs.insert(
            address,
            AccountProof {
                address,
                info: Some(account),
                proof: account_proofs[&address].clone(),
                storage_root: trie_account.storage_root,
                storage_proofs,
            },
        );
    }

    (
        OpeningStateProvider {
            state_root,
            accounts,
            storage,
            proofs,
            storage_reads: Arc::new(AtomicUsize::new(0)),
        },
        state_root,
    )
}

#[test]
fn fidelity_and_oracle_openings_reject_mutated_values_shape_and_mpt_nodes() {
    let limits = poc_schema_limits();
    let fidelity_slots = vec![
        (B256::repeat_byte(0x11), U256::from(7)),
        (B256::repeat_byte(0x12), U256::ZERO),
    ];
    let oracle_slots = vec![
        (B256::repeat_byte(0x21), U256::from(840)),
        (B256::repeat_byte(0x22), U256::from(1_000)),
    ];
    let (state, state_root) = opening_state(&[
        (FIDELITY_ADDRESS, fidelity_slots.clone()),
        (ORACLE_ADDRESS, oracle_slots.clone()),
    ]);

    for (address, slots) in [
        (FIDELITY_ADDRESS, fidelity_slots),
        (ORACLE_ADDRESS, oracle_slots),
    ] {
        let ordered_slots = slots.iter().map(|(slot, _)| *slot).collect::<Vec<_>>();
        let opening = build_verified_raw_contract_opening(
            &state,
            state_root,
            address,
            &ordered_slots,
            &limits,
        )
        .expect("real account/storage MPT opening must build and self-verify");
        verify_raw_contract_opening(&opening, address, state_root, &ordered_slots, &limits)
            .expect("unaltered raw opening must verify");

        let mut wrong_value = opening.clone();
        wrong_value.ordered_slots[0].value += U256::from(1);
        assert!(
            verify_raw_contract_opening(
                &wrong_value,
                address,
                state_root,
                &ordered_slots,
                &limits,
            )
            .is_err(),
            "a changed raw value must invalidate its storage proof"
        );

        let mut missing_slot = opening.clone();
        missing_slot.ordered_slots.pop();
        assert!(
            verify_raw_contract_opening(
                &missing_slot,
                address,
                state_root,
                &ordered_slots,
                &limits,
            )
            .is_err(),
            "an omitted slot must invalidate the exact opening shape"
        );

        let mut reordered = opening.clone();
        reordered.ordered_slots.swap(0, 1);
        assert!(
            verify_raw_contract_opening(&reordered, address, state_root, &ordered_slots, &limits,)
                .is_err(),
            "slot order is part of the authenticated opening"
        );

        let mut corrupt_proof = opening;
        let byte = corrupt_proof
            .storage_proof
            .0
            .last_mut()
            .expect("fixture storage proof is non-empty");
        *byte ^= 1;
        assert!(
            verify_raw_contract_opening(
                &corrupt_proof,
                address,
                state_root,
                &ordered_slots,
                &limits,
            )
            .is_err(),
            "mutated MPT proof bytes must not verify"
        );
    }
}

#[test]
fn lysis_opening_builder_returns_league_snapshot_and_oracle_proofs() {
    let limits = poc_schema_limits();
    let owner = Address::repeat_byte(0x41);
    let subjects = OpeningSubjectsV1 {
        owners: vec![owner],
        reference_isos: vec![840],
    };
    let day = WorldwideDay::new(20260724);

    // The Fidelity opening is now a single per-owner league word in Metadosis
    // storage; any value in [1, 4096] is a valid league.
    let fidelity_slots = vec![(league_snapshot_slot(day.value(), owner), U256::from(7))];

    let oracle_counts =
        oracle_count_slot_plan_v1(day, &subjects.reference_isos).expect("Oracle count fixture");
    let oracle_pair_indices = vec![1u32; subjects.reference_isos.len()];
    let oracle_plan =
        oracle_opening_slot_plan_v1(day, &subjects.reference_isos, 1, &oracle_pair_indices, 1, 0)
            .expect("bounded Oracle fixture");
    let mut oracle_values = oracle_plan
        .slots
        .iter()
        .enumerate()
        .map(|(index, slot)| (*slot, U256::from(index + 1)))
        .collect::<BTreeMap<_, _>>();
    // reference_currencies: length then the single registered ISO.
    oracle_values.insert(oracle_plan.slots[1], U256::from(840));
    oracle_values.insert(oracle_counts.slots[0], U256::from(1)); // reference currency count
    oracle_values.insert(oracle_counts.slots[1], U256::from(1)); // wwd_vwap_exists
    oracle_values.insert(oracle_counts.slots[2], U256::from(1)); // scurve_count
    oracle_values.insert(oracle_counts.slots[3], U256::ZERO); // scurve_oldest
                                                              // The pair-index word must equal the index the plan above was built from.
    for (slot, index) in oracle_counts.slots[ORACLE_COUNT_SLOTS_V1..]
        .iter()
        .zip(&oracle_pair_indices)
    {
        oracle_values.insert(*slot, U256::from(*index));
    }
    let oracle_slots = oracle_values.into_iter().collect::<Vec<_>>();

    let (state, state_root) = opening_state(&[
        (METADOSIS_ADDRESS, fidelity_slots),
        (ORACLE_ADDRESS, oracle_slots),
    ]);
    let candidate = CandidatePinV1 {
        block_number: 100,
        block_hash: B256::repeat_byte(0x61),
        state_root,
        intent_id: B256::repeat_byte(0x62),
        wwd: day.value(),
        ce_sealed_root: B256::repeat_byte(0x63),
        protocol_bundle_hash: B256::repeat_byte(0x64),
        input_lease_id: B256::repeat_byte(0x65),
    };
    let openings = build_lysis_openings(
        &OpeningProvider {
            state,
            block_number: candidate.block_number,
            block_hash: candidate.block_hash,
        },
        &limits,
        candidate,
        subjects.clone(),
    )
    .expect("exact historical Fidelity and Oracle openings");

    let expected_fidelity_slots = ordered_league_snapshot_slots(day.value(), &subjects.owners);
    assert_eq!(openings.subjects, subjects);
    assert_eq!(openings.finalized_block_hash, candidate.block_hash);
    assert_eq!(openings.finalized_state_root, candidate.state_root);
    assert_eq!(openings.wwd, candidate.wwd);
    assert_eq!(
        openings
            .fidelity
            .ordered_slots
            .iter()
            .map(|raw| raw.slot)
            .collect::<Vec<_>>(),
        expected_fidelity_slots
    );
    assert_eq!(
        openings
            .oracle
            .ordered_slots
            .iter()
            .map(|raw| raw.slot)
            .collect::<Vec<_>>(),
        oracle_plan.slots
    );
    verify_raw_contract_opening(
        &openings.fidelity,
        METADOSIS_ADDRESS,
        state_root,
        &expected_fidelity_slots,
        &limits,
    )
    .expect("Fidelity league proof must verify against the finalized root");
    verify_raw_contract_opening(
        &openings.oracle,
        ORACLE_ADDRESS,
        state_root,
        &oracle_plan.slots,
        &limits,
    )
    .expect("Oracle proof must verify against the finalized root");
}
