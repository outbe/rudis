use alloy_primitives::{Address, Bytes, B256, U256};
use outbe_agentreward::AgentRewardContract;
use outbe_compressed_entities::{
    begin_block, derive_poseidon_digest, EntityRef, ExecutionScope, IdPage, IdPageRequest,
    ParentBodySource, ParentBodySourceError, QueryRef, StoredBody,
};
use outbe_metadosis::{
    genesis::{FreshDevnetGenesisBuilder, GenesisWorldwideDay},
    WwdDayType, WwdStatus,
};
use outbe_oracle::{
    genesis::{init_from_genesis, OracleGenesisConfig},
    schema::OracleContract,
};
use outbe_primitives::address_pair::AddressPair;
use outbe_primitives::addresses::COMPRESSED_ENTITIES_ADDRESS;
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::date_key_to_utc_timestamp;
use outbe_primitives::time::WorldwideDay;
use outbe_tee::protocol::{EncryptedTributeOffer, TributeOfferResult, TributeOfferStatus};
use outbe_tribute::TributeContract;

use crate::runtime::{validate_agent_reward_addresses, OfferTributeInput};
use crate::schema::TributeFactoryContract;

const CHAIN_ID: u64 = 1;

struct NoParentBodies;

impl ParentBodySource for NoParentBodies {
    fn get(
        &self,
        _entity: EntityRef,
    ) -> core::result::Result<Option<StoredBody>, ParentBodySourceError> {
        Ok(None)
    }

    fn list(
        &self,
        _query: QueryRef,
        _request: IdPageRequest,
    ) -> core::result::Result<IdPage, ParentBodySourceError> {
        Ok(IdPage {
            ids: Vec::new(),
            next_after: None,
        })
    }
}

mod l2_zk_gate {
    use alloy_primitives::{Address, Bytes, U256};
    use outbe_compressed_entities::ExecutionScope;
    use outbe_l2registry::L2RegistryContract;
    use outbe_primitives::error::PrecompileError;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::StorageHandle;
    use outbe_zk_canonical::full_proof::COMBINED_LEN as FULL_PROOF_COMBINED_LEN;

    use super::NoParentBodies;
    use crate::runtime::OfferTributeInput;
    use crate::schema::TributeFactoryContract;

    const L2_CHAIN_ID: u64 = 4242;

    fn caller() -> Address {
        Address::repeat_byte(0x77)
    }

    /// A valid calendar day; whether it is OFFERING depends on Metadosis state,
    /// which these fixtures leave empty.
    pub(super) const DAY: u32 = 20250115;

    fn offer(zk_merkle_root: &[u8], signature: &[u8]) -> OfferTributeInput {
        OfferTributeInput {
            caller: caller(),
            cipher_text: Bytes::new(),
            nonce: Bytes::new(),
            ephemeral_pubkey: U256::ZERO,
            worldwide_day: DAY.into(),
            tribute_currency: 840,
            reference_currency: 840,
            exclude_from_intex_issuance: false,
            zk_proof: Bytes::new(),
            zk_merkle_root: Bytes::copy_from_slice(zk_merkle_root),
            signature: Bytes::copy_from_slice(signature),
        }
    }

    fn dummy_full_proof(root: [u8; 32]) -> Bytes {
        let mut proof = Vec::with_capacity(FULL_PROOF_COMBINED_LEN);
        proof.extend_from_slice(&4u32.to_be_bytes());
        proof.extend_from_slice(&[0x01; 32]);
        proof.extend_from_slice(&[0x02; 32]);
        proof.extend_from_slice(&[0x03; 32]);
        proof.extend_from_slice(&root);
        proof.resize(FULL_PROOF_COMBINED_LEN, 0);
        proof.into()
    }

    fn revert_message(err: PrecompileError) -> String {
        match err {
            PrecompileError::Revert(msg) => msg,
            other => panic!("expected revert, got {other:?}"),
        }
    }

    #[test]
    fn offer_rejects_invalid_l2_signature_when_zk_enabled() {
        use commonware_codec::Encode;
        use commonware_cryptography::bls12381::primitives::{
            ops::{self, sign_message},
            variant::MinSig,
        };

        let (private, public) = ops::keypair::<_, MinSig>(&mut rand_core::OsRng);
        let public = public.encode().to_vec();
        let root = [0x04; 32];

        let mut storage = HashMapStorageProvider::new(super::CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut registry = L2RegistryContract::new(storage.clone());
            registry
                .register_network(L2_CHAIN_ID, caller(), &public)
                .unwrap();
            registry.set_zk_enabled(L2_CHAIN_ID, true).unwrap();

            let scope = ExecutionScope::new();
            let mut factory = TributeFactoryContract::new(storage.clone());

            // Enabled + missing signature: the gate rejects before any
            // oracle/metadosis/enclave work.
            let err = factory
                .offer_tribute(&scope, &NoParentBodies, offer(&root, &[]))
                .unwrap_err();
            assert!(revert_message(err).contains("invalid BLS signature"));

            // Enabled + valid signature: the gate passes and the offer
            // proceeds to the next stage (no OFFERING day in this fixture).
            let good_sig = sign_message::<MinSig>(
                &private,
                outbe_l2registry::api::ZK_MERKLE_ROOT_NAMESPACE,
                &root,
            )
            .encode()
            .to_vec();
            let mut valid_gate = offer(&root, &good_sig);
            valid_gate.zk_proof = dummy_full_proof(root);
            let mut factory = TributeFactoryContract::new(storage.clone());
            let err = factory
                .offer_tribute(&scope, &NoParentBodies, valid_gate)
                .unwrap_err();
            assert!(revert_message(err).contains("is not in OFFERING status"));
        });
    }

    #[test]
    fn enabled_network_requires_proof_and_matching_public_root() {
        use commonware_codec::Encode;
        use commonware_cryptography::bls12381::primitives::{
            ops::{self, sign_message},
            variant::MinSig,
        };

        let (private, public) = ops::keypair::<_, MinSig>(&mut rand_core::OsRng);
        let public = public.encode().to_vec();
        let root = [0x04; 32];
        let signature = sign_message::<MinSig>(
            &private,
            outbe_l2registry::api::ZK_MERKLE_ROOT_NAMESPACE,
            &root,
        )
        .encode()
        .to_vec();

        let mut storage = HashMapStorageProvider::new(super::CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let mut registry = L2RegistryContract::new(storage.clone());
            registry
                .register_network(L2_CHAIN_ID, caller(), &public)
                .unwrap();
            registry.set_zk_enabled(L2_CHAIN_ID, true).unwrap();
            let scope = ExecutionScope::new();

            let mut factory = TributeFactoryContract::new(storage.clone());
            let missing = factory
                .offer_tribute(&scope, &NoParentBodies, offer(&root, &signature))
                .unwrap_err();
            assert!(revert_message(missing).contains("zkProof is required"));

            let mut wrong_root = offer(&root, &signature);
            wrong_root.zk_proof = dummy_full_proof([0x24; 32]);
            let mut factory = TributeFactoryContract::new(storage.clone());
            let mismatch = factory
                .offer_tribute(&scope, &NoParentBodies, wrong_root)
                .unwrap_err();
            assert!(revert_message(mismatch).contains("merkle_root"));
        });
    }

    #[test]
    fn offer_skips_signature_check_for_unregistered_and_disabled() {
        use commonware_codec::Encode;
        use commonware_cryptography::bls12381::primitives::{
            ops::{self},
            variant::MinSig,
        };

        let (_, public) = ops::keypair::<_, MinSig>(&mut rand_core::OsRng);
        let public = public.encode().to_vec();

        let mut storage = HashMapStorageProvider::new(super::CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let scope = ExecutionScope::new();

            // Unregistered caller with empty zk fields sails past the gate.
            let mut factory = TributeFactoryContract::new(storage.clone());
            let err = factory
                .offer_tribute(&scope, &NoParentBodies, offer(&[], &[]))
                .unwrap_err();
            assert!(revert_message(err).contains("is not in OFFERING status"));

            // Registered but zk disabled: still no signature requirement.
            let mut registry = L2RegistryContract::new(storage.clone());
            registry
                .register_network(L2_CHAIN_ID, caller(), &public)
                .unwrap();
            let mut factory = TributeFactoryContract::new(storage.clone());
            let err = factory
                .offer_tribute(&scope, &NoParentBodies, offer(&[], &[]))
                .unwrap_err();
            assert!(revert_message(err).contains("is not in OFFERING status"));
        });
    }

    /// `worldwideDay` and `tributeCurrency` are cleartext ABI arguments precisely
    /// so a bad one costs no enclave round trip. These fixtures configure no
    /// enclave client at all, so reaching the sidecar would surface as
    /// `tee_sidecar_unavailable` - the assertions below are what prove the host
    /// rejected first.
    #[test]
    fn host_rejects_an_invalid_calendar_day_before_the_enclave() {
        let mut storage = HashMapStorageProvider::new(super::CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let scope = ExecutionScope::new();
            let mut bad_day = offer(&[], &[]);
            bad_day.worldwide_day = 20250230u32.into(); // February 30th

            let mut factory = TributeFactoryContract::new(storage);
            let err = factory
                .offer_tribute(&scope, &NoParentBodies, bad_day)
                .unwrap_err();
            let message = revert_message(err);
            assert!(
                message.contains("not a valid YYYYMMDD calendar date"),
                "unexpected revert: {message}"
            );
        });
    }

    /// The day check runs before the currency check, so this case needs the day to
    /// be OFFERING first - which these fixtures cannot arrange. Assert the ordering
    /// instead: an unregistered currency paired with a non-OFFERING day still
    /// reports the day, proving the currency lookup is not reached and therefore
    /// that neither reaches the enclave.
    #[test]
    fn host_rejects_a_non_offering_day_before_pricing() {
        let mut storage = HashMapStorageProvider::new(super::CHAIN_ID);
        StorageHandle::enter(&mut storage, |storage| {
            let scope = ExecutionScope::new();
            let mut unpriced = offer(&[], &[]);
            unpriced.tribute_currency = 999; // never registered

            let mut factory = TributeFactoryContract::new(storage);
            let err = factory
                .offer_tribute(&scope, &NoParentBodies, unpriced)
                .unwrap_err();
            let message = revert_message(err);
            assert!(
                message.contains("is not in OFFERING status"),
                "unexpected revert: {message}"
            );
        });
    }
}

#[test]
fn test_validate_agent_reward_both_empty() {
    assert!(validate_agent_reward_addresses(&[], &[]).is_ok());
}

#[test]
fn test_validate_agent_reward_both_present() {
    let wallets = vec!["0x1111111111111111111111111111111111111111".to_string()];
    let sfas = vec!["0x2222222222222222222222222222222222222222".to_string()];
    assert!(validate_agent_reward_addresses(&wallets, &sfas).is_ok());
}

#[test]
fn test_validate_agent_reward_wallets_only() {
    let wallets = vec!["0x1111111111111111111111111111111111111111".to_string()];
    assert!(validate_agent_reward_addresses(&wallets, &[]).is_err());
}

#[test]
fn test_validate_agent_reward_sfa_only() {
    let sfas = vec!["0x2222222222222222222222222222222222222222".to_string()];
    assert!(validate_agent_reward_addresses(&[], &sfas).is_err());
}

#[test]
fn test_validate_agent_reward_invalid_address() {
    let wallets = vec!["not_a_valid_address".to_string()];
    let sfas = vec!["0x2222222222222222222222222222222222222222".to_string()];
    assert!(validate_agent_reward_addresses(&wallets, &sfas).is_err());
}

const TARGET_WWD_A: WorldwideDay = WorldwideDay::new(20_260_802);
const TARGET_WWD_B: WorldwideDay = WorldwideDay::new(20_260_803);
const REWARD_WALLET: Address = Address::repeat_byte(0x71);
const REWARD_SRA: Address = Address::repeat_byte(0x72);

fn seed_offer_world(storage: StorageHandle<'_>, target_days: &[WorldwideDay]) {
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

    let mut metadosis = FreshDevnetGenesisBuilder::new();
    for (index, worldwide_day) in target_days.iter().copied().enumerate() {
        let offset = u64::try_from(index).unwrap() * 10;
        metadosis = metadosis.seed_active_worldwide_day(GenesisWorldwideDay {
            worldwide_day,
            status: WwdStatus::Offering,
            day_type: WwdDayType::Green,
            forming_start: offset + 1,
            forming_end: offset + 2,
            lookback_end: offset + 3,
            offering_end: offset + 4,
            scheduled_process_time: offset + 5,
            metadosis_limit_amount: U256::from(100),
            previous_vwap: U256::from(90),
            current_vwap: U256::from(100),
        });
    }
    metadosis.apply(storage.clone()).unwrap();

    let mut oracle = OracleContract::new(storage.clone());
    init_from_genesis(&mut oracle, &OracleGenesisConfig::default_config()).unwrap();
    let pair = AddressPair::new_coen_to(840);
    for worldwide_day in target_days {
        let start = worldwide_day.start_timestamp();
        oracle
            .write_snapshot(start + 1, &[(pair, U256::from(100), U256::ONE)])
            .unwrap();
        oracle
            .store_worldwide_day_vwap_snapshot(*worldwide_day, start, start + 50 * 60 * 60)
            .unwrap();
    }

    let mut tribute = TributeContract::new(storage);
    for worldwide_day in target_days {
        tribute.unseal_day(*worldwide_day).unwrap();
    }
}

fn offer_input(caller: Address, worldwide_day: WorldwideDay) -> OfferTributeInput {
    OfferTributeInput {
        caller,
        cipher_text: Bytes::new(),
        nonce: Bytes::new(),
        ephemeral_pubkey: U256::ZERO,
        worldwide_day,
        tribute_currency: 840,
        reference_currency: 840,
        exclude_from_intex_issuance: false,
        zk_proof: Bytes::new(),
        zk_merkle_root: Bytes::new(),
        signature: Bytes::new(),
    }
}

fn successful_offer_processor(
    offers: &[EncryptedTributeOffer],
) -> core::result::Result<Vec<TributeOfferResult>, PrecompileError> {
    Ok(offers
        .iter()
        .map(|offer| TributeOfferResult {
            token_id: derive_poseidon_digest(offer.owner, offer.worldwide_day).unwrap(),
            owner: offer.owner,
            issuance_amount_minor: U256::ONE,
            nominal_amount_minor: U256::ONE,
            effective_reference_price_minor: offer
                .reference_wwd_vwap_minor
                .max(offer.reference_scurve_minor),
            su_hashes: Vec::new(),
            wallet_addresses: vec![REWARD_WALLET.to_string()],
            sra_addresses: vec![REWARD_SRA.to_string()],
            zk_expected_hashes: None,
            status: TributeOfferStatus::Created,
        })
        .collect())
}

fn execute_successful_offer(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    caller: Address,
    worldwide_day: WorldwideDay,
) -> outbe_primitives::error::Result<()> {
    TributeFactoryContract::new(storage)
        .offer_tribute_with_processor(
            scope,
            &NoParentBodies,
            offer_input(caller, worldwide_day),
            successful_offer_processor,
        )
        .map(|_| ())
}

fn active_scope(storage: StorageHandle<'_>) -> ExecutionScope {
    let scope = ExecutionScope::new();
    begin_block(storage, &scope).unwrap();
    scope
}

#[test]
fn one_hundred_real_offer_writes_for_distinct_target_wwds_share_the_execution_utc_day() {
    const REWARD_UTC_DAY: u32 = 20_260_825;
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);

    StorageHandle::enter(&mut provider, |storage| {
        seed_offer_world(storage.clone(), &[TARGET_WWD_A, TARGET_WWD_B]);
        storage
            .set_block_timestamp(U256::from(
                date_key_to_utc_timestamp(REWARD_UTC_DAY) + 43_200,
            ))
            .unwrap();
        let scope = active_scope(storage.clone());

        for index in 0..100u8 {
            let target = if index % 2 == 0 {
                TARGET_WWD_A
            } else {
                TARGET_WWD_B
            };
            execute_successful_offer(
                storage.clone(),
                &scope,
                Address::repeat_byte(index + 1),
                target,
            )
            .unwrap();
        }

        let rewards = AgentRewardContract::new(storage);
        assert_eq!(
            rewards.get_all_waa_counts(REWARD_UTC_DAY.into()).unwrap(),
            vec![(REWARD_WALLET, 100)]
        );
        assert_eq!(
            rewards.get_all_sra_counts(REWARD_UTC_DAY.into()).unwrap(),
            vec![(REWARD_SRA, 100)]
        );
        for target in [TARGET_WWD_A, TARGET_WWD_B] {
            assert!(rewards.get_all_waa_counts(target).unwrap().is_empty());
            assert!(rewards.get_all_sra_counts(target).unwrap().is_empty());
        }
    });
}

#[test]
fn real_offer_writer_uses_utc_calendar_boundaries() {
    const OLD_DAY: u32 = 20_261_231;
    const NEW_DAY: u32 = 20_270_101;
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);

    StorageHandle::enter(&mut provider, |storage| {
        seed_offer_world(storage.clone(), &[TARGET_WWD_A]);
        let scope = active_scope(storage.clone());
        storage
            .set_block_timestamp(U256::from(
                date_key_to_utc_timestamp(NEW_DAY).saturating_sub(1),
            ))
            .unwrap();
        execute_successful_offer(
            storage.clone(),
            &scope,
            Address::repeat_byte(0x31),
            TARGET_WWD_A,
        )
        .unwrap();

        storage
            .set_block_timestamp(U256::from(date_key_to_utc_timestamp(NEW_DAY)))
            .unwrap();
        execute_successful_offer(
            storage.clone(),
            &scope,
            Address::repeat_byte(0x32),
            TARGET_WWD_A,
        )
        .unwrap();

        let rewards = AgentRewardContract::new(storage);
        for day in [OLD_DAY, NEW_DAY] {
            assert_eq!(
                rewards.get_all_waa_counts(day.into()).unwrap(),
                vec![(REWARD_WALLET, 1)]
            );
            assert_eq!(
                rewards.get_all_sra_counts(day.into()).unwrap(),
                vec![(REWARD_SRA, 1)]
            );
        }
    });
}

#[test]
fn reverted_real_offer_writer_leaves_no_reward_day_activity() {
    const REWARD_UTC_DAY: u32 = 20_260_825;

    let mutation_count = {
        let mut probe = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut probe, |storage| {
            seed_offer_world(storage.clone(), &[TARGET_WWD_A]);
            storage
                .set_block_timestamp(U256::from(date_key_to_utc_timestamp(REWARD_UTC_DAY)))
                .unwrap();
        });
        probe.clear_mutation_failure();
        probe.fail_after_mutation_at(usize::MAX);
        StorageHandle::enter(&mut probe, |storage| {
            let scope = active_scope(storage.clone());
            storage
                .with_checkpoint(|| {
                    execute_successful_offer(
                        storage.clone(),
                        &scope,
                        Address::repeat_byte(0x41),
                        TARGET_WWD_A,
                    )
                })
                .unwrap();
        });
        probe.clear_mutation_failure()
    };
    assert!(mutation_count > 2);

    for operation in 0..mutation_count {
        let mut provider = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut provider, |storage| {
            seed_offer_world(storage.clone(), &[TARGET_WWD_A]);
            storage
                .set_block_timestamp(U256::from(date_key_to_utc_timestamp(REWARD_UTC_DAY)))
                .unwrap();
        });
        provider.clear_mutation_failure();
        let before = provider.storage.clone();
        provider.fail_after_mutation_at(operation);

        StorageHandle::enter(&mut provider, |storage| {
            let scope = active_scope(storage.clone());
            assert!(storage
                .with_checkpoint(|| {
                    execute_successful_offer(
                        storage.clone(),
                        &scope,
                        Address::repeat_byte(0x41),
                        TARGET_WWD_A,
                    )
                })
                .is_err());
        });
        assert_eq!(provider.clear_mutation_failure(), operation + 1);
        assert_eq!(
            provider.storage, before,
            "operation {operation} leaked state"
        );

        StorageHandle::enter(&mut provider, |storage| {
            let rewards = AgentRewardContract::new(storage);
            assert!(rewards
                .get_all_waa_counts(REWARD_UTC_DAY.into())
                .unwrap()
                .is_empty());
            assert!(rewards
                .get_all_sra_counts(REWARD_UTC_DAY.into())
                .unwrap()
                .is_empty());
        });
    }
}

#[test]
fn su_hash_can_only_be_used_once() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let expect_reused = |err: PrecompileError| {
            assert!(matches!(err, PrecompileError::Revert(ref m)
                if m.contains("SU hash already used")));
        };

        // Distinct hashes across the array all succeed.
        let (a, b) = (B256::repeat_byte(0xAA), B256::repeat_byte(0xBB));
        TributeFactoryContract::new(storage.clone())
            .mark_su_hashes_used(&[a, b])
            .expect("distinct hashes ok");

        // Reuse in a later call is rejected (persistent marker).
        expect_reused(
            TributeFactoryContract::new(storage.clone())
                .mark_su_hashes_used(&[a])
                .unwrap_err(),
        );

        // Duplicate within a single array is rejected.
        let dup = B256::repeat_byte(0xCC);
        expect_reused(
            TributeFactoryContract::new(storage.clone())
                .mark_su_hashes_used(&[dup, dup])
                .unwrap_err(),
        );
    });
}

#[test]
fn test_storage_dsl_layout_is_compatible_with_previous_slots() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let factory = TributeFactoryContract::new(storage.clone());
        assert_eq!(
            factory.used_su_hashes.base_slot(),
            alloy_primitives::U256::ZERO
        );
    });
}
