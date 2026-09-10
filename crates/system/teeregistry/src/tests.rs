use alloy_primitives::{Address, B256};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::runtime::TeeBootstrapData;
use crate::schema::TeeRegistry;

const CHAIN_ID: u64 = 1;

fn sample_data() -> TeeBootstrapData {
    TeeBootstrapData {
        tribute_offer_public_key: B256::repeat_byte(0xAA),
        policy_hash: B256::repeat_byte(0xBB),
        key_epoch: 0,
        tribute_offer_epoch: 0,
        dkg_transcript_hash: B256::repeat_byte(0xCC),
        committee_snapshot_block: 1,
        committee_snapshot_hash: B256::repeat_byte(0xDD),
        tribute_offer_group_public_key: alloy_primitives::Bytes::from(vec![0xEE; 96]),
    }
}

#[test]
fn bootstrap_writes_and_reads_back() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut reg = TeeRegistry::new(storage.clone());
        assert!(!reg.is_bootstrapped().unwrap());

        let data = sample_data();
        reg.write_bootstrap(&data).unwrap();

        assert!(reg.is_bootstrapped().unwrap());
        assert_eq!(
            reg.offer_public_key().unwrap(),
            data.tribute_offer_public_key
        );
        assert_eq!(reg.policy_hash().unwrap(), data.policy_hash);
        assert_eq!(reg.key_epoch().unwrap(), data.key_epoch);
        assert_eq!(reg.tribute_offer_epoch().unwrap(), data.tribute_offer_epoch);
        assert_eq!(reg.group_public_key_len.read().unwrap(), 96);
        for index in 0..3 {
            assert_eq!(
                reg.group_public_key.read(&index).unwrap(),
                B256::repeat_byte(0xEE)
            );
        }
    });
}

#[test]
fn bootstrap_is_idempotent_reject() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut reg = TeeRegistry::new(storage.clone());
        reg.write_bootstrap(&sample_data()).unwrap();
        // A second bootstrap must be rejected (registry no longer empty).
        assert!(reg.write_bootstrap(&sample_data()).is_err());
    });
}

#[test]
fn empty_registry_reads_zero() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let reg = TeeRegistry::new(storage.clone());
        assert!(!reg.is_bootstrapped().unwrap());
        assert_eq!(reg.offer_public_key().unwrap(), B256::ZERO);
    });
}

#[test]
fn boundary_recipient_keys_recorded_and_overwritten() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut reg = TeeRegistry::new(storage.clone());
        let val_a = Address::repeat_byte(0x11);
        let val_b = Address::repeat_byte(0x12);

        // Unannounced validators read zero.
        assert_eq!(reg.announced_recipient_key(val_a).unwrap(), B256::ZERO);

        reg.record_boundary_recipient_keys(&[
            (val_a, B256::repeat_byte(0xA1)),
            (val_b, B256::repeat_byte(0xB1)),
        ])
        .unwrap();
        assert_eq!(
            reg.announced_recipient_key(val_a).unwrap(),
            B256::repeat_byte(0xA1)
        );
        assert_eq!(
            reg.announced_recipient_key(val_b).unwrap(),
            B256::repeat_byte(0xB1)
        );

        // Latest announcement wins (key rotation).
        reg.record_boundary_recipient_keys(&[(val_a, B256::repeat_byte(0xA2))])
            .unwrap();
        assert_eq!(
            reg.announced_recipient_key(val_a).unwrap(),
            B256::repeat_byte(0xA2)
        );
        // Untouched validator keeps its prior announcement.
        assert_eq!(
            reg.announced_recipient_key(val_b).unwrap(),
            B256::repeat_byte(0xB1)
        );
    });
}

#[test]
fn boundary_recipient_keys_are_independent_of_node_host_binding() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut reg = TeeRegistry::new(storage.clone());
        let validator = Address::repeat_byte(0x11);

        // A boundary announcement does not bootstrap the registry or create a
        // validator-to-NodeHost association.
        reg.record_boundary_recipient_keys(&[(validator, B256::repeat_byte(0xA1))])
            .unwrap();
        assert!(!reg.is_bootstrapped().unwrap());
        assert_eq!(
            reg.validator_v1_node_hash.read(&validator).unwrap(),
            B256::ZERO
        );
        assert_eq!(
            reg.announced_recipient_key(validator).unwrap(),
            B256::repeat_byte(0xA1)
        );
    });
}
