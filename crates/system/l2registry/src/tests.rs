use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    group::Private,
    ops::{self, sign_message},
    variant::MinSig,
};
use outbe_primitives::error::PrecompileError;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::api::{check_zk_merkle_root_signature, ZkOfferCheck, ZK_MERKLE_ROOT_NAMESPACE};
use crate::precompile;
use crate::schema::L2RegistryContract;

const CHAIN_ID: u64 = 1;
const L2_CHAIN_ID: u64 = 4242;

sol! {
    interface RemovedL2RegistryMutators {
        function registerNetwork(uint64 chainId, address l1Address, bytes publicKey) external;
        function setZkEnabled(uint64 chainId, bool enabled) external;
    }
}

fn l1_addr() -> Address {
    Address::repeat_byte(0x11)
}

fn keypair() -> (Private, Vec<u8>) {
    let (private, public) = ops::keypair::<_, MinSig>(&mut rand_core::OsRng);
    let public = public.encode().to_vec();
    (private, public)
}

fn revert_message(err: PrecompileError) -> String {
    match err {
        PrecompileError::Revert(msg) => msg,
        other => panic!("expected revert, got {other:?}"),
    }
}

#[test]
fn register_toggle_owner_remove_roundtrip() {
    let (_, public) = keypair();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut registry = L2RegistryContract::new(storage.clone());
        registry
            .register_network(L2_CHAIN_ID, l1_addr(), &public)
            .unwrap();

        let record = registry.load_network(L2_CHAIN_ID).unwrap();
        assert_eq!(record.l1_address, l1_addr());
        assert_eq!(record.public_key_bytes().as_slice(), public.as_slice());
        assert!(!record.zk_enabled);
        assert_eq!(registry.l1_to_chain.read(&l1_addr()).unwrap(), L2_CHAIN_ID);

        registry.set_zk_enabled(L2_CHAIN_ID, true).unwrap();
        assert!(registry.load_network(L2_CHAIN_ID).unwrap().zk_enabled);
        registry.set_zk_enabled(L2_CHAIN_ID, false).unwrap();
        assert!(!registry.load_network(L2_CHAIN_ID).unwrap().zk_enabled);

        registry.remove_network(l1_addr(), L2_CHAIN_ID).unwrap();
        assert!(!registry.networks.exists(L2_CHAIN_ID).unwrap());
        assert_eq!(registry.l1_to_chain.read(&l1_addr()).unwrap(), 0);

        // The l1 address is free for a fresh registration after removal.
        registry
            .register_network(L2_CHAIN_ID + 1, l1_addr(), &public)
            .unwrap();
    });
}

#[test]
fn governed_register_applies_requested_zk_state_atomically() {
    let (_, public) = keypair();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut registry = L2RegistryContract::new(storage.clone());
        registry
            .register_network_with_zk(L2_CHAIN_ID, l1_addr(), &public, true)
            .unwrap();

        let record = registry.load_network(L2_CHAIN_ID).unwrap();
        assert_eq!(record.l1_address, l1_addr());
        assert_eq!(record.public_key_bytes().as_slice(), public.as_slice());
        assert!(record.zk_enabled);
        assert_eq!(registry.l1_to_chain.read(&l1_addr()).unwrap(), L2_CHAIN_ID);
    });
}

#[test]
fn register_rejects_invalid_inputs() {
    let (_, public) = keypair();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut registry = L2RegistryContract::new(storage.clone());

        let err = registry
            .register_network(0, l1_addr(), &public)
            .unwrap_err();
        assert!(revert_message(err).contains("chain id"));

        let err = registry
            .register_network(L2_CHAIN_ID, Address::ZERO, &public)
            .unwrap_err();
        assert!(revert_message(err).contains("l1 address"));

        let err = registry
            .register_network(L2_CHAIN_ID, l1_addr(), &public[..95])
            .unwrap_err();
        assert!(revert_message(err).contains("96 bytes"));

        let err = registry
            .register_network(L2_CHAIN_ID, l1_addr(), &[0xAB; 96])
            .unwrap_err();
        assert!(revert_message(err).contains("group element"));
    });
}

#[test]
fn register_rejects_duplicates() {
    let (_, public) = keypair();
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut registry = L2RegistryContract::new(storage.clone());
        registry
            .register_network(L2_CHAIN_ID, l1_addr(), &public)
            .unwrap();

        let err = registry
            .register_network(L2_CHAIN_ID, Address::repeat_byte(0x22), &public)
            .unwrap_err();
        assert!(revert_message(err).contains("already registered"));

        let err = registry
            .register_network(L2_CHAIN_ID + 1, l1_addr(), &public)
            .unwrap_err();
        assert!(revert_message(err).contains("already registered"));
    });
}

#[test]
fn toggle_and_owner_remove_require_registration() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        let mut registry = L2RegistryContract::new(storage.clone());
        let err = registry.set_zk_enabled(L2_CHAIN_ID, true).unwrap_err();
        assert!(revert_message(err).contains("not registered"));
        let err = registry.remove_network(l1_addr(), L2_CHAIN_ID).unwrap_err();
        assert!(revert_message(err).contains("not registered"));
    });
}

#[test]
fn removed_mutation_selectors_are_not_public_abi() {
    let (_, public) = keypair();
    let calls = [
        RemovedL2RegistryMutators::registerNetworkCall {
            chainId: L2_CHAIN_ID,
            l1Address: l1_addr(),
            publicKey: Bytes::from(public),
        }
        .abi_encode(),
        RemovedL2RegistryMutators::setZkEnabledCall {
            chainId: L2_CHAIN_ID,
            enabled: true,
        }
        .abi_encode(),
    ];
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        for call in calls {
            precompile::dispatch(
                storage.clone(),
                &call,
                Address::repeat_byte(0xaa),
                U256::ZERO,
            )
            .unwrap_err();
        }
        assert!(!L2RegistryContract::new(storage)
            .networks
            .exists(L2_CHAIN_ID)
            .unwrap());
    });
}

#[test]
fn public_remove_rejects_non_owner_without_effects() {
    let (_, public) = keypair();
    let stranger = Address::repeat_byte(0x22);
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        L2RegistryContract::new(storage.clone())
            .register_network(L2_CHAIN_ID, l1_addr(), &public)
            .unwrap();

        let call = precompile::IL2Registry::removeNetworkCall {
            chainId: L2_CHAIN_ID,
        };
        let err = precompile::dispatch(storage.clone(), &call.abi_encode(), stranger, U256::ZERO)
            .unwrap_err();

        assert!(revert_message(err).contains("owner"));
        let registry = L2RegistryContract::new(storage);
        assert_eq!(
            registry.load_network(L2_CHAIN_ID).unwrap().l1_address,
            l1_addr()
        );
        assert_eq!(registry.l1_to_chain.read(&l1_addr()).unwrap(), L2_CHAIN_ID);
    });
}

#[test]
fn public_remove_allows_owner_and_replay_is_not_registered() {
    let (_, public) = keypair();
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        L2RegistryContract::new(storage.clone())
            .register_network(L2_CHAIN_ID, l1_addr(), &public)
            .unwrap();

        let call = precompile::IL2Registry::removeNetworkCall {
            chainId: L2_CHAIN_ID,
        };
        precompile::dispatch(storage.clone(), &call.abi_encode(), l1_addr(), U256::ZERO).unwrap();

        let registry = L2RegistryContract::new(storage.clone());
        assert!(!registry.networks.exists(L2_CHAIN_ID).unwrap());
        assert_eq!(registry.l1_to_chain.read(&l1_addr()).unwrap(), 0);

        let err =
            precompile::dispatch(storage, &call.abi_encode(), l1_addr(), U256::ZERO).unwrap_err();
        assert!(revert_message(err).contains("not registered"));
    });
}

#[test]
fn zk_signature_check_paths() {
    let (private, public) = keypair();
    let root = [0x42; 32];
    let good_sig = sign_message::<MinSig>(&private, ZK_MERKLE_ROOT_NAMESPACE, &root)
        .encode()
        .to_vec();

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, |storage| {
        // Unregistered caller: no check applies.
        assert_eq!(
            check_zk_merkle_root_signature(storage.clone(), l1_addr(), &root, &good_sig).unwrap(),
            ZkOfferCheck::NotRegistered
        );

        let mut registry = L2RegistryContract::new(storage.clone());
        registry
            .register_network(L2_CHAIN_ID, l1_addr(), &public)
            .unwrap();

        // Registered, zk disabled: signature is not checked.
        assert_eq!(
            check_zk_merkle_root_signature(storage.clone(), l1_addr(), &root, &[]).unwrap(),
            ZkOfferCheck::Disabled {
                chain_id: L2_CHAIN_ID
            }
        );

        let mut registry = L2RegistryContract::new(storage.clone());
        registry.set_zk_enabled(L2_CHAIN_ID, true).unwrap();

        // Enabled + valid signature.
        assert_eq!(
            check_zk_merkle_root_signature(storage.clone(), l1_addr(), &root, &good_sig).unwrap(),
            ZkOfferCheck::Verified {
                chain_id: L2_CHAIN_ID
            }
        );

        // Enabled + empty root.
        let err =
            check_zk_merkle_root_signature(storage.clone(), l1_addr(), &[], &good_sig).unwrap_err();
        assert!(revert_message(err).contains("exactly 32 bytes"));

        // Enabled + malformed signature bytes.
        let err = check_zk_merkle_root_signature(storage.clone(), l1_addr(), &root, &[0x01; 8])
            .unwrap_err();
        assert!(revert_message(err).contains("invalid BLS signature"));

        // Enabled + signature over a different message.
        let wrong_sig = sign_message::<MinSig>(&private, ZK_MERKLE_ROOT_NAMESPACE, &[0x24; 32])
            .encode()
            .to_vec();
        let err = check_zk_merkle_root_signature(storage.clone(), l1_addr(), &root, &wrong_sig)
            .unwrap_err();
        assert!(revert_message(err).contains("invalid BLS signature"));

        // Enabled + signature by a different key.
        let (other_private, _) = keypair();
        let foreign_sig = sign_message::<MinSig>(&other_private, ZK_MERKLE_ROOT_NAMESPACE, &root)
            .encode()
            .to_vec();
        let err = check_zk_merkle_root_signature(storage.clone(), l1_addr(), &root, &foreign_sig)
            .unwrap_err();
        assert!(revert_message(err).contains("invalid BLS signature"));
    });
}
