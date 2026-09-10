use alloy_primitives::{address, Address, U256};
use alloy_sol_types::SolCall;
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

use crate::precompile::{dispatch, ICca};

const CHAIN_ID: u64 = 1;

fn with_cca<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut storage, f)
}

fn caller() -> Address {
    address!("0x00000000000000000000000000000000000000a1")
}

/// `sol!` is bare here, so the generated enum carries no `Debug`/`PartialEq`.
/// Comparing discriminants keeps the assertions readable without pulling in
/// `extra_derives` the production path does not need.
fn state_of(storage: StorageHandle, cca: Address) -> u8 {
    let data = ICca::getCcaStateCall { cca }.abi_encode();
    let out = dispatch(storage, &data, caller(), U256::ZERO).unwrap();
    ICca::getCcaStateCall::abi_decode_returns(&out).unwrap() as u8
}

/// The stub answers `Active` for every address, including ones that could never
/// have registered. Replacing it with the real registry must break this test.
#[test]
fn every_address_reads_back_active() {
    with_cca(|storage| {
        for cca in [
            Address::ZERO,
            caller(),
            address!("0x000000000000000000000000000000000000dead"),
        ] {
            assert_eq!(
                state_of(storage.clone(), cca),
                ICca::State::Active as u8,
                "stub registry must report {cca} active"
            );
        }
    });
}

/// `Unknown` occupies discriminant 0, so `Active` is 1 on the wire. A caller
/// that decodes the enum as "0 == registered" would read every agent as
/// unregistered; pin the encoding rather than the variant name alone.
#[test]
fn active_encodes_as_one_not_zero() {
    with_cca(|storage| {
        assert_eq!(ICca::State::Unknown as u8, 0);
        assert_eq!(state_of(storage, caller()), 1);
    });
}

#[test]
fn precompile_rejects_msg_value() {
    with_cca(|storage| {
        let data = ICca::getCcaStateCall { cca: caller() }.abi_encode();
        let err = dispatch(storage, &data, caller(), U256::from(1u64)).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("value"));
    });
}

#[test]
fn precompile_supports_erc165() {
    with_cca(|storage| {
        let data = ICca::supportsInterfaceCall {
            interfaceId: ERC165_INTERFACE_ID.into(),
        }
        .abi_encode();
        let out = dispatch(storage.clone(), &data, caller(), U256::ZERO).unwrap();
        assert!(ICca::supportsInterfaceCall::abi_decode_returns(&out).unwrap());

        let data = ICca::supportsInterfaceCall {
            interfaceId: [0xde, 0xad, 0xbe, 0xef].into(),
        }
        .abi_encode();
        let out = dispatch(storage, &data, caller(), U256::ZERO).unwrap();
        assert!(!ICca::supportsInterfaceCall::abi_decode_returns(&out).unwrap());
    });
}

#[test]
fn unknown_selector_reverts() {
    with_cca(|storage| {
        assert!(dispatch(storage, &[0x00, 0x11, 0x22, 0x33], caller(), U256::ZERO).is_err());
    });
}
