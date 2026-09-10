use alloy_primitives::{b256, hex, keccak256, Address, B256, U256};
use alloy_sol_types::{sol, SolCall, SolError, SolEvent};

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IStablecoin.sol"
);
sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IStablecoinFactory.sol"
);
sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IStablecoinPolicyRegistry.sol"
);
sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IVote.sol"
);

#[test]
fn complete_exported_abis_match_golden_hashes() {
    let token = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/precompiles/abi-export/IStablecoin.json"
    ));
    let factory = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/precompiles/abi-export/IStablecoinFactory.json"
    ));
    let policy = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/precompiles/abi-export/IStablecoinPolicyRegistry.json"
    ));
    let vote = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../contracts/precompiles/abi-export/IVote.json"
    ));

    assert_eq!(
        canonical_abi_hash(token),
        b256!("d8b6eb011c35cce3d2c3f18596944d8e56c2d63c245d940e9179f02fad9aceb0")
    );
    assert_eq!(
        canonical_abi_hash(factory),
        b256!("c2eef29b3be6e35a38c704c3276d4c548a0745a80b146d28db7c5e920a8b02a7")
    );
    assert_eq!(
        canonical_abi_hash(policy),
        b256!("82b8e648b836c37d92851360826ee852ba37ad5afb84f9c5ab381a4c719b9940")
    );
    assert_eq!(
        canonical_abi_hash(vote),
        b256!("a6507e6860b3747b4a31c7e7f615c2a0fb79fce105f02f9e7e82db5767bda11d")
    );
}

#[test]
fn alloy_call_selectors_match_solidity_vectors() {
    assert_eq!(
        IStablecoin::transferWithMemoCall::SELECTOR,
        [0x95, 0x77, 0x7d, 0x59]
    );
    assert_eq!(
        IStablecoin::forcedTransferWithMemoCall::SELECTOR,
        [0xea, 0x24, 0x5f, 0xb8]
    );
    assert_eq!(
        IStablecoinFactory::predictTokenAddressCall::SELECTOR,
        [0xc5, 0xab, 0x02, 0x80]
    );
    assert_eq!(
        IStablecoinFactory::listTokensCall::SELECTOR,
        [0xe3, 0x0e, 0x5a, 0xe9]
    );
    assert_eq!(
        IStablecoinPolicyRegistry::createDirectionalPolicyCall::SELECTOR,
        [0xba, 0xa1, 0x72, 0x5c]
    );
    assert_eq!(
        IStablecoinPolicyRegistry::policyMemberCountCall::SELECTOR,
        [0x20, 0xaa, 0x75, 0x1c]
    );
    assert_eq!(
        IStablecoinPolicyRegistry::listPolicyMembersCall::SELECTOR,
        [0xb5, 0x4e, 0x03, 0x19]
    );
    assert_eq!(
        IVote::getProposalBondCall::SELECTOR,
        [0xb6, 0xe1, 0x93, 0x28]
    );
}

#[test]
fn alloy_encodes_canonical_dynamic_arguments() {
    let factory = IStablecoinFactory::predictTokenAddressCall {
        issuer: Address::with_last_byte(0x11),
        ticker: "EXUSD".to_owned(),
    }
    .abi_encode();
    assert_eq!(
        factory.as_slice(),
        &hex!("c5ab02800000000000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000054558555344000000000000000000000000000000000000000000000000000000")
    );

    let directional = IStablecoinPolicyRegistry::createDirectionalPolicyCall {
        admin: Address::with_last_byte(0x22),
        sendPolicyId: U256::from(2),
        receivePolicyId: U256::from(3),
        mintPolicyId: U256::from(1),
    }
    .abi_encode();
    assert_eq!(
        directional.as_slice(),
        &hex!("baa1725c0000000000000000000000000000000000000000000000000000000000000022000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000001")
    );

    let memo = IStablecoin::transferWithMemoCall {
        to: Address::with_last_byte(0x33),
        amount: U256::from(7),
        memo: B256::repeat_byte(0x44),
    }
    .abi_encode();
    assert_eq!(
        memo.as_slice(),
        &hex!("95777d59000000000000000000000000000000000000000000000000000000000000003300000000000000000000000000000000000000000000000000000000000000074444444444444444444444444444444444444444444444444444444444444444")
    );
}

#[test]
fn alloy_event_and_error_selectors_match_solidity_vectors() {
    assert_eq!(
        IStablecoinFactory::StablecoinCreated::SIGNATURE_HASH,
        b256!("3bc7cf7e0d900433f10a105db3704bd383cbe686a86099bff51166e3c9e5fe02")
    );
    assert_eq!(
        IStablecoin::TransferWithMemo::SIGNATURE_HASH,
        b256!("57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0")
    );
    assert_eq!(
        IVote::ProposalBondBurned::SIGNATURE_HASH,
        b256!("b7e5d2683c51bcb2296756a4963c8b5130542b95b0f975446e6f3ac3f02dfb89")
    );
    assert_eq!(
        IStablecoinPolicyRegistry::MembershipUnchanged::SELECTOR,
        [0x0c, 0xdf, 0x47, 0x3a]
    );
    assert_eq!(
        IStablecoinPolicyRegistry::PolicyMemberEnumerationUnsupported::SELECTOR,
        [0x1c, 0x87, 0x79, 0xff]
    );
    assert_eq!(
        IStablecoin::ERC7943CannotSend::SELECTOR,
        [0x45, 0xba, 0xe9, 0xe2]
    );
    assert_eq!(
        IStablecoin::ERC7943CannotReceive::SELECTOR,
        [0x70, 0x5c, 0x1e, 0xed]
    );
    assert_eq!(
        IStablecoin::ERC7943CannotTransfer::SELECTOR,
        [0x22, 0xdd, 0xa4, 0xbe]
    );
    assert_eq!(
        IStablecoin::ERC7943InsufficientUnfrozenBalance::SELECTOR,
        [0x00, 0x38, 0x4e, 0x71]
    );
    assert_eq!(
        IVote::ProposalErrored::SIGNATURE_HASH,
        b256!("c67a227da837cfcd61a6205491c7c4e5e187f7f490ff3ff1ba7735fe96f6f724")
    );
}

fn canonical_abi_hash(mut bytes: &[u8]) -> B256 {
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    keccak256(bytes)
}
