// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface ITributeFactory {
    // `zkProof` is the self-describing combined proof for the pinned
    // `outbe.full_proof@1.0.0` circuit. It is mandatory for a registered L2
    // operator with ZK verification enabled. `zkVerificationKey` and
    // `zkPublicKey` remain ignored ABI placeholders: the circuit is pinned by
    // the chain and the root-signing key comes from L2Registry.
    //
    // `signature` is the L2 committee's compressed BLS MinSig signature in G1
    // (48 bytes) over the 32-byte `zkMerkleRoot`. L2Registry stores the
    // corresponding compressed G2 group key (96 bytes). Unregistered callers
    // and networks with ZK disabled may pass empty ZK fields.
    function offerTribute(
        bytes calldata cipherText,
        bytes calldata nonce,
        uint256 ephemeralPubkey,
        uint32 worldwideDay,
        uint16 tributeCurrency,
        uint16 referenceCurrency,
        bool excludeFromIntexIssuance,
        bytes calldata zkProof,
        bytes calldata zkVerificationKey,
        bytes calldata zkPublicKey,
        bytes calldata zkMerkleRoot,
        bytes calldata signature
    ) external returns (uint256 tributeId);
}
