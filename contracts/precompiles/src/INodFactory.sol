// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface INodFactory {
    event NodIssued(
        address indexed owner,
        uint256 nodId,
        uint256 worldwideDay,
        uint256 leagueId,
        uint256 floorPriceMinor,
        uint256 gratisLoadMinor,
        uint256 entryPriceMinor,
        uint256 costAmountMinor
    );

    event NodBurned(address indexed owner, uint256 nodId, uint256 gratisLoadMinor);

    event NodMaterializationProgress(
        uint64 indexed queueSequence,
        uint32 indexed worldwideDay,
        uint64 generation,
        uint32 firstNodOrdinal,
        uint32 nextNodOrdinal,
        bool completed,
        uint64 blockNumber
    );

    error NodMaterializationRejected(uint8 code);

    /// @notice Emitted when a Nod's cost is discharged by burning a PayNote.
    /// Names the spent nullifier instead of a payer address: the note is what
    /// pays, and it is deliberately not linkable to a payer.
    event NodPaid(address indexed owner, uint256 nodId, address asset, bytes32 nullifier, uint256 amountCovered);

    /// @notice Constant-size owner event for one certified OCOMP generation.
    /// There is deliberately no matching public installation selector.
    event CertifiedNodGenerationInstalled(
        bytes32 indexed activationCallId,
        uint32 indexed worldwideDay,
        uint64 targetGeneration,
        bytes32 namespaceRootBefore,
        uint32 tributeCount,
        uint32 nodCount,
        uint32 bucketCount,
        bytes32 nodRoot,
        bytes32 bucketRoot,
        bytes32 outputManifestRoot,
        uint256 nodAmountTotal,
        uint256 nodGratisConsumed,
        uint64 issuedAt,
        bytes32 stateEventDigest
    );

    /// @notice Burn the caller-owned Nod and mint its gratis load to the caller.
    ///
    /// @dev Callable only by the Nod's owner, who is also the gratis recipient
    /// and so can always supply the mint authorization.
    ///
    /// The Nod's cost is discharged here, by spending a PayNote.
    /// The underlying value already reached the reserve vault when the note
    /// was deposited, so this call moves no tokens: it books the note's nullifier,
    /// appends any change note to the pool, and logs `NodPaid` event.
    ///
    /// @param nodId        Identifier of a Nod owned by the caller.
    /// @param nonce Proof-of-work nonce. `sha256(nodId_be32 || nonce_be8)`
    /// MUST have the protocol's required leading zero bytes.
    /// @param mac Gratis mint authorization, `HMAC(modifyKey, op-preimage)`
    /// under the caller's Gratis modify key.
    /// @param opNonce MUST equal the caller's current on-chain gratis op-nonce;
    /// binds `mac` to exactly this mint.
    /// @param payNoteProof `outbe.paynote` spend proof.
    /// @return Gratis minor units minted to the caller.
    function mineGratis(uint256 nodId, uint64 nonce, bytes32 mac, uint64 opNonce, bytes calldata payNoteProof)
        external
        returns (uint256);

    /// @notice Materialize the current certified FIFO head from one canonical
    /// proof-backed OCOMP batch.
    function materializeCertifiedNods(bytes calldata canonicalBatch) external;

    /// @notice Return the canonical current FIFO head, or `exists=false` when empty.
    function materializationHead() external view returns (bool exists, bytes memory canonicalHead);
}
