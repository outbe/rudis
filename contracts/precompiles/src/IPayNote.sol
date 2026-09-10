// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

/// @title IPayNote
/// @notice Shielded pool at 0x0000000000000000000000000000000000001019.
/// A deposit pulls `amount` of `asset` from the caller, routes it into the
/// asset's reserve vault via VaultRouter, and appends a note commitment to an
/// incremental Merkle tree. The commitment is always derived by the runtime
/// from the transfer it actually performed - opaque caller-supplied commitments
/// are prohibited, so Merkle membership attests both the asset and the amount.
///
/// Spending is deliberately **not** on this interface. It consumes a frozen
/// `outbe.paynote`, version 1.1.0, UltraHonkKeccak proof and is exposed only as
/// the in-process Rust API `outbe_paynote::api::consume`, for integration by
/// other precompile modules.
interface IPayNote {
    /// @notice The pool holds no vault for this asset.
    error AssetVaultMissing(address asset);
    /// @notice A field-typed argument is not a canonical BN254 word.
    error NonCanonicalField(string field);
    /// @notice An argument that must be non-zero was zero.
    error MustBeNonZero(string field);
    /// @notice This commitment is already in the tree.
    error CommitmentExists(bytes32 commitment);
    /// @notice The commitment tree is at its 2^32-leaf capacity.
    error TreeFull();

    /// @notice Deposit `amount` of `asset` into the pool under `noteSn`.
    /// @dev `noteSn` is the note serial number - a hiding commitment to the spend key,
    /// chosen off-chain as `P(NOTE_SN, [spendKey])`. It reveals nothing about the key.
    /// @param asset ERC20 to deposit; must have a registered reserve vault.
    /// @param amount Units to pull from the caller.
    /// @param noteSn Caller-supplied note serial. Must be a non-zero canonical
    /// BN254 field word.
    function deposit(address asset, uint256 amount, bytes32 noteSn) external;

    /// @notice Latest commitment-tree root.
    function currentRoot() external view returns (bytes32 root);

    /// @notice Number of leaves appended so far; `0` means a pristine tree.
    function leafCount() external view returns (uint64 count);

    /// @notice Whether `root` is inside the 32-root acceptance window. Proofs
    /// are built against a root that may go stale as deposits land, so the pool
    /// accepts any root in the window, not just the latest.
    function isKnownRoot(bytes32 root) external view returns (bool known);

    /// @notice Whether `nullifier` has already been spent.
    function isSpent(bytes32 nullifier) external view returns (bool spent);

    /// @notice Whether `commitment` is already a leaf of the tree.
    function hasCommitment(bytes32 commitment) external view returns (bool present);

    /// @notice A commitment was appended to the pool's tree.
    /// @param commitment The appended commitment (indexed).
    /// @param leafIndex Zero-based leaf position of the append.
    /// @param rootAfter Tree root after the append.
    /// @param asset The note's bound ERC20 (indexed).
    /// @param noteAmount Deposited public amount; `0` is the sentinel for a
    /// spend's change note, whose remaining value is private.
    event NewNote(
        bytes32 indexed commitment, uint32 leafIndex, bytes32 rootAfter, address indexed asset, uint256 noteAmount
    );

    /// @notice A note was spent through the Rust `consume` API.
    /// @param asset The spent note's bound ERC20 (indexed).
    /// @param spender Recipient bound by the proof (indexed).
    /// @param nullifier The spent nullifier (indexed).
    /// @param spendAmount Units released by the spend.
    event NoteUsed(address indexed asset, address indexed spender, bytes32 indexed nullifier, uint256 spendAmount);
}
