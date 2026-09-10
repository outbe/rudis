// SPDX-License: UNLICENSED
pragma solidity ^0.8.30;

/// @title IEmit
/// @notice Emit private-note tree precompile at
///         0x000000000000000000000000000000000000EE13
interface IEmit {
    /// Burn native COEN into a private note. The commitment is derived from
    /// the runtime chain ID, `noteSn`, and the caller-supplied value; the note
    /// itself (owner, spend key) is chosen off-chain and proven later at mint.
    /// `msg.value` must be positive. Native base units map 1:1 to the
    /// circuit's full-width uint256 amount.
    function burn(bytes32 noteSn) external payable;

    /// Redeem a private note: prove membership under an accepted root,
    /// nullify the note, credit `mintUnits` to `payoutRecipient`, and - when
    /// the note holds more than `mintUnits` - append the circuit-derived
    /// deterministic change commitment. The caller must be `noteOwner`; the
    /// embedded proof statement must equal the explicit calldata fields. The
    /// proof's chain ID must equal the runtime chain ID. `proof` is the combined
    /// UltraHonkKeccak wire for the frozen Emit mint circuit
    /// (`outbe.emit.mint`, version 1.5.0), enforced at its exact frozen
    /// length.
    function mint(
        address payoutRecipient,
        bytes32 root,
        bytes32 nullifier,
        address noteOwner,
        uint256 mintUnits,
        bytes32 changeCommitment,
        bytes calldata proof
    ) external;

    /// @notice Latest commitment-tree root.
    function currentRoot() external view returns (bytes32 root);

    /// @notice Number of leaves appended so far; `0` means a pristine tree.
    function leafCount() external view returns (uint64 count);

    /// @notice Whether `nullifier` has already been spent.
    function isSpent(bytes32 nullifier) external view returns (bool spent);

    /// @notice Whether `commitment` is already a leaf of the tree.
    function hasCommitment(bytes32 commitment) external view returns (bool present);

    /// @notice A commitment was appended to the chain's Emit tree.
    /// @param commitment The appended commitment (indexed).
    /// @param leafIndex Zero-based leaf position of the append.
    /// @param rootAfter Tree root after the append.
    /// @param noteAmount Burned public amount; `0` is the sentinel for a
    ///        partial mint's change note, whose remaining value is private.
    event NewNote(bytes32 indexed commitment, uint32 leafIndex, bytes32 rootAfter, uint256 noteAmount);

    /// @notice A note was spent via mint.
    /// @param noteOwner Owner proven by the mint proof (indexed).
    /// @param payoutRecipient Recipient credited with `mintAmount` (indexed).
    /// @param nullifier The spent nullifier (indexed).
    /// @param mintAmount Credited native base units.
    event NoteUsed(
        address indexed noteOwner, address indexed payoutRecipient, bytes32 indexed nullifier, uint256 mintAmount
    );
}
