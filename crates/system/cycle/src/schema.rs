use outbe_macros::contract;
use outbe_primitives::addresses::CYCLE_ADDRESS;
use outbe_primitives::storage::types::{Mapping, Slot};

/// EVM storage layout for the Cycle dispatcher.
///
/// Tracks per-trigger execution state: the timestamp of the slot most
/// recently processed and the block number that processed it. The slot
/// timestamp is canonical - `last_executed_at` is set to the
/// `next_fire_at` value chosen by the dispatcher, not to
/// `block.timestamp`, so that a clock-jump that crosses several slots
/// records the latest covered slot rather than the dispatching block's
/// wall time.
///
/// Storage slots:
///   0:  last_executed_at             - mapping(uint32 => uint64)
///   1:  last_executed_block_number   - mapping(uint32 => uint64)
///   2:  active_utc_day                - uint32
#[contract(addr = CYCLE_ADDRESS)]
pub struct Cycle {
    /// Per-trigger last-fired slot timestamp. Stored as the slot value
    /// (`offset + k * period`), not `block.timestamp`, so the
    /// scheduling math in [`crate::triggers::next_fire_at`] is
    /// monotonic across clock jumps.
    pub last_executed_at: Mapping<u32, u64>,

    /// Per-trigger block number that last fired the trigger. Useful for
    /// auditing which block dispatched which slot; not consulted by the
    /// scheduling math.
    pub last_executed_block_number: Mapping<u32, u64>,

    /// UTC calendar day currently owned by ProtocolCycle. Genesis seeds this
    /// from the consensus header timestamp. A contiguous transition settles it;
    /// a multi-day halt advances it without synthesizing missed-day economics.
    pub active_utc_day: Slot<u32>,
}
