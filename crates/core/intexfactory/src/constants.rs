//! Module-local constants: external contract addresses called via
//! `storage.call`, plus protocol constants.

#[cfg(feature = "e2e-test")]
use alloy_primitives::{address, Address};
use outbe_primitives::units::SCALE_1E18_U128;

pub use outbe_primitives::addresses::{INTEX_NFT1155_ADDRESS, ORIGIN_ROUTER_ADDRESS};

/// A payout e2e credits proceeds without deploying the router, so a throwaway
/// build also accepts Hardhat account #0 as their source.
#[cfg(feature = "e2e-test")]
pub const PROCEEDS_TEST_SENDER: Address = address!("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// minePromis PoW difficulty: required leading zero bytes of the work hash.
pub const POW_DIFFICULTY: usize = 1;

/// Max contributor payouts per `distribute` pass (pagination chunk size).
/// Large series are drained across several blocks by the begin-block hook.
pub const DIST_CHUNK_LIMIT: u32 = 200;

/// Proceeds fan-in window: creators are paid once every winning chain has
/// routed its proceeds, or this long after issuance - whichever comes first.
/// A full day absorbs legitimate escrow-finalize retries so, in virtually all
/// cases, creators receive a single payment.
pub const PROCEEDS_FANIN_TIMEOUT_SECS: u64 = 24 * 60 * 60;

/// Bin step (basis points) for the floor-price bin ladder.
pub const BIN_STEP_BP: u16 = 25;

/// Work one lifecycle scan may do: a decision reads a group, an action writes one
/// series with its index move and notice. Budgeted apart because they differ in cost.
pub(crate) const MAX_GROUP_DECISIONS_PER_BLOCK: u32 = 256;
pub(crate) const MAX_SERIES_ACTIONS_PER_BLOCK: u32 = 256;

/// Router calls one `intex_notify` firing may make; an entry costing none still
/// spends one. Sized to clear a day of calls inside [`CALL_NOTICE_PERIOD`] while
/// leaving CycleTick its block headroom.
pub const MAX_ROUTER_CALLS_PER_FIRING: u32 = 64;

/// Markup rates in percentage points: price = entry * (PRICE_RATE_DEN + rate) / PRICE_RATE_DEN.
pub const PRICE_RATE_DEN: u16 = 100;

/// Floor price = entry * 1.08.
pub const FLOOR_RATE: u16 = 8;
/// Call price = entry * 2.28; its breach arms a Call Event.
pub const CALL_RATE: u16 = 128;

/// Notice a holder gets to settle after a series is Called.
pub const CALL_NOTICE_PERIOD: u32 = 7 * 24 * 3600;

/// Call-trigger evaluation window: the most recent stretch scanned for breaches.
pub const CALL_WINDOW: u32 = 28 * 24 * 3600;
/// Call-trigger threshold: how much of the window must be in breach to force-call.
pub const CALL_THRESHOLD: u32 = 21 * 24 * 3600;

/// Commit-entry bond on the target-chain auction: 100M WCOEN in native
/// 18-decimal payment-token units.
pub const COMMIT_BOND_MINOR: u128 = 100_000_000 * SCALE_1E18_U128;

/// Series one ISSUANCE_INSTRUCTIONS message may carry. Mirrors `MAX_SERIES_PER_ISSUANCE`.
pub const MAX_SERIES_PER_MESSAGE: usize = 8;

/// Recipients one ISSUANCE_INSTRUCTIONS may carry across its series. Mirrors the codec's
/// `MAX_RECIPIENTS_PER_ISSUANCE`, which is narrower than the general payload cap because a
/// recipient costs an issue on the destination.
pub const MAX_RECIPIENTS_PER_ISSUANCE: usize = 24;

/// The general cross-chain array cap, mirroring `MAX_PAYLOAD_ARRAY_LEN`. Refund chunks use it.
pub const MAX_RECIPIENTS_PER_MESSAGE: usize = 64;

/// Series one MARK_CALLED or MARK_QUALIFIED message may carry. Mirrors the
/// codec's `MAX_SERIES_PER_MARK`; a wider group is sent in several messages.
pub const MAX_SERIES_PER_MARK: usize = 8;
