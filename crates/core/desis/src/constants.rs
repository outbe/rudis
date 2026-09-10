pub use outbe_primitives::addresses::ORIGIN_ROUTER_ADDRESS;

/// Minimum-bid-quantity floor: 4% of the prior series' issued count (basis points).
pub const BID_QUANTITY_FLOOR_BPS: u32 = 400;

/// Currency the ladder reads the rate in; mirrors the oracle's `DAY_TYPE_ISO`.
pub const PROMIS_LOAD_ANCHOR_ISO: u16 = 840;

/// The rung the first Intex carries: 10^11 minor, 100 000 PROMIS at six decimals.
pub const PROMIS_LOAD_LAUNCH_EXPONENT: u32 = 11;

/// Deadband at each decade boundary, so a rate loitering there stops flipping the load daily.
pub const PROMIS_LOAD_DEADBAND_BPS: u32 = 200;

/// Fixed load bypassing the ladder. The harness seeds the day's mint cap at 500
/// PROMIS, far under one laddered Intex, so a laddered e2e day would issue none.
#[cfg(not(feature = "e2e-test"))]
pub const PROMIS_LOAD_OVERRIDE: Option<u128> = None;
#[cfg(feature = "e2e-test")]
pub const PROMIS_LOAD_OVERRIDE: Option<u128> = Some(1);

/// Bid fan-in deadline: clearing proceeds without chains that have not reported
/// BIDS_DONE within this window after the clearing stage starts. A repair window
/// for parked legs; must stay under 24h so the deadline clear lands the same UTC
/// day as the dispatch.
pub const BIDS_FANIN_TIMEOUT_SECS: u64 = 12 * 3600;

/// Midnight-anchored schedule: the commit, reveal and settlement windows each span one day.
#[cfg(not(feature = "e2e-test"))]
pub const COMMIT_WINDOW_SECONDS: u64 = 24 * 3600;
#[cfg(not(feature = "e2e-test"))]
pub const REVEAL_WINDOW_SECONDS: u32 = 24 * 3600;
#[cfg(not(feature = "e2e-test"))]
pub const SETTLEMENT_WINDOW_SECONDS: u64 = 24 * 3600;

/// An e2e run walks the same stages inside one day, so its windows have to fit
/// there: a day-long window would carry the auction over a midnight the run
/// never formed.
#[cfg(feature = "e2e-test")]
pub const COMMIT_WINDOW_SECONDS: u64 = 900;
#[cfg(feature = "e2e-test")]
pub const REVEAL_WINDOW_SECONDS: u32 = 1800;
#[cfg(feature = "e2e-test")]
pub const SETTLEMENT_WINDOW_SECONDS: u64 = 1800;

/// Guarantee at least this much commit window; a brief that would leave less
/// anchors to the next midnight instead.
#[cfg(not(feature = "e2e-test"))]
pub const MIN_COMMIT_WINDOW_SECONDS: u64 = 18 * 3600;
#[cfg(feature = "e2e-test")]
pub const MIN_COMMIT_WINDOW_SECONDS: u64 = 300;

/// `dayState` wire values carried by AUCTION_STAGE_START.
pub const DAY_STATE_GREEN: u8 = 1;
pub const DAY_STATE_RED: u8 = 2;

/// Bidders per REFUND_INSTRUCTIONS message: the codec's `MAX_PAYLOAD_ARRAY_LEN`. Issuance uses its own,
/// narrower cap - a recipient costs a mint, a bidder costs a lock update.
pub use outbe_intexfactory::constants::MAX_RECIPIENTS_PER_MESSAGE as REFUND_CHUNK_LEN;

/// Chunks one chain-day's refunds may span; mirrors the codec's `MAX_CHUNKS`.
pub const MAX_REFUND_CHUNKS: usize = 256;

/// Bids one PROCESS_BIDS_BATCH message may carry; mirrors the codec's `MAX_BIDS_BATCH`.
pub const MAX_BIDS_PER_BATCH: usize = 64;

/// Batches one chain-day may send: the arrival bitmap is one 256-bit word.
pub const MAX_BID_BATCHES: u16 = 256;

// Everything the intake admits from one chain must still fit its refund fan-out;
// otherwise clearing fails on bids the intake already took.
const _: () =
    assert!(MAX_BIDS_PER_BATCH * MAX_BID_BATCHES as usize <= REFUND_CHUNK_LEN * MAX_REFUND_CHUNKS);

/// Reference currencies one day may price. Mirrors the codec's `MAX_REFERENCE_PRICES`:
/// a day over it could not be started on any chain.
pub const MAX_REFERENCE_PRICES: usize = 6;

/// `IDesis.InboundIgnored` reason codes; mirrors the routers' `InboundReason` library.
pub const IGNORED_OBSOLETE: u8 = 2;
pub const IGNORED_CONFLICT: u8 = 3;
pub const IGNORED_NOT_FOUND: u8 = 4;
