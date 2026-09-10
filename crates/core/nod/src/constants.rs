/// Legacy ERC-721 metadata surface values.
pub const TOKEN_NAME: &str = "Nod";
pub const TOKEN_SYMBOL: &str = "NOD";
pub const TOKEN_DESCRIPTION: &str = "Rudis Nod";

/// Per-bin multiplicative step in basis points. PancakeSwap LB default; each
/// bin spans a 0.25% price band. The LB-protocol constants used alongside
/// this value (`SCALE`, `SCALE_OFFSET`, `PRECISION`, `BASIS_POINT_MAX`,
/// `REAL_ID_SHIFT`, `MAX_BIN_ID`) live in `outbe_primitives::math::constants`.
pub const BIN_STEP_BP: u16 = 25;

/// Maximum number of off-chain bucket bodies inspected by the consensus
/// begin-block qualifier. Remaining work stays in the compact EVM worklist
/// and is resumed deterministically in the next block.
pub const MAX_BUCKET_QUALIFICATIONS_PER_BLOCK: u32 = 256;

/// Call-price markup percent: `call = entry x (100 + CALL_RATE_PCT) / 100`
/// (256 => +256%, i.e. 3.56x entry). Same shape as credis' 64 and
/// gem/intex's 128, one rung up the same ladder.
pub const CALL_RATE_PCT: u64 = 256;

/// Trailing window the daily call scan inspects, in whole UTC days.
pub const CALL_LOOKBACK_DAYS: u32 = 28;

/// Breach days within the lookback window that arm a call. A day at or below the
/// call price, and a day with no published price, both simply fail to count, so
/// the window absorbs up to `CALL_LOOKBACK_DAYS - CALL_BREACH_DAYS` of either.
pub const CALL_BREACH_DAYS: u32 = 21;

/// Seconds after `called_at` within which the owner must settle and mine. Once
/// elapsed the bucket's remaining Nods are forfeit-burned.
pub const CALL_NOTICE_PERIOD: u64 = 7 * 24 * 3600;

/// Callable buckets visited per daily run; the cursor resumes the rest. A bucket
/// displaced past the cursor is picked up a day later, which cannot change an
/// outcome: the call needs a multi-week breach count and the forfeit follows a
/// seven-day window.
pub const MAX_NOD_CALL_VISITS: u32 = 4096;

/// Nod bodies forfeit-burned per daily run, far below the visit budget because a
/// forfeit is a compressed-entity load plus delete rather than an EVM slot write.
/// A correlated mass-forfeit is the expected shape of a call event, not a tail
/// case, so the burst needs its own cap.
pub const MAX_NOD_FORFEITS_PER_RUN: u32 = 256;
