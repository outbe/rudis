/// SRA cost rate (share of the full agent cost): cost = `full x SRA_RATE / 100`
/// (64 => 0.64x).
pub const SRA_RATE: u64 = 64;

/// Positions the daily sweep may retire before it gives out.
pub const MAX_POSITION_EXPIRIES_PER_RUN: u32 = 256;
