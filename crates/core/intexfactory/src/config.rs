//! Genesis-selectable parameter profile for IntexFactory: `PROD` (real timings)
//! and `DEV` (short timings) are fixed here. A chain picks one via the
//! `config_profile` selector byte seeded from genesis; an unset byte resolves by
//! network, so only mainnet runs PROD.

use outbe_primitives::chain::is_mainnet;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::units::SCALE_1E18_U128;

use crate::constants::{
    CALL_NOTICE_PERIOD, CALL_RATE, CALL_THRESHOLD, CALL_WINDOW, COMMIT_BOND_MINOR, FLOOR_RATE,
};
use crate::schema::IntexFactoryContract;

/// Resolve by network: PROD on mainnet, DEV everywhere else.
pub const PROFILE_AUTO: u8 = 0;
pub const PROFILE_DEV: u8 = 1;
pub const PROFILE_PROD: u8 = 2;

/// Resolved IntexFactory protocol parameters. Periods are seconds; rates are
/// percentage points over [`crate::constants::PRICE_RATE_DEN`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntexParams {
    pub call_window: u32,
    pub call_threshold: u32,
    pub call_notice_period: u32,
    pub call_rate: u16,
    pub floor_rate: u16,
    /// Commit-entry bond on the target-chain auction in 18-decimal WCOEN units.
    pub commit_bond_minor: u128,
}

impl IntexParams {
    /// Real protocol timings; the default on mainnet.
    pub const PROD: Self = Self {
        call_window: CALL_WINDOW,
        call_threshold: CALL_THRESHOLD,
        call_notice_period: CALL_NOTICE_PERIOD,
        call_rate: CALL_RATE,
        floor_rate: FLOOR_RATE,
        commit_bond_minor: COMMIT_BOND_MINOR,
    };

    /// Short timings for dev/test. `called` is day-granular (daily VWAP scan),
    /// so window/threshold stay whole multiples of a day. The bond drops to
    /// 100 wCOEN so test bidders are not forced to mint 100M per commit.
    pub const DEV: Self = Self {
        call_window: 3 * 24 * 3600,
        call_threshold: 2 * 24 * 3600,
        #[cfg(not(feature = "e2e-test"))]
        call_notice_period: 3 * 24 * 3600,
        #[cfg(feature = "e2e-test")]
        call_notice_period: 600,
        call_rate: 10,
        floor_rate: 5,
        commit_bond_minor: 100 * SCALE_1E18_U128,
    };

    /// The profile a chain runs when genesis left the selector unset.
    pub const fn for_chain_id(chain_id: u64) -> Self {
        if is_mainnet(chain_id) {
            Self::PROD
        } else {
            Self::DEV
        }
    }

    pub fn from_selector(selector: u8, chain_id: u64) -> Result<Self> {
        match selector {
            PROFILE_AUTO => Ok(Self::for_chain_id(chain_id)),
            PROFILE_DEV => Ok(Self::DEV),
            PROFILE_PROD => Ok(Self::PROD),
            other => Err(PrecompileError::Revert(format!(
                "unknown intex profile selector: {other}"
            ))),
        }
    }
}

pub fn read(storage: &StorageHandle<'_>) -> Result<IntexParams> {
    read_from(
        &IntexFactoryContract::new(storage.clone()),
        storage.chain_id()?,
    )
}

pub(crate) fn read_from(factory: &IntexFactoryContract<'_>, chain_id: u64) -> Result<IntexParams> {
    IntexParams::from_selector(factory.config_profile.read()?, chain_id)
}
