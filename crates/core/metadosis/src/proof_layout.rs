use alloy_primitives::{b256, B256};

/// Fixed consensus slot used by OCM finality proof construction.
pub use crate::schema::OCOMP_JOB_RECORDS_BASE_SLOT;

/// Canonical fresh-devnet Metadosis layout description committed by genesis.
///
/// The corresponding schema test pins every value encoded here to the actual
/// generated storage layout. Changing either the layout or this description
/// therefore requires an explicit fresh-genesis contract revision.
pub const METADOSIS_STORAGE_LAYOUT_V1_CANONICAL: &[u8] = b"OUTBE_METADOSIS_STORAGE_LAYOUT_V1|worldwide_day_slots=10|active_wwd_count_slot=11|closed_wwd_base_slot=14|terminal_receipt_base_slot=36|terminal_receipt_slots=6|capacity_forfeiture_base_slot=42|capacity_forfeiture_slots=13|day_limit_receipt_base_slot=55|day_limit_receipt_slots=7";

pub const METADOSIS_STORAGE_LAYOUT_V1_HASH: B256 =
    b256!("06de88157b2c94c36b929a65c9db8d0f6a7ca10fad6d40be14098019f5749187");
