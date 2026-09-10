//! Whitelist for pre-exec hook events published via the `HookEvents` system tx.

use alloy_primitives::{Address, Log};

use crate::addresses::{
    GEM_ADDRESS, GOVERNANCE_ADDRESS, INTEX_FACTORY_ADDRESS, NOD_ADDRESS,
    STABLECOIN_FACTORY_ADDRESS, UPDATE_ADDRESS, VOTE_ADDRESS,
};

/// Contract addresses whose pre-exec hook events are copied into the mandatory
/// [`SystemTxKind::HookEvents`](crate::system_tx::SystemTxKind::HookEvents)
/// begin-zone system transaction receipt.
pub const HOOK_EVENT_RECEIPT_ADDRESSES: &[Address] = &[
    VOTE_ADDRESS,
    UPDATE_ADDRESS,
    NOD_ADDRESS,
    GOVERNANCE_ADDRESS,
    STABLECOIN_FACTORY_ADDRESS,
    GEM_ADDRESS,
    INTEX_FACTORY_ADDRESS,
];

/// Returns `true` when `address` is whitelisted for hook-event receipt publication.
pub fn is_hook_event_receipt_address(address: Address) -> bool {
    HOOK_EVENT_RECEIPT_ADDRESSES.contains(&address)
}

/// Splits hook events into receipt-visible (whitelisted) and tracing-only buckets.
pub fn partition_hook_events(events: &[Log]) -> (Vec<Log>, Vec<Log>) {
    let mut receipt_visible = Vec::new();
    let mut tracing_only = Vec::new();
    for event in events {
        if is_hook_event_receipt_address(event.address) {
            receipt_visible.push(event.clone());
        } else {
            tracing_only.push(event.clone());
        }
    }
    (receipt_visible, tracing_only)
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{Bytes, Log, LogData, B256};

    use crate::addresses::{NOD_ADDRESS, REWARDS_ADDRESS};

    use super::*;

    fn log_at(address: Address) -> Log {
        Log {
            address,
            data: LogData::new(vec![B256::ZERO], Bytes::new()).expect("test log data"),
        }
    }

    #[test]
    fn partition_keeps_only_whitelisted_addresses_for_receipt() {
        let (whitelisted, tracing_only) = partition_hook_events(&[
            log_at(REWARDS_ADDRESS),
            log_at(VOTE_ADDRESS),
            log_at(UPDATE_ADDRESS),
            log_at(NOD_ADDRESS),
            log_at(GOVERNANCE_ADDRESS),
            log_at(STABLECOIN_FACTORY_ADDRESS),
        ]);
        assert_eq!(whitelisted.len(), 5);
        assert_eq!(whitelisted[0].address, VOTE_ADDRESS);
        assert_eq!(whitelisted[1].address, UPDATE_ADDRESS);
        assert_eq!(whitelisted[2].address, NOD_ADDRESS);
        assert_eq!(whitelisted[3].address, GOVERNANCE_ADDRESS);
        assert_eq!(whitelisted[4].address, STABLECOIN_FACTORY_ADDRESS);
        assert_eq!(tracing_only.len(), 1);
        assert_eq!(tracing_only[0].address, REWARDS_ADDRESS);
    }
}
