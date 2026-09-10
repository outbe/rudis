#![cfg(feature = "test-protocol-overrides")]

use outbe_chain_constants::{
    get_metadosis_forming_period_seconds, get_metadosis_lookback_delay_seconds,
    get_ocomp_compute_vote_window_blocks, initialize, ProtocolConstantsError,
    DEFAULT_METADOSIS_LOOKBACK_DELAY_SECONDS,
};
use serde_json::json;

#[test]
fn test_initialization_resolves_genesis_overrides() {
    let overrides = json!({
        "governance": { "votingWindowBlocks": 17 },
        "metadosis": { "formingPeriodSeconds": 60 },
        "ocomp": { "computeVoteWindowBlocks": 120 }
    });

    initialize(Some(&overrides)).unwrap();
    assert_eq!(
        outbe_chain_constants::get_governance_voting_window_blocks(),
        17
    );

    assert_eq!(get_metadosis_forming_period_seconds(), 60);
    assert_eq!(
        get_metadosis_lookback_delay_seconds(),
        DEFAULT_METADOSIS_LOOKBACK_DELAY_SECONDS
    );
    assert_eq!(get_ocomp_compute_vote_window_blocks(), 120);
    assert_eq!(
        initialize(None),
        Err(ProtocolConstantsError::AlreadyInitialized)
    );
}
