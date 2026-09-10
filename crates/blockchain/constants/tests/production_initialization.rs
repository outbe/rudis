#![cfg(not(feature = "test-protocol-overrides"))]

use outbe_chain_constants::{
    get_metadosis_forming_period_seconds, get_ocomp_compute_vote_window_blocks, initialize,
    ProtocolConstantsError, DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS,
    DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS,
};
use serde_json::json;

#[test]
fn production_getters_are_zero_state_defaults_and_reject_the_test_key() {
    assert_eq!(
        outbe_chain_constants::get_governance_voting_window_blocks(),
        86_400
    );
    assert_eq!(
        get_metadosis_forming_period_seconds(),
        DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS
    );
    assert_eq!(
        get_ocomp_compute_vote_window_blocks(),
        DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS
    );

    initialize(None).unwrap();
    initialize(None).unwrap();

    let override_value = json!({});
    assert_eq!(
        initialize(Some(&override_value)),
        Err(ProtocolConstantsError::UnsupportedInProduction)
    );

    assert_eq!(
        get_metadosis_forming_period_seconds(),
        DEFAULT_METADOSIS_FORMING_PERIOD_SECONDS
    );
}
