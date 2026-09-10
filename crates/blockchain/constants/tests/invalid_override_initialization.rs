#![cfg(feature = "test-protocol-overrides")]

use outbe_chain_constants::{
    get_metadosis_forming_period_seconds, initialize, ProtocolConstantsError,
};
use serde_json::json;

#[test]
fn invalid_override_does_not_initialize_the_singleton() {
    let invalid = json!({
        "metadosis": { "formingPeriodSeconds": 0 }
    });

    assert!(matches!(
        initialize(Some(&invalid)),
        Err(ProtocolConstantsError::InvalidValue {
            field: "metadosis.formingPeriodSeconds",
            ..
        })
    ));
    assert!(std::panic::catch_unwind(get_metadosis_forming_period_seconds).is_err());
}
