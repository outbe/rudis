#![cfg(feature = "test-protocol-overrides")]

use outbe_chain_constants::get_metadosis_forming_period_seconds;

#[test]
#[should_panic(expected = "protocol constants must be initialized before runtime access")]
fn runtime_getter_fails_fast_before_initialization() {
    let _ = get_metadosis_forming_period_seconds();
}
