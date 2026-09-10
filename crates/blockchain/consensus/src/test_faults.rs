use commonware_consensus::types::Height;

#[cfg(feature = "test-marshal-drop")]
pub(crate) fn should_drop_new_payload_for_test(height: Height) -> bool {
    std::env::var("OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|target_height| target_height == height.get())
}

#[cfg(not(feature = "test-marshal-drop"))]
pub(crate) const fn should_drop_new_payload_for_test(_height: Height) -> bool {
    false
}
