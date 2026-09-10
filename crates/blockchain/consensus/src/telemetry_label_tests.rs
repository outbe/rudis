//! CL-2: telemetry-label charset guard for consensus-crate spawn labels.
//!
//! commonware 2026.5.0's `validate_label` panics if a span/metric label is not
//! `[a-zA-Z][a-zA-Z0-9_]*` (the BUG-B class that crashed DKG rotation ~block 90).
//! This feeds the labels the consensus crate passes to `Context::child(...)`
//! through the REAL commonware validator - the same function the runtime invokes
//! when building a child-context label - so an invalid label fails here instead
//! of panicking in production. It asserts actual label values via the real
//! validator; it does NOT scan source text.

/// Static labels the consensus crate passes to `Context::child(...)` on its
/// spawn / metric paths. Add new labels here when introducing a labeled child
/// context. New labels are additionally caught at runtime: commonware panics in
/// `validate_label`, which the actor/handler behavioral tests and the localnet
/// harness exercise by actually spawning these contexts.
const CONSENSUS_SPAWN_LABELS: &[&str] = &[
    "ancestry",
    "broadcast",
    "cert_mux",
    "dkg_ceremony",
    "driver",
    "engine",
    "exec",
    "executor",
    "genesis",
    "marshal",
    "marshal_blocks",
    "marshal_finalizations",
    "marshal_node",
    "marshal_resolver",
    "network",
    "node",
    "propose",
    "res_mux",
    "resolver_handler",
    "verify",
    "vote_mux",
    "writer",
];

/// Every consensus spawn label is accepted by commonware's real `validate_label`
/// (which `panic!`s on an invalid charset). A regression that renames a label to
/// an invalid form fails this test instead of crashing the node at runtime.
#[test]
fn consensus_spawn_labels_pass_commonware_validate_label() {
    for label in CONSENSUS_SPAWN_LABELS {
        commonware_runtime::telemetry::metrics::validate_label(label);
    }
}

/// Guard the guard: prove `validate_label` actually rejects the dotted form that
/// caused BUG-B, so the test above is meaningful (not a no-op validator).
#[test]
#[should_panic]
fn dotted_label_is_rejected_by_commonware_validate_label() {
    commonware_runtime::telemetry::metrics::validate_label("dkg.live");
}
