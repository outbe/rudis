//! Finalization actor (Half B of the validator-rewards refactor).
//!
//! `FinalizationActor` owns the per-finalization side effects that used
//! to live inside `application::handler` - bridge updates, DKG header
//! artifact recording, replay classification, VRF seed propagation,
//! and (post-step-21) the block-cache eviction. It runs in a separate
//! tokio task with its own unbounded mailbox so that slow consumers
//! (bridge, DKG manager, executor) cannot back-pressure the voter
//! task by saturating the application handler's bounded mailbox.
//!
//! for the full design and the migration sequence
//! through steps 16-21.

pub mod actor;
pub mod attestation;
pub mod block_cache;
pub mod committee_prelude;
pub mod finalize_verify;
pub mod ingress;
pub mod late_sig_store;
pub mod parent_cert_store;
pub mod resolver;
pub mod selection;
pub mod state;
pub mod util;
