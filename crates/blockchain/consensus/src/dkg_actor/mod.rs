//! DKG Actor - runs interactive DKG protocol over dedicated P2P channel.
//!
//! Two modes:
//! - **Initial**: Standalone P2P ceremony, blocks consensus engine startup.
//!   All validators are simultaneously Dealer AND Player.
//! - **Reshare**: Runs in parallel with consensus; finalized dealer logs may be
//!   carried in block headers while the ceremony is still in progress. Previous
//!   share holders are Dealers; the frozen target set are Players.

pub mod actor;
mod recovery;
pub mod wire;

#[cfg(test)]
mod sim_tests;

#[cfg(test)]
pub use actor::{run_initial_dkg, run_reshare_dealer_only};
pub use actor::{
    run_initial_dkg_durable, run_reshare_dealer_only_durable, DkgComplete, DkgDealerOnlyComplete,
    DkgProgress,
};
pub use recovery::DkgRetryStore;
