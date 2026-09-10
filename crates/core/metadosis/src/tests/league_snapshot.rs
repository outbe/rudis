use alloy_primitives::{address, U256};
use outbe_ocomp_protocol::league_snapshot::{
    league_snapshot_slot, METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT,
};
use outbe_primitives::addresses::METADOSIS_ADDRESS;

use crate::fixture_kernel::FixtureKernelExt;
use crate::tests::with_contract;

/// Pins the hand-derived `METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT` against the slot
/// the `#[storage_schema]` macro actually assigns to the appended snapshot
/// mapping. If the Metadosis layout ever shifts, this fails loudly rather than
/// letting the node/worker open the wrong slots.
#[test]
fn snapshot_base_slot_matches_the_generated_dsl_layout() {
    with_contract(|metadosis| {
        assert_eq!(
            metadosis.ocomp_fidelity_league_snapshot.base_slot(),
            U256::from(METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT),
        );
    });
}

/// The node and worker derive each owner's league slot purely (no storage
/// handle) via `league_snapshot_slot`. This proves that pure derivation points
/// at the exact storage word the DSL `Mapping` writes, closing the loop on the
/// base-slot and key derivation together.
#[test]
fn pure_snapshot_slot_points_at_the_dsl_written_word() {
    with_contract(|metadosis| {
        let wwd = 20_260_709u32;
        let owner = address!("7200000000000000000000000000000000000072");
        metadosis
            .fixture_write_league_snapshot(wwd, owner, 4096u16)
            .unwrap();

        let slot = league_snapshot_slot(wwd, owner);
        let word = metadosis
            .storage
            .sload(METADOSIS_ADDRESS, U256::from_be_bytes(slot.0))
            .unwrap();
        assert_eq!(word, U256::from(4096u16));
    });
}
