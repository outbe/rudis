//! Private OCOMP/Fidelity snapshot boundary used while CE is still active.

use alloy_primitives::Address;
use outbe_compressed_entities::{ExecutionScope, ParentBodySource};
use outbe_ocomp_protocol::league_snapshot::{fidelity_league_snapshot_root, league_snapshot_key};
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;
use outbe_tribute::TributeContract;

use crate::schema::MetadosisContract;

impl MetadosisContract<'_> {
    /// Snapshots each day-owner's Fidelity league into per-owner storage and
    /// commits the ordered root, once per day. It MUST run during the active CE
    /// lifecycle (tribute enumeration requires `PHASE_ACTIVE`); the terminal
    /// request runs post-seal and only reads the committed root.
    ///
    /// Idempotent: a non-zero stored root means the snapshot already exists, so
    /// re-entry is a no-op and the frozen leagues stay stable across the blocks
    /// between READY enqueue and terminal-request consumption.
    pub(crate) fn build_fidelity_league_snapshot(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        wwd: WorldwideDay,
        timestamp: u64,
    ) -> Result<()> {
        if !self
            .ocomp_fidelity_league_snapshot_root
            .read(&wwd)?
            .is_zero()
        {
            return Ok(());
        }
        let tributes =
            TributeContract::new(self.storage.clone()).get_all_day_tributes(scope, parent, wwd)?;
        // One canonical Tribute per owner per day -> the owner set must be
        // unique; sorting also yields the canonical OCOMP subject order.
        let mut owners: Vec<Address> = tributes.iter().map(|t| t.owner).collect();
        owners.sort_unstable();
        if owners.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(crate::errors::storage_corruption(
                "OCOMP day owner set is not strictly ordered and unique".into(),
            ));
        }
        // Snapshot the whole day's leagues in ONE enclave round-trip (was one
        // per owner); results come back in `owners` (sorted) order.
        let entries =
            outbe_fidelity::api::snapshot_leagues(self.storage.clone(), timestamp, &owners)?;
        for (owner, league) in &entries {
            self.ocomp_fidelity_league_snapshot
                .write(&league_snapshot_key(wwd.value(), *owner), *league)?;
        }
        self.ocomp_fidelity_league_snapshot_root
            .write(&wwd, fidelity_league_snapshot_root(wwd.value(), &entries))?;
        Ok(())
    }
}
