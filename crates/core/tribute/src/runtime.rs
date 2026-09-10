use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{
    delete, mint, read, retire_partition, BodyInput, EntityRef, ExecutionScope, ParentBodySource,
    PartitionRef, RetirementOutcome, VerifiedBody, WwdEntityId,
};
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;

use crate::errors::TributeError;
use crate::precompile::ITribute;
use crate::schema::{TributeContract, TributeData};
use crate::state::tribute_from_verified;

/// A semantic Tribute paired with the exact generic mutation capability that verified it.
pub struct LoadedTribute {
    body: TributeData,
    current: VerifiedBody,
}

/// Constant-size owner receipt for a sealed Tribute generation forfeited by
/// Metadosis retained-cap policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributeForfeitureReceipt {
    pub worldwide_day: WorldwideDay,
    pub sealed_root: B256,
    pub forfeited_count: u32,
    pub forfeited_nominal: U256,
    pub source_generation: u64,
    pub retired_generation: u64,
    pub retirement_outcome: RetirementOutcome,
}

impl LoadedTribute {
    /// Converts an authenticated generic Tribute body into the domain capability.
    pub fn from_verified(current: VerifiedBody) -> Result<Self> {
        let body = tribute_from_verified(&current)?;
        Ok(Self { body, current })
    }

    #[must_use]
    pub const fn body(&self) -> &TributeData {
        &self.body
    }
}

impl TributeContract<'_> {
    /// Applies ADR-011's one bulk accounting transition after every verified
    /// Tribute in the sealed WWD has produced exactly one Nod.
    pub fn consume_lysis_partition(
        &mut self,
        day: WorldwideDay,
        verified_count: u32,
        verified_nominal: alloy_primitives::U256,
    ) -> Result<()> {
        if self.ocomp_profile_ready.read()? {
            return Err(outbe_primitives::error::PrecompileError::Revert(
                "populated OCOMP Tribute input requires certified retirement".into(),
            ));
        }
        self.consume_lysis_partition_inner(day, verified_count, verified_nominal)
    }

    pub(crate) fn consume_lysis_partition_inner(
        &mut self,
        day: WorldwideDay,
        verified_count: u32,
        verified_nominal: alloy_primitives::U256,
    ) -> Result<()> {
        let mut totals = self.get_day_totals(day)?;
        if !totals.initialized
            || !totals.is_sealed
            || totals.tribute_count != verified_count
            || totals.tribute_nominal_amount != verified_nominal
        {
            return Err(
                outbe_primitives::error::PrecompileError::BodyReadCorruption(
                    "Lysis input count/nominal does not match sealed Tribute DayTotals".into(),
                ),
            );
        }
        let supply = self
            .total_supply
            .read()?
            .checked_sub(u64::from(verified_count))
            .ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(
                    "Tribute total supply underflow during Lysis".into(),
                )
            })?;
        self.total_supply.write(supply)?;
        totals.tribute_count = 0;
        totals.tribute_nominal_amount = alloy_primitives::U256::ZERO;
        self.store_day_totals(&totals)
    }

    /// Requests the one authenticated Catalog retirement after the sealed
    /// DayTotals are empty. The legacy terminal path calls this after
    /// completion; certified activation calls the private inner transition
    /// inside the same outer checkpoint as terminal completion.
    pub fn retire_completed_partition(
        &mut self,
        scope: &ExecutionScope,
        day: WorldwideDay,
    ) -> Result<RetirementOutcome> {
        if self.ocomp_profile_ready.read()? {
            let admission = self.pre_admission_projection(day)?;
            if admission.is_sealed && admission.tribute_count != 0 {
                return Err(outbe_primitives::error::PrecompileError::Revert(
                    "populated OCOMP Tribute input requires certified retirement".into(),
                ));
            }
        }
        let storage = self.storage_handle();
        storage.with_checkpoint(|| self.retire_completed_partition_inner(scope, day))
    }

    /// Requests retirement for the one terminal policy where OFFERING was
    /// never opened. The day must still be sealed and exactly empty before any
    /// CE work is touched.
    pub fn retire_empty_missed_offering_partition(
        &mut self,
        scope: &ExecutionScope,
        day: WorldwideDay,
    ) -> Result<RetirementOutcome> {
        let ce_checkpoint = scope.ce_work_checkpoint()?;
        let storage = self.storage_handle();
        let result = storage.with_checkpoint(|| {
            let totals = self.get_day_totals(day)?;
            if !totals.initialized
                || !totals.is_sealed
                || totals.tribute_count != 0
                || !totals.tribute_nominal_amount.is_zero()
            {
                return Err(
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(
                        "MissedOffering requires a sealed empty Tribute partition".into(),
                    ),
                );
            }
            self.retire_completed_partition_inner(scope, day)
        });
        if result.is_err() {
            scope.restore_ce_work_checkpoint(ce_checkpoint)?;
        }
        result
    }

    /// Forfeits one complete sealed Tribute generation without enumerating
    /// individual bodies. The authenticated parent partition root and owner
    /// aggregates are bound before supply, retirement, or generation changes.
    pub fn forfeit_sealed_partition(
        &mut self,
        scope: &ExecutionScope,
        day: WorldwideDay,
    ) -> Result<TributeForfeitureReceipt> {
        let ce_checkpoint = scope.ce_work_checkpoint()?;
        let storage = self.storage_handle();
        let result = storage.with_checkpoint(|| {
            let mut totals = self.get_day_totals(day)?;
            if !self.ocomp_profile_ready.read()? || !totals.initialized || !totals.is_sealed {
                return Err(
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(
                        "CapacityForfeiture requires a fresh-profile sealed Tribute partition"
                            .into(),
                    ),
                );
            }

            let partition = PartitionRef::TributeWwd(day);
            let authenticated_root = scope.authenticated_partition_root(partition)?;
            if totals.tribute_count != 0 && authenticated_root.is_none() {
                return Err(
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(
                        "populated Tribute aggregate has no authenticated parent partition".into(),
                    ),
                );
            }
            let sealed_root = authenticated_root.unwrap_or(B256::ZERO);

            let mut admission = self
                .day_pre_admission
                .get(day)?
                .unwrap_or_else(|| crate::DayPreAdmission::with_key(day));
            if admission.source_generation != 0 {
                return Err(
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(
                        "CapacityForfeiture requires unretired Tribute generation zero".into(),
                    ),
                );
            }
            if admission.is_sealed {
                if admission.sealed_collection_root != sealed_root
                    || admission.sealed_tribute_count != totals.tribute_count
                    || admission.sealed_tribute_nominal_amount != totals.tribute_nominal_amount
                {
                    return Err(
                        outbe_primitives::error::PrecompileError::BodyReadCorruption(
                            "sealed Tribute pre-admission differs from authenticated aggregate"
                                .into(),
                        ),
                    );
                }
            } else {
                admission.initialized = true;
                admission.is_sealed = true;
                admission.sealed_collection_root = sealed_root;
                admission.sealed_tribute_count = totals.tribute_count;
                admission.sealed_tribute_nominal_amount = totals.tribute_nominal_amount;
            }

            let forfeited_count = totals.tribute_count;
            let forfeited_nominal = totals.tribute_nominal_amount;
            let supply = self
                .total_supply
                .read()?
                .checked_sub(u64::from(forfeited_count))
                .ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(
                        "Tribute total supply underflow during CapacityForfeiture".into(),
                    )
                })?;
            self.total_supply.write(supply)?;
            totals.tribute_count = 0;
            totals.tribute_nominal_amount = U256::ZERO;
            self.store_day_totals(&totals)?;

            let retirement_outcome = self.retire_completed_partition_inner(scope, day)?;
            let expected_retirement = if authenticated_root.is_some() {
                RetirementOutcome::Requested
            } else {
                RetirementOutcome::NotPresent
            };
            if retirement_outcome != expected_retirement {
                return Err(outbe_primitives::error::PrecompileError::Fatal(
                    "Tribute retirement outcome contradicts authenticated partition root".into(),
                ));
            }

            let source_generation = admission.source_generation;
            let retired_generation = source_generation.checked_add(1).ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(
                    "Tribute source generation overflow during CapacityForfeiture".into(),
                )
            })?;
            admission.source_generation = retired_generation;
            self.store_day_pre_admission(&admission)?;

            Ok(TributeForfeitureReceipt {
                worldwide_day: day,
                sealed_root,
                forfeited_count,
                forfeited_nominal,
                source_generation,
                retired_generation,
                retirement_outcome,
            })
        });
        if result.is_err() {
            scope.restore_ce_work_checkpoint(ce_checkpoint)?;
        }
        result
    }

    pub(crate) fn retire_completed_partition_inner(
        &mut self,
        scope: &ExecutionScope,
        day: WorldwideDay,
    ) -> Result<RetirementOutcome> {
        let outcome =
            retire_partition(self.storage_handle(), scope, PartitionRef::TributeWwd(day))?;
        if outcome == RetirementOutcome::NotPresent {
            return Ok(outcome);
        }

        let totals = self.get_day_totals(day)?;
        if !totals.initialized
            || !totals.is_sealed
            || totals.tribute_count != 0
            || !totals.tribute_nominal_amount.is_zero()
        {
            return Err(outbe_primitives::error::PrecompileError::Revert(
                "Tribute WWD is not completed and empty".into(),
            ));
        }
        self.emit(ITribute::TributePartitionRetired {
            worldwideDay: day.into(),
        })?;
        Ok(outcome)
    }

    pub fn get_tributes_by_owner(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        owner: Address,
    ) -> Result<Vec<TributeData>> {
        self.read_all_by_owner(scope, parent, owner)
    }

    pub fn get_all_day_tributes(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        day: WorldwideDay,
    ) -> Result<Vec<TributeData>> {
        self.read_all_by_day(scope, parent, day)
    }

    pub fn issue(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        tribute: &TributeData,
    ) -> Result<()> {
        let storage = self.storage_handle();
        storage.with_checkpoint(|| self.issue_inner(scope, parent, tribute))
    }

    fn issue_inner(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        tribute: &TributeData,
    ) -> Result<()> {
        self.validate_tribute_for_issue(tribute)?;
        self.ensure_day_accepts_tributes(tribute.worldwide_day)?;
        if self
            .get_tribute(scope, parent, tribute.tribute_id)?
            .is_some()
        {
            return Err(TributeError::TributeAlreadyExists.into());
        }

        self.bump_day_bucket(tribute.worldwide_day, 1, tribute.nominal_amount_minor)?;
        self.update_pre_admission_for_tribute(tribute, true)?;

        let supply = self.total_supply.read()?.checked_add(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(
                "Tribute total supply overflow during issuance".into(),
            )
        })?;
        self.total_supply.write(supply)?;

        let canonical = crate::repository::canonical_body(tribute);
        mint(self.storage_handle(), scope, BodyInput::Tribute(&canonical))?;
        self.emit(ITribute::TributeIssued {
            owner: tribute.owner,
            tributeId: tribute.tribute_id.to_u256(),
            worldwideDay: tribute.worldwide_day.into(),
            issuanceAmountMinor: tribute.issuance_amount_minor,
            settlementCurrency: tribute.issuance_currency,
            nominalAmountMinor: tribute.nominal_amount_minor,
        })?;

        Ok(())
    }

    pub fn burn(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        tribute_id: WwdEntityId,
    ) -> Result<()> {
        let loaded = self
            .load_tribute(scope, parent, tribute_id)?
            .ok_or(TributeError::TributeNotFound)?;
        self.burn_loaded(scope, loaded)
    }

    /// Loads one Tribute while retaining its verified generic mutation capability.
    pub fn load_tribute(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        tribute_id: WwdEntityId,
    ) -> Result<Option<LoadedTribute>> {
        read(
            self.storage_handle(),
            scope,
            parent,
            EntityRef::Tribute(tribute_id),
        )?
        .map(LoadedTribute::from_verified)
        .transpose()
    }

    /// Burns a previously loaded Tribute without repeating a parent-body read.
    pub fn burn_loaded(&mut self, scope: &ExecutionScope, loaded: LoadedTribute) -> Result<()> {
        let storage = self.storage_handle();
        storage.with_checkpoint(|| self.burn_loaded_inner(scope, loaded))
    }

    fn burn_loaded_inner(&mut self, scope: &ExecutionScope, loaded: LoadedTribute) -> Result<()> {
        let LoadedTribute { body, current } = loaded;
        let tribute = body;
        self.ensure_day_accepts_tributes(tribute.worldwide_day)?;
        self.bump_day_bucket(tribute.worldwide_day, -1, tribute.nominal_amount_minor)?;
        self.update_pre_admission_for_tribute(&tribute, false)?;

        let supply = self.total_supply.read()?.checked_sub(1).ok_or_else(|| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(
                "Tribute total supply underflow during burn".into(),
            )
        })?;
        self.total_supply.write(supply)?;

        delete(self.storage_handle(), scope, current)?;
        self.emit(ITribute::TributeBurned {
            tributeId: tribute.tribute_id.to_u256(),
            owner: tribute.owner,
            worldwideDay: tribute.worldwide_day.into(),
        })?;

        Ok(())
    }

    pub fn burn_all_by_wwd(
        &mut self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        day: WorldwideDay,
    ) -> Result<()> {
        let storage = self.storage_handle();
        storage.with_checkpoint(|| {
            let tribute_ids = self.get_tribute_ids_by_day(scope, parent, day)?;
            for tribute_id in tribute_ids {
                let current = read(
                    self.storage_handle(),
                    scope,
                    parent,
                    EntityRef::Tribute(tribute_id),
                )?
                .ok_or(TributeError::TributeNotFound)?;
                self.burn_loaded_inner(scope, LoadedTribute::from_verified(current)?)?;
            }
            Ok(())
        })
    }

    pub fn seal_day(&mut self, day: WorldwideDay) -> Result<()> {
        let mut totals = self.get_day_totals(day)?;
        totals.initialized = true;
        totals.is_sealed = true;
        self.store_day_totals(&totals)?;
        self.emit(ITribute::TributeWorldwideDaySealed {
            worldwideDay: day.into(),
            isSealed: true,
        })?;
        Ok(())
    }

    pub fn unseal_day(&mut self, day: WorldwideDay) -> Result<()> {
        if self.pre_admission_projection(day)?.is_sealed {
            return Err(TributeError::PreAdmissionSealed.into());
        }
        let mut totals = self.get_day_totals(day)?;
        totals.initialized = true;
        totals.is_sealed = false;
        self.store_day_totals(&totals)?;
        self.emit(ITribute::TributeWorldwideDaySealed {
            worldwideDay: day.into(),
            isSealed: false,
        })?;
        Ok(())
    }

    /// Freezes the bounded Tribute projection after the WWD and its CE
    /// collection have both been sealed. The root must come from the
    /// terminal CE lifecycle; callers cannot replace an already sealed value.
    pub fn seal_pre_admission(
        &mut self,
        day: WorldwideDay,
        sealed_collection: outbe_compressed_entities::SealedCollectionRoot,
    ) -> Result<crate::TributePreAdmissionProjection> {
        let storage = self.storage_handle();
        storage.with_checkpoint(|| {
            if !self.ocomp_profile_ready.read()? {
                return Err(TributeError::OcompProfileNotReady.into());
            }
            if sealed_collection.partition()
                != outbe_compressed_entities::PartitionRef::TributeWwd(day)
            {
                return Err(TributeError::InvalidSealedCollectionRoot.into());
            }
            let sealed_collection_root = sealed_collection.root();
            if sealed_collection_root.is_zero() {
                return Err(TributeError::InvalidSealedCollectionRoot.into());
            }
            let totals = self.get_day_totals(day)?;
            if !totals.initialized || !totals.is_sealed {
                return Err(TributeError::WorldwideDaySealed.into());
            }
            let mut admission = self
                .day_pre_admission
                .get(day)?
                .unwrap_or_else(|| crate::DayPreAdmission::with_key(day));
            if admission.is_sealed {
                return Err(TributeError::PreAdmissionSealed.into());
            }
            admission.initialized = true;
            admission.is_sealed = true;
            admission.sealed_collection_root = sealed_collection_root;
            admission.sealed_tribute_count = totals.tribute_count;
            admission.sealed_tribute_nominal_amount = totals.tribute_nominal_amount;
            self.store_day_pre_admission(&admission)?;
            self.pre_admission_projection(day)
        })
    }
}
