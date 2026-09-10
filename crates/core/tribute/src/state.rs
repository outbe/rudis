use alloy_primitives::{keccak256, Address, B256, U256};
use outbe_compressed_entities::{
    derive_poseidon_entity_id, list, read, EntityRef, ExecutionScope, IdPageRequest,
    ParentBodySource, QueryRef, VerifiedBody, WwdEntityId, MAX_ID_PAGE_LIMIT,
};
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;

use crate::errors::TributeError;
use crate::schema::{DayPreAdmission, DayTotals, TributeContract, TributeData};

/// Immutable read projection consumed by the OCOMP terminal request path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TributePreAdmissionProjection {
    pub worldwide_day: WorldwideDay,
    pub source_generation: u64,
    pub profile_ready: bool,
    pub is_sealed: bool,
    pub sealed_collection_root: B256,
    pub tribute_count: u32,
    pub tribute_nominal_amount: U256,
    pub canonical_body_bytes: u64,
    pub distinct_owner_count: u32,
    pub distinct_reference_currency_count: u16,
}

impl TributeContract<'_> {
    /// Initializes the OCOMP accumulator only on an empty fresh-devnet
    /// Tribute state. The genesis-bound OCOMP lifecycle owns the production
    /// call site.
    pub fn initialize_fresh_ocomp_profile(&mut self) -> Result<()> {
        let storage = self.storage_handle();
        storage.with_checkpoint(|| {
            if self.ocomp_profile_ready.read()? {
                return Ok(());
            }
            if self.total_supply.read()? != 0 {
                return Err(outbe_primitives::error::PrecompileError::Fatal(
                    "Tribute OCOMP profile requires empty live state".into(),
                ));
            }
            self.ocomp_profile_ready.write(true)
        })
    }

    pub fn total_supply(&self) -> Result<u64> {
        self.total_supply.read()
    }

    pub fn owner_of(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        tribute_id: WwdEntityId,
    ) -> Result<Address> {
        let tribute = self
            .get_tribute(scope, parent, tribute_id)?
            .ok_or(TributeError::TributeNotFound)?;
        Ok(tribute.owner)
    }

    pub fn balance_of(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        owner: Address,
    ) -> Result<u64> {
        let count = self.get_tribute_ids_by_owner(scope, parent, owner)?.len();
        let count: u64 = count
            .try_into()
            .map_err(|_| TributeError::OwnerBalanceOverflow)?;
        Ok(count)
    }

    pub fn token_uri(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        tribute_id: WwdEntityId,
    ) -> Result<String> {
        let tribute = self
            .get_tribute(scope, parent, tribute_id)?
            .ok_or(TributeError::TributeNotFound)?;
        Ok(format!(
            "data:application/json;utf8,{{\"name\":\"Tribute 0x{}\",\"description\":\"Rudis Tribute\",\"attributes\":[{{\"trait_type\":\"owner\",\"value\":\"{}\"}},{{\"trait_type\":\"worldwide_day\",\"value\":\"{}\"}},{{\"trait_type\":\"issuance_currency\",\"value\":\"{}\"}},{{\"trait_type\":\"issuance_amount_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"nominal_amount_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"reference_currency\",\"value\":\"{}\"}},{{\"trait_type\":\"exclude_from_intex_issuance\",\"value\":{}}}]}}",
            tribute.tribute_id,
            tribute.owner,
            tribute.worldwide_day,
            tribute.issuance_currency,
            tribute.issuance_amount_minor,
            tribute.nominal_amount_minor,
            tribute.reference_currency,
            tribute.exclude_from_intex_issuance,
        ))
    }

    pub fn get_tribute(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        tribute_id: WwdEntityId,
    ) -> Result<Option<TributeData>> {
        read(
            self.storage_handle(),
            scope,
            parent,
            EntityRef::Tribute(tribute_id),
        )?
        .map(|current| tribute_from_verified(&current))
        .transpose()
    }

    pub fn get_day_totals(&self, day: WorldwideDay) -> Result<DayTotals> {
        Ok(self
            .day_totals
            .get(day)?
            .unwrap_or_else(|| DayTotals::with_key(day)))
    }

    pub fn is_day_sealed(&self, day: WorldwideDay) -> Result<bool> {
        Ok(self
            .day_totals
            .get(day)?
            .map(|totals| totals.is_sealed)
            .unwrap_or(false))
    }

    pub fn pre_admission_projection(
        &self,
        day: WorldwideDay,
    ) -> Result<TributePreAdmissionProjection> {
        let totals = self.get_day_totals(day)?;
        let admission = self
            .day_pre_admission
            .get(day)?
            .unwrap_or_else(|| DayPreAdmission::with_key(day));
        let (tribute_count, tribute_nominal_amount) = if admission.is_sealed {
            (
                admission.sealed_tribute_count,
                admission.sealed_tribute_nominal_amount,
            )
        } else {
            (totals.tribute_count, totals.tribute_nominal_amount)
        };
        Ok(TributePreAdmissionProjection {
            worldwide_day: day,
            source_generation: admission.source_generation,
            profile_ready: self.ocomp_profile_ready.read()?,
            is_sealed: admission.is_sealed,
            sealed_collection_root: admission.sealed_collection_root,
            tribute_count,
            tribute_nominal_amount,
            canonical_body_bytes: admission.canonical_body_bytes,
            distinct_owner_count: admission.distinct_owner_count,
            distinct_reference_currency_count: admission.distinct_reference_currency_count,
        })
    }

    pub fn get_tribute_ids_by_owner(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        owner: Address,
    ) -> Result<Vec<WwdEntityId>> {
        Ok(self
            .read_all_by_owner(scope, parent, owner)?
            .into_iter()
            .map(|tribute| tribute.tribute_id)
            .collect())
    }

    pub fn get_tribute_ids_by_day(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        day: WorldwideDay,
    ) -> Result<Vec<WwdEntityId>> {
        Ok(self
            .read_all_by_day(scope, parent, day)?
            .into_iter()
            .map(|tribute| tribute.tribute_id)
            .collect())
    }

    pub(crate) fn validate_tribute_for_issue(&self, tribute: &TributeData) -> Result<()> {
        if tribute.owner.is_zero() {
            return Err(TributeError::InvalidOwner.into());
        }
        if tribute.issuance_amount_minor.is_zero() {
            return Err(TributeError::SettlementAmountMustBePositive.into());
        }
        let expected = derive_poseidon_entity_id(tribute.owner, tribute.worldwide_day)
            .map_err(|error| outbe_primitives::error::PrecompileError::Fatal(error.to_string()))?;
        if tribute.tribute_id != expected {
            return Err(outbe_primitives::error::PrecompileError::Fatal(format!(
                "Tribute canonical identity mismatch: expected {expected}, found {}",
                tribute.tribute_id
            )));
        }
        Ok(())
    }

    pub(crate) fn ensure_day_accepts_tributes(&self, day: WorldwideDay) -> Result<()> {
        let totals = self.get_day_totals(day)?;
        if !totals.initialized || totals.is_sealed {
            return Err(TributeError::WorldwideDaySealed.into());
        }
        Ok(())
    }

    pub(crate) fn store_day_totals(&mut self, totals: &DayTotals) -> Result<()> {
        if self.day_totals.exists(totals.worldwide_day)? {
            self.day_totals.update(totals)
        } else {
            self.day_totals.create(totals)
        }
    }

    pub(crate) fn store_day_pre_admission(&mut self, admission: &DayPreAdmission) -> Result<()> {
        if self.day_pre_admission.exists(admission.worldwide_day)? {
            self.day_pre_admission.update(admission)
        } else {
            self.day_pre_admission.create(admission)
        }
    }

    pub(crate) fn update_pre_admission_for_tribute(
        &mut self,
        tribute: &TributeData,
        is_add: bool,
    ) -> Result<()> {
        if !self.ocomp_profile_ready.read()? {
            return Ok(());
        }
        let day = tribute.worldwide_day;
        let mut admission = self
            .day_pre_admission
            .get(day)?
            .unwrap_or_else(|| DayPreAdmission::with_key(day));
        if admission.is_sealed {
            return Err(TributeError::PreAdmissionSealed.into());
        }

        let body_bytes = outbe_compressed_entities::encode_tribute_v1(
            &crate::repository::canonical_body(tribute),
        )
        .map_err(|error| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(error.to_string())
        })?
        .len();
        let body_bytes = u64::try_from(body_bytes).map_err(|_| {
            outbe_primitives::error::PrecompileError::BodyReadCorruption(
                "Tribute canonical body length exceeds u64".into(),
            )
        })?;
        let currency_key = reference_currency_refcount_key(day, tribute.reference_currency);
        let currency_refcount = self.day_reference_currency_refcount.read(&currency_key)?;

        let next_currency_refcount = if is_add {
            admission.canonical_body_bytes = admission
                .canonical_body_bytes
                .checked_add(body_bytes)
                .ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(
                        "Tribute canonical body byte total overflow".into(),
                    )
                })?;
            if currency_refcount == 0 {
                admission.distinct_reference_currency_count = admission
                    .distinct_reference_currency_count
                    .checked_add(1)
                    .ok_or_else(|| {
                        outbe_primitives::error::PrecompileError::BodyReadCorruption(
                            "Tribute distinct reference currency count overflow".into(),
                        )
                    })?;
            }
            currency_refcount.checked_add(1).ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(
                    "Tribute reference currency membership refcount overflow".into(),
                )
            })?
        } else {
            admission.canonical_body_bytes = admission
                .canonical_body_bytes
                .checked_sub(body_bytes)
                .ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(
                        "Tribute canonical body byte total underflow".into(),
                    )
                })?;
            let next_currency = currency_refcount.checked_sub(1).ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(
                    "Tribute reference currency membership refcount underflow".into(),
                )
            })?;
            if next_currency == 0 {
                admission.distinct_reference_currency_count = admission
                    .distinct_reference_currency_count
                    .checked_sub(1)
                    .ok_or_else(|| {
                        outbe_primitives::error::PrecompileError::BodyReadCorruption(
                            "Tribute distinct reference currency count underflow".into(),
                        )
                    })?;
            }
            next_currency
        };

        admission.initialized = true;
        admission.distinct_owner_count = self.get_day_totals(day)?.tribute_count;
        self.day_reference_currency_refcount
            .write(&currency_key, next_currency_refcount)?;
        self.store_day_pre_admission(&admission)
    }

    pub(crate) fn bump_day_bucket(
        &mut self,
        day: WorldwideDay,
        delta_count: i32,
        nominal_amount: U256,
    ) -> Result<()> {
        let mut totals = self.get_day_totals(day)?;
        totals.initialized = true;

        if delta_count >= 0 {
            totals.tribute_count = totals
                .tribute_count
                .checked_add(delta_count as u32)
                .ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Tribute day {day} count overflow"
                    ))
                })?;
            totals.tribute_nominal_amount = totals
                .tribute_nominal_amount
                .checked_add(nominal_amount)
                .ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Tribute day {day} nominal amount overflow"
                    ))
                })?;
        } else {
            let delta = (-delta_count) as u32;
            totals.tribute_count = totals.tribute_count.checked_sub(delta).ok_or_else(|| {
                outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                    "Tribute day {day} count underflow"
                ))
            })?;
            totals.tribute_nominal_amount = totals
                .tribute_nominal_amount
                .checked_sub(nominal_amount)
                .ok_or_else(|| {
                    outbe_primitives::error::PrecompileError::BodyReadCorruption(format!(
                        "Tribute day {day} nominal amount underflow"
                    ))
                })?;
        }

        self.store_day_totals(&totals)
    }

    pub(crate) fn read_all_by_owner(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        owner: Address,
    ) -> Result<Vec<TributeData>> {
        self.read_all(scope, parent, QueryRef::TributeByOwner(owner))
    }

    pub(crate) fn read_all_by_day(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        day: WorldwideDay,
    ) -> Result<Vec<TributeData>> {
        self.read_all(scope, parent, QueryRef::TributeByDay(day))
    }

    fn read_all(
        &self,
        scope: &ExecutionScope,
        parent: &impl ParentBodySource,
        query: QueryRef,
    ) -> Result<Vec<TributeData>> {
        let mut records = Vec::new();
        let mut after = None;
        loop {
            let page = list(
                self.storage_handle(),
                scope,
                parent,
                query,
                IdPageRequest {
                    after,
                    limit: MAX_ID_PAGE_LIMIT,
                },
            )?;
            let next_after = page.next_after();
            let bodies = page.into_bodies();
            records.extend(
                bodies
                    .iter()
                    .map(tribute_from_verified)
                    .collect::<Result<Vec<_>>>()?,
            );
            let Some(next) = next_after else {
                return Ok(records);
            };
            after = Some(next);
        }
    }
}

fn reference_currency_refcount_key(day: WorldwideDay, currency: u16) -> B256 {
    let mut preimage = [0_u8; 6];
    preimage[..4].copy_from_slice(&day.value().to_be_bytes());
    preimage[4..].copy_from_slice(&currency.to_be_bytes());
    keccak256(preimage)
}

pub(crate) fn tribute_from_verified(body: &VerifiedBody) -> Result<TributeData> {
    let payload = body.payload().as_tribute().ok_or_else(|| {
        outbe_primitives::error::PrecompileError::BodyReadCorruption(
            "compressed-entity read returned a non-Tribute payload".into(),
        )
    })?;
    Ok(crate::repository::from_canonical_body(payload.clone()))
}
