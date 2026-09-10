use std::collections::BTreeSet;

use alloy_primitives::{Bytes, B256};
use alloy_sol_types::{sol, SolEvent};
use outbe_primitives::{
    addresses::{NOD_ADDRESS, TRIBUTE_ADDRESS},
    error::{PrecompileError, Result},
    storage::StorageHandle,
};

use crate::{
    api::{
        nod_bucket_payload, nod_item_payload, tribute_payload, BodyInput, EntityRef,
        ExecutionScope, IdPageRequest, ParentBodySource, QueryRef, VerifiedBody, VerifiedBodyPage,
        MAX_ID_PAGE_LIMIT,
    },
    body_commitment, decode_nod_bucket_v1, decode_nod_item_v1, decode_tribute_v1,
    encode_nod_bucket_v1, encode_nod_item_v1, encode_tribute_v1,
    schema::{Collection, DeltaStatus, IndexKind, IndexRecord, PendingWord},
    state::State,
    Commitment, NodBucketBodyV1, NodItemBodyV1, StoredBody, TributeBodyV1, WwdEntityId,
    ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1,
};

sol!(
    #![sol(alloy_sol_types = alloy_sol_types)]
    "../../../contracts/precompiles/src/ITribute.sol"
);
sol!(
    #![sol(alloy_sol_types = alloy_sol_types)]
    "../../../contracts/precompiles/src/INod.sol"
);

pub(crate) use INod::{NodBodyDeleted, NodBodyStored, NodBucketBodyDeleted, NodBucketBodyStored};
pub(crate) use ITribute::{TributeBodyDeleted, TributeBodyStored, TributePartitionRetired};

pub(crate) const READ_FIXED_GAS: u64 = 200;
pub(crate) const READ_GAS_PER_CANONICAL_BYTE: u64 = 8;
pub(crate) const INDEX_RECORD_SCAN_GAS: u64 = 300;
pub(crate) const PARENT_ID_GAS: u64 = 120;

struct PreparedBody {
    collection: Collection,
    entity_id: WwdEntityId,
    stored_body: StoredBody,
    commitment: Commitment,
    memberships: Vec<IndexRecord>,
}

impl PreparedBody {
    fn entity_ref(&self) -> EntityRef {
        match self.collection {
            Collection::Tribute => EntityRef::Tribute(self.entity_id),
            Collection::NodItem => EntityRef::NodItem(self.entity_id),
            Collection::NodBucket => EntityRef::NodBucket(self.entity_id),
        }
    }
}

pub(crate) fn read(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    entity: EntityRef,
) -> Result<Option<VerifiedBody>> {
    let (collection, entity_id) = entity_parts(entity);
    let state = State::new(storage.clone());
    let (_, pending, pending_body) = state.pending(collection, entity_id)?;
    match pending {
        PendingWord::Set(commitment) => {
            charge_body_read(&storage, scope, pending_body.len())?;
            let stored = StoredBody::decode(&pending_body)
                .map_err(|error| fatal(format!("invalid pending StoredBody: {error}")))?;
            verify_stored(entity, stored, commitment, BodyOrigin::Overlay).map(Some)
        }
        PendingWord::Deleted => Ok(None),
        PendingWord::Untouched => {
            let parent_root = state.root()?;
            let Some(commitment) = scope.read_parent_leaf_verified(entity, parent_root)? else {
                return Ok(None);
            };
            let stored = parent
                .get(entity)
                .map_err(PrecompileError::from)?
                .ok_or_else(|| {
                    PrecompileError::BodyReadCorruption(format!(
                        "committed body {entity_id} is missing from finalized parent"
                    ))
                })?;
            charge_body_read(&storage, scope, stored.encode().len())?;
            verify_stored(entity, stored, commitment, BodyOrigin::Parent)
                .map(Some)
                .map_err(|error| match error {
                    PrecompileError::BodyReadCorruption(message) => {
                        PrecompileError::BodyReadCorruption(format!(
                            "{message}; [CE_BODY_DIAGNOSTIC] evm_block={:?} evm_ce_root={parent_root} parent_root={:?} {} thread={:?}",
                            storage.block_number(),
                            scope.parent_root(),
                            scope.diagnostic_parent_binding(),
                            std::thread::current().id(),
                        ))
                    }
                    other => other,
                })
        }
    }
}

pub(crate) fn mint(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    new_body: BodyInput<'_>,
) -> Result<()> {
    scope.require_active()?;
    let prepared = prepare_input(new_body)?;
    let state = State::new(storage.clone());
    if current_commitment(scope, &state, prepared.collection, prepared.entity_id)?.is_some() {
        return Err(revert("compressed entity already exists"));
    }

    let locator = state.prepare_body_touch(scope, prepared.collection, prepared.entity_id)?;
    state.set_pending_prepared(locator, prepared.commitment, &prepared.stored_body.encode())?;
    for membership in &prepared.memberships {
        state.apply_index_add(scope, membership)?;
    }
    emit_stored(&storage, &prepared, None)
}

pub(crate) fn update(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    current: VerifiedBody,
    new_body: BodyInput<'_>,
) -> Result<()> {
    scope.require_active()?;
    let prepared = prepare_input(new_body)?;
    if current.entity != prepared.entity_ref() {
        return Err(revert(
            "compressed entity update collection or identity mismatch",
        ));
    }
    let state = State::new(storage.clone());
    require_capability_current(scope, &state, &current)?;

    let old_memberships = memberships_for_verified(&current)?;
    let old_set: BTreeSet<_> = old_memberships.into_iter().collect();
    let new_set: BTreeSet<_> = prepared.memberships.iter().cloned().collect();

    let locator = state.prepare_body_touch(scope, prepared.collection, prepared.entity_id)?;
    state.set_pending_prepared(locator, prepared.commitment, &prepared.stored_body.encode())?;
    for membership in old_set.difference(&new_set) {
        state.apply_index_remove(scope, membership)?;
    }
    for membership in new_set.difference(&old_set) {
        state.apply_index_add(scope, membership)?;
    }
    emit_stored(&storage, &prepared, Some(current.commitment))
}

pub(crate) fn delete(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    current: VerifiedBody,
) -> Result<()> {
    scope.require_active()?;
    let state = State::new(storage.clone());
    require_capability_current(scope, &state, &current)?;
    let (collection, entity_id) = entity_parts(current.entity);
    let memberships = memberships_for_verified(&current)?;

    let locator = state.prepare_body_touch(scope, collection, entity_id)?;
    state.set_deleted_prepared(locator)?;
    for membership in &memberships {
        state.apply_index_remove(scope, membership)?;
    }
    emit_deleted(&storage, current.entity, current.commitment)
}

pub(crate) fn list(
    storage: StorageHandle<'_>,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    query: QueryRef,
    request: IdPageRequest,
) -> Result<VerifiedBodyPage> {
    validate_page_request(query, request)?;
    let state = State::new(storage.clone());
    let mut added = BTreeSet::new();
    let mut removed = BTreeSet::new();

    for (record, status) in state.index_deltas()? {
        scope.deduct_explicit_gas(&storage, INDEX_RECORD_SCAN_GAS)?;
        if !record_matches_query(&record, query) {
            continue;
        }
        if request.after.is_some_and(|after| record.entity_id <= after) {
            continue;
        }
        match status {
            DeltaStatus::Added => {
                added.insert(record.entity_id);
            }
            DeltaStatus::Removed => {
                removed.insert(record.entity_id);
            }
            DeltaStatus::NoChangeTouched => {}
            DeltaStatus::NeverTouched => {
                return Err(fatal("zero index delta escaped state validation"));
            }
        }
    }

    let target =
        usize::try_from(request.limit).map_err(|_| revert("page limit is not representable"))?;
    let initial_after = request.after;
    let mut parent_cursor = request.after;
    let mut parent_seen = BTreeSet::new();
    let mut observed_removed = BTreeSet::new();
    let mut parent_exhausted: bool;

    loop {
        let page = parent
            .list(
                query,
                IdPageRequest {
                    after: parent_cursor,
                    limit: request.limit,
                },
            )
            .map_err(PrecompileError::from)?;
        validate_parent_page(query, parent_cursor, request.limit, &page)?;
        for id in &page.ids {
            scope.deduct_explicit_gas(&storage, PARENT_ID_GAS)?;
            if added.contains(id) {
                return Err(PrecompileError::BodyReadCorruption(format!(
                    "Added ID {id} already exists in finalized-parent index"
                )));
            }
            if !parent_seen.insert(*id) {
                return Err(PrecompileError::BodyReadCorruption(format!(
                    "duplicate finalized-parent ID {id}"
                )));
            }
            if removed.contains(id) {
                observed_removed.insert(*id);
            }
        }
        if let Some(last) = page.ids.last() {
            let skipped_removed = removed.iter().any(|removed_id| {
                initial_after.is_none_or(|after| *removed_id > after)
                    && *removed_id <= *last
                    && !observed_removed.contains(removed_id)
            });
            if skipped_removed {
                return Err(PrecompileError::BodyReadCorruption(
                    "Removed ID was skipped by the ordered finalized-parent index".into(),
                ));
            }
        }

        parent_exhausted = page.next_after.is_none();
        if !parent_exhausted {
            parent_cursor = page.next_after;
        }

        let candidates = merged_candidates(&parent_seen, &added, &removed);
        let has_lookahead = candidates.len() > target;
        let proof_reached = if has_lookahead {
            let lookahead = candidates[target];
            page.ids.last().is_some_and(|last| *last >= lookahead)
        } else {
            false
        };
        if parent_exhausted || proof_reached {
            break;
        }
    }

    if parent_exhausted {
        let relevant_removed: BTreeSet<_> = removed
            .iter()
            .copied()
            .filter(|id| initial_after.is_none_or(|after| *id > after))
            .collect();
        if observed_removed != relevant_removed {
            return Err(PrecompileError::BodyReadCorruption(
                "Removed ID is missing from finalized-parent index".into(),
            ));
        }
    }

    let candidates = merged_candidates(&parent_seen, &added, &removed);
    let has_more = candidates.len() > target || !parent_exhausted;
    let selected: Vec<_> = candidates.into_iter().take(target).collect();
    let next_after = if has_more {
        Some(*selected.last().ok_or_else(|| {
            fatal("parent continuation or merged lookahead produced an empty result page")
        })?)
    } else {
        None
    };
    let mut bodies = Vec::with_capacity(selected.len());
    for id in selected {
        let entity = entity_for_query(query, id);
        let body = read(storage.clone(), scope, parent, entity)?.ok_or_else(|| {
            PrecompileError::BodyReadCorruption(format!(
                "listed compressed entity {id} is canonically absent"
            ))
        })?;
        if !verified_matches_query(&body, query) {
            return Err(PrecompileError::BodyReadCorruption(format!(
                "listed compressed entity {id} violates query predicate"
            )));
        }
        bodies.push(body);
    }
    Ok(VerifiedBodyPage::new(bodies, next_after))
}

fn prepare_input(input: BodyInput<'_>) -> Result<PreparedBody> {
    match input {
        BodyInput::Tribute(body) => prepare_tribute(body.clone()),
        BodyInput::NodItem(body) => prepare_nod_item(body.clone()),
        BodyInput::NodBucket(body) => prepare_nod_bucket(body.clone()),
    }
}

fn prepare_tribute(body: TributeBodyV1) -> Result<PreparedBody> {
    let payload = encode_tribute_v1(&body).map_err(input_error)?;
    let stored_body = StoredBody::new_v1(payload.clone()).map_err(input_error)?;
    let entity_id = body.tribute_id;
    let commitment = calculate_commitment(entity_id, &payload)?;
    let memberships = vec![
        IndexRecord::owner(IndexKind::TributeByOwner, body.owner, entity_id),
        IndexRecord::day(body.worldwide_day, entity_id),
    ];
    Ok(PreparedBody {
        collection: Collection::Tribute,
        entity_id,
        stored_body,
        commitment,
        memberships,
    })
}

fn prepare_nod_item(body: NodItemBodyV1) -> Result<PreparedBody> {
    let payload = encode_nod_item_v1(&body).map_err(input_error)?;
    let stored_body = StoredBody::new_v1(payload.clone()).map_err(input_error)?;
    let entity_id = body.nod_id;
    let commitment = calculate_commitment(entity_id, &payload)?;
    let memberships = vec![
        IndexRecord::owner(IndexKind::NodByOwner, body.owner, entity_id),
        IndexRecord::nod_all(entity_id),
    ];
    Ok(PreparedBody {
        collection: Collection::NodItem,
        entity_id,
        stored_body,
        commitment,
        memberships,
    })
}

fn prepare_nod_bucket(body: NodBucketBodyV1) -> Result<PreparedBody> {
    let payload = encode_nod_bucket_v1(&body).map_err(input_error)?;
    let stored_body = StoredBody::new_v1(payload.clone()).map_err(input_error)?;
    let entity_id = body.entity_id();
    let commitment = calculate_commitment(entity_id, &payload)?;
    Ok(PreparedBody {
        collection: Collection::NodBucket,
        entity_id,
        stored_body,
        commitment,
        memberships: Vec::new(),
    })
}

fn verify_stored(
    entity: EntityRef,
    stored_body: StoredBody,
    expected: Commitment,
    origin: BodyOrigin,
) -> Result<VerifiedBody> {
    if stored_body.schema_version() != BODY_SCHEMA_V1 {
        return Err(origin.invalid(format!(
            "unsupported stored body schema {}",
            stored_body.schema_version()
        )));
    }
    let payload = stored_body.payload();
    let entity_id = entity.entity_id();
    let (decoded_id, verified_payload) = match entity {
        EntityRef::Tribute(_) => {
            let body =
                decode_tribute_v1(payload).map_err(|error| origin.invalid(error.to_string()))?;
            (body.tribute_id, tribute_payload(body))
        }
        EntityRef::NodItem(_) => {
            let body =
                decode_nod_item_v1(payload).map_err(|error| origin.invalid(error.to_string()))?;
            (body.nod_id, nod_item_payload(body))
        }
        EntityRef::NodBucket(_) => {
            let body =
                decode_nod_bucket_v1(payload).map_err(|error| origin.invalid(error.to_string()))?;
            (body.entity_id(), nod_bucket_payload(body))
        }
    };
    if decoded_id != entity_id {
        return Err(origin.invalid(format!(
            "body identity {decoded_id} does not match requested {entity_id}"
        )));
    }
    let actual = body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, entity_id, payload)
        .map_err(|error| origin.invalid(error.to_string()))?;
    if actual != expected {
        // Preserve the exact authenticated input, not a re-encoded replacement.
        // Bodies are canonical on-chain event payloads, never enclave key material.
        return Err(origin.invalid(format!(
            "body commitment mismatch for {entity_id}; [CE_BODY_DIAGNOSTIC] entity={entity:?} origin={origin:?} scheme={ACTIVE_COMMITMENT_SCHEME} schema={} expected=0x{} actual=0x{} payload_len={} payload_hex={} stored_body_hex={} decoded={verified_payload:?}",
            stored_body.schema_version(),
            hex::encode(expected.as_bytes()),
            hex::encode(actual.as_bytes()),
            payload.len(),
            hex::encode(payload),
            hex::encode(stored_body.encode()),
        )));
    }
    Ok(VerifiedBody {
        entity,
        commitment: expected,
        stored_body,
        payload: verified_payload,
    })
}

fn calculate_commitment(entity_id: WwdEntityId, payload: &[u8]) -> Result<Commitment> {
    body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, entity_id, payload)
        .map_err(|error| fatal(error.to_string()))
}

fn current_commitment(
    scope: &ExecutionScope,
    state: &State<'_>,
    collection: Collection,
    entity_id: WwdEntityId,
) -> Result<Option<Commitment>> {
    let (_, pending, body) = state.pending(collection, entity_id)?;
    match pending {
        PendingWord::Untouched => {
            scope.read_parent_leaf_verified(entity_from_parts(collection, entity_id), state.root()?)
        }
        PendingWord::Set(value) => {
            let stored = StoredBody::decode(&body)
                .map_err(|error| fatal(format!("invalid pending StoredBody: {error}")))?;
            verify_stored(
                entity_from_parts(collection, entity_id),
                stored,
                value,
                BodyOrigin::Overlay,
            )?;
            Ok(Some(value))
        }
        PendingWord::Deleted => Ok(None),
    }
}

fn require_capability_current(
    scope: &ExecutionScope,
    state: &State<'_>,
    current: &VerifiedBody,
) -> Result<()> {
    let (collection, entity_id) = entity_parts(current.entity);
    match current_commitment(scope, state, collection, entity_id)? {
        None => Err(revert("compressed entity is absent")),
        Some(actual) if actual != current.commitment => Err(revert(
            "verified body capability no longer matches current value",
        )),
        Some(_) => Ok(()),
    }
}

fn memberships_for_verified(body: &VerifiedBody) -> Result<Vec<IndexRecord>> {
    let id = body.entity_id();
    if let Some(tribute) = body.payload.as_tribute() {
        return Ok(vec![
            IndexRecord::owner(IndexKind::TributeByOwner, tribute.owner, id),
            IndexRecord::day(tribute.worldwide_day, id),
        ]);
    }
    if let Some(item) = body.payload.as_nod_item() {
        return Ok(vec![
            IndexRecord::owner(IndexKind::NodByOwner, item.owner, id),
            IndexRecord::nod_all(id),
        ]);
    }
    if body.payload.as_nod_bucket().is_some() {
        return Ok(Vec::new());
    }
    Err(fatal("verified payload has no typed variant"))
}

fn emit_stored(
    storage: &StorageHandle<'_>,
    body: &PreparedBody,
    previous: Option<Commitment>,
) -> Result<()> {
    let previous = commitment_b256(previous);
    let new_commitment = commitment_b256(Some(body.commitment));
    let canonical_payload = Bytes::copy_from_slice(body.stored_body.payload());
    let id = body.entity_id.to_u256();
    let event = match body.collection {
        Collection::Tribute => TributeBodyStored {
            tributeId: id,
            commitmentSchemeVersion: ACTIVE_COMMITMENT_SCHEME,
            schemaVersion: BODY_SCHEMA_V1,
            previousCommitment: previous,
            newCommitment: new_commitment,
            canonicalPayload: canonical_payload,
        }
        .encode_log_data(),
        Collection::NodItem => NodBodyStored {
            nodId: id,
            commitmentSchemeVersion: ACTIVE_COMMITMENT_SCHEME,
            schemaVersion: BODY_SCHEMA_V1,
            previousCommitment: previous,
            newCommitment: new_commitment,
            canonicalPayload: canonical_payload,
        }
        .encode_log_data(),
        Collection::NodBucket => NodBucketBodyStored {
            bucketId: id,
            commitmentSchemeVersion: ACTIVE_COMMITMENT_SCHEME,
            schemaVersion: BODY_SCHEMA_V1,
            previousCommitment: previous,
            newCommitment: new_commitment,
            canonicalPayload: canonical_payload,
        }
        .encode_log_data(),
    };
    let emitter = if body.collection == Collection::Tribute {
        TRIBUTE_ADDRESS
    } else {
        NOD_ADDRESS
    };
    storage.emit_event(emitter, event)
}

fn emit_deleted(
    storage: &StorageHandle<'_>,
    entity: EntityRef,
    previous: Commitment,
) -> Result<()> {
    let previous = commitment_b256(Some(previous));
    let id = entity.entity_id().to_u256();
    let (emitter, event) = match entity {
        EntityRef::Tribute(_) => (
            TRIBUTE_ADDRESS,
            TributeBodyDeleted {
                tributeId: id,
                previousCommitment: previous,
            }
            .encode_log_data(),
        ),
        EntityRef::NodItem(_) => (
            NOD_ADDRESS,
            NodBodyDeleted {
                nodId: id,
                previousCommitment: previous,
            }
            .encode_log_data(),
        ),
        EntityRef::NodBucket(_) => (
            NOD_ADDRESS,
            NodBucketBodyDeleted {
                bucketId: id,
                previousCommitment: previous,
            }
            .encode_log_data(),
        ),
    };
    storage.emit_event(emitter, event)
}

fn validate_page_request(query: QueryRef, request: IdPageRequest) -> Result<()> {
    if request.limit == 0 || request.limit > MAX_ID_PAGE_LIMIT {
        return Err(revert(format!(
            "page limit must be in 1..={MAX_ID_PAGE_LIMIT}"
        )));
    }
    if let (QueryRef::TributeByDay(day), Some(after)) = (query, request.after) {
        if after.worldwide_day() != day {
            return Err(revert("TributeByDay cursor has the wrong day prefix"));
        }
    }
    Ok(())
}

fn validate_parent_page(
    query: QueryRef,
    after: Option<WwdEntityId>,
    limit: u32,
    page: &crate::IdPage,
) -> Result<()> {
    if page.ids.len() > limit as usize {
        return Err(PrecompileError::BodyReadCorruption(
            "parent page exceeds requested limit".into(),
        ));
    }
    let mut previous = after;
    for id in &page.ids {
        if previous.is_some_and(|value| *id <= value) {
            return Err(PrecompileError::BodyReadCorruption(
                "parent IDs are not strictly ascending after the cursor".into(),
            ));
        }
        if let QueryRef::TributeByDay(day) = query {
            if id.worldwide_day() != day {
                return Err(PrecompileError::BodyReadCorruption(
                    "parent TributeByDay ID has the wrong day prefix".into(),
                ));
            }
        }
        previous = Some(*id);
    }
    match page.next_after {
        Some(next) if page.ids.last().copied() != Some(next) => {
            Err(PrecompileError::BodyReadCorruption(
                "parent next_after must equal its last returned ID".into(),
            ))
        }
        Some(_) if page.ids.is_empty() => Err(PrecompileError::BodyReadCorruption(
            "empty parent page cannot advertise a continuation".into(),
        )),
        _ => Ok(()),
    }
}

fn merged_candidates(
    parent: &BTreeSet<WwdEntityId>,
    added: &BTreeSet<WwdEntityId>,
    removed: &BTreeSet<WwdEntityId>,
) -> Vec<WwdEntityId> {
    parent
        .difference(removed)
        .copied()
        .chain(added.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn record_matches_query(record: &IndexRecord, query: QueryRef) -> bool {
    match query {
        QueryRef::TributeByOwner(owner) => {
            record.kind == IndexKind::TributeByOwner && record.partition == owner.as_slice()
        }
        QueryRef::TributeByDay(day) => {
            record.kind == IndexKind::TributeByDay && record.partition == day.value().to_be_bytes()
        }
        QueryRef::NodByOwner(owner) => {
            record.kind == IndexKind::NodByOwner && record.partition == owner.as_slice()
        }
        QueryRef::NodAll => record.kind == IndexKind::NodAll && record.partition.is_empty(),
    }
}

fn verified_matches_query(body: &VerifiedBody, query: QueryRef) -> bool {
    match query {
        QueryRef::TributeByOwner(owner) => body
            .payload()
            .as_tribute()
            .is_some_and(|tribute| tribute.owner == owner),
        QueryRef::TributeByDay(day) => body
            .payload()
            .as_tribute()
            .is_some_and(|tribute| tribute.worldwide_day == day),
        QueryRef::NodByOwner(owner) => body
            .payload()
            .as_nod_item()
            .is_some_and(|item| item.owner == owner),
        QueryRef::NodAll => body.payload().as_nod_item().is_some(),
    }
}

fn entity_for_query(query: QueryRef, id: WwdEntityId) -> EntityRef {
    match query {
        QueryRef::TributeByOwner(_) | QueryRef::TributeByDay(_) => EntityRef::Tribute(id),
        QueryRef::NodByOwner(_) | QueryRef::NodAll => EntityRef::NodItem(id),
    }
}

const fn entity_from_parts(collection: Collection, id: WwdEntityId) -> EntityRef {
    match collection {
        Collection::Tribute => EntityRef::Tribute(id),
        Collection::NodItem => EntityRef::NodItem(id),
        Collection::NodBucket => EntityRef::NodBucket(id),
    }
}

const fn entity_parts(entity: EntityRef) -> (Collection, WwdEntityId) {
    match entity {
        EntityRef::Tribute(id) => (Collection::Tribute, id),
        EntityRef::NodItem(id) => (Collection::NodItem, id),
        EntityRef::NodBucket(id) => (Collection::NodBucket, id),
    }
}

fn charge_body_read(
    storage: &StorageHandle<'_>,
    scope: &ExecutionScope,
    bytes: usize,
) -> Result<()> {
    let bytes = u64::try_from(bytes).map_err(|_| fatal("body length exceeds gas range"))?;
    scope.deduct_explicit_gas(
        storage,
        READ_FIXED_GAS.saturating_add(READ_GAS_PER_CANONICAL_BYTE.saturating_mul(bytes)),
    )
}

fn commitment_b256(value: Option<Commitment>) -> B256 {
    value.map_or(B256::ZERO, |commitment| B256::from(*commitment.as_bytes()))
}

fn input_error(error: impl core::fmt::Display) -> PrecompileError {
    revert(error.to_string())
}

#[derive(Clone, Copy, Debug)]
enum BodyOrigin {
    Overlay,
    Parent,
}

impl BodyOrigin {
    fn invalid(self, message: impl Into<String>) -> PrecompileError {
        match self {
            Self::Overlay => fatal(message),
            Self::Parent => PrecompileError::BodyReadCorruption(message.into()),
        }
    }
}

fn fatal(message: impl Into<String>) -> PrecompileError {
    PrecompileError::Fatal(message.into())
}

fn revert(message: impl Into<String>) -> PrecompileError {
    PrecompileError::Revert(message.into())
}
