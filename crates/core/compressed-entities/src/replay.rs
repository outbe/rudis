//! Canonical ADR-007 body-event decoding for authenticated tree recovery.
//!
//! Recovery never trusts an event signature alone. Stored events are decoded
//! through the canonical body codec and their advertised leaf is recomputed;
//! event transitions are then checked against the exact parent SMT leaves.

use std::collections::{BTreeMap, BTreeSet};

use alloy_primitives::{Address, LogData, B256};
use alloy_sol_types::SolEvent;
use outbe_primitives::addresses::{NOD_ADDRESS, TRIBUTE_ADDRESS};
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

use crate::{
    body_commitment, decode_nod_bucket_v1, decode_nod_item_v1, decode_tribute_v1,
    runtime::{NodBodyDeleted, NodBodyStored, NodBucketBodyDeleted, NodBucketBodyStored},
    runtime::{TributeBodyDeleted, TributeBodyStored, TributePartitionRetired},
    Commitment, EntityRef, FinalLeafMutation, PartitionRef, WwdEntityId, ACTIVE_COMMITMENT_SCHEME,
    BODY_SCHEMA_V1,
};

/// One canonical receipt-visible body transition in execution order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalBodyEvent {
    pub entity: EntityRef,
    pub previous: Option<Commitment>,
    pub next: Option<Commitment>,
}

/// Decode and authenticate an ADR-011 Tribute partition-retirement event.
pub fn decode_partition_retirement(
    emitter: Address,
    data: &LogData,
) -> Result<Option<PartitionRef>, ReplayEventError> {
    let Some(signature) = data.topics().first().copied() else {
        return Ok(None);
    };
    if emitter != TRIBUTE_ADDRESS || signature != TributePartitionRetired::SIGNATURE_HASH {
        return Ok(None);
    }

    let event = TributePartitionRetired::decode_log_data(data)
        .map_err(|error| ReplayEventError::MalformedRetirement(error.to_string()))?;
    Ok(Some(PartitionRef::TributeWwd(WorldwideDay::new(
        event.worldwideDay,
    ))))
}

/// Decode and authenticate an ADR-007 body event.
///
/// Unrelated logs return `Ok(None)`. A log at a reserved emitter/signature pair
/// is either fully valid or an error; recovery never skips malformed evidence.
pub fn decode_canonical_body_event(
    emitter: Address,
    data: &LogData,
) -> Result<Option<CanonicalBodyEvent>, ReplayEventError> {
    let Some(signature) = data.topics().first().copied() else {
        return Ok(None);
    };

    if emitter == TRIBUTE_ADDRESS && signature == TributeBodyStored::SIGNATURE_HASH {
        let event = TributeBodyStored::decode_log_data(data)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        validate_versions(event.commitmentSchemeVersion, event.schemaVersion)?;
        let id = WwdEntityId::from(event.tributeId);
        let body = decode_tribute_v1(&event.canonicalPayload)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        if body.tribute_id != id {
            return Err(ReplayEventError::PayloadIdentityMismatch);
        }
        return stored_event(
            EntityRef::Tribute(id),
            event.previousCommitment,
            event.newCommitment,
            &event.canonicalPayload,
        )
        .map(Some);
    }
    if emitter == TRIBUTE_ADDRESS && signature == TributeBodyDeleted::SIGNATURE_HASH {
        let event = TributeBodyDeleted::decode_log_data(data)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        return deleted_event(
            EntityRef::Tribute(WwdEntityId::from(event.tributeId)),
            event.previousCommitment,
        )
        .map(Some);
    }
    if emitter == NOD_ADDRESS && signature == NodBodyStored::SIGNATURE_HASH {
        let event = NodBodyStored::decode_log_data(data)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        validate_versions(event.commitmentSchemeVersion, event.schemaVersion)?;
        let id = WwdEntityId::from(event.nodId);
        let body = decode_nod_item_v1(&event.canonicalPayload)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        if body.nod_id != id {
            return Err(ReplayEventError::PayloadIdentityMismatch);
        }
        return stored_event(
            EntityRef::NodItem(id),
            event.previousCommitment,
            event.newCommitment,
            &event.canonicalPayload,
        )
        .map(Some);
    }
    if emitter == NOD_ADDRESS && signature == NodBodyDeleted::SIGNATURE_HASH {
        let event = NodBodyDeleted::decode_log_data(data)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        return deleted_event(
            EntityRef::NodItem(WwdEntityId::from(event.nodId)),
            event.previousCommitment,
        )
        .map(Some);
    }
    if emitter == NOD_ADDRESS && signature == NodBucketBodyStored::SIGNATURE_HASH {
        let event = NodBucketBodyStored::decode_log_data(data)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        validate_versions(event.commitmentSchemeVersion, event.schemaVersion)?;
        let id = WwdEntityId::from(event.bucketId);
        let body = decode_nod_bucket_v1(&event.canonicalPayload)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        if body.entity_id() != id {
            return Err(ReplayEventError::PayloadIdentityMismatch);
        }
        return stored_event(
            EntityRef::NodBucket(id),
            event.previousCommitment,
            event.newCommitment,
            &event.canonicalPayload,
        )
        .map(Some);
    }
    if emitter == NOD_ADDRESS && signature == NodBucketBodyDeleted::SIGNATURE_HASH {
        let event = NodBucketBodyDeleted::decode_log_data(data)
            .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
        return deleted_event(
            EntityRef::NodBucket(WwdEntityId::from(event.bucketId)),
            event.previousCommitment,
        )
        .map(Some);
    }

    Ok(None)
}

/// Collapse receipt-order transitions into the final effective leaf set.
///
/// The first transition for every entity must extend the exact authenticated
/// parent leaf and every later transition must extend the preceding event.
/// Parent-equal net no-ops are intentionally omitted.
pub fn reconstruct_effective_final_mutations(
    events: &[CanonicalBodyEvent],
    parent_leaves: &BTreeMap<EntityRef, Option<Commitment>>,
) -> Result<Vec<FinalLeafMutation>, ReplayEventError> {
    let touched = events
        .iter()
        .map(|event| event.entity)
        .collect::<BTreeSet<_>>();
    if touched.len() != parent_leaves.len()
        || touched
            .iter()
            .any(|entity| !parent_leaves.contains_key(entity))
    {
        return Err(ReplayEventError::IncompleteParentLeafSet);
    }

    let mut current = parent_leaves.clone();
    for event in events {
        let actual = current
            .get(&event.entity)
            .copied()
            .ok_or(ReplayEventError::IncompleteParentLeafSet)?;
        if actual != event.previous {
            return Err(ReplayEventError::TransitionMismatch {
                entity: event.entity,
                expected: actual.map(|value| B256::from(*value.as_bytes())),
                actual: event.previous.map(|value| B256::from(*value.as_bytes())),
            });
        }
        current.insert(event.entity, event.next);
    }

    Ok(current
        .into_iter()
        .filter_map(|(entity, final_leaf)| {
            (parent_leaves.get(&entity).copied() != Some(final_leaf))
                .then_some(FinalLeafMutation { entity, final_leaf })
        })
        .collect())
}

fn stored_event(
    entity: EntityRef,
    previous: B256,
    advertised: B256,
    payload: &[u8],
) -> Result<CanonicalBodyEvent, ReplayEventError> {
    let expected = body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        BODY_SCHEMA_V1,
        entity.entity_id(),
        payload,
    )
    .map_err(|error| ReplayEventError::Malformed(error.to_string()))?;
    if advertised != B256::from(*expected.as_bytes()) {
        return Err(ReplayEventError::CommitmentMismatch);
    }
    Ok(CanonicalBodyEvent {
        entity,
        previous: optional_commitment(previous)?,
        next: Some(expected),
    })
}

fn deleted_event(
    entity: EntityRef,
    previous: B256,
) -> Result<CanonicalBodyEvent, ReplayEventError> {
    Ok(CanonicalBodyEvent {
        entity,
        previous: Some(required_commitment(previous)?),
        next: None,
    })
}

fn validate_versions(scheme: u32, schema: u32) -> Result<(), ReplayEventError> {
    if scheme != ACTIVE_COMMITMENT_SCHEME {
        return Err(ReplayEventError::UnsupportedCommitmentScheme(scheme));
    }
    if schema != BODY_SCHEMA_V1 {
        return Err(ReplayEventError::UnsupportedBodySchema(schema));
    }
    Ok(())
}

fn optional_commitment(value: B256) -> Result<Option<Commitment>, ReplayEventError> {
    if value.is_zero() {
        Ok(None)
    } else {
        required_commitment(value).map(Some)
    }
}

fn required_commitment(value: B256) -> Result<Commitment, ReplayEventError> {
    Commitment::try_from(value.0).map_err(|error| ReplayEventError::Malformed(error.to_string()))
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReplayEventError {
    #[error("malformed canonical compressed-entity body event: {0}")]
    Malformed(String),
    #[error("malformed canonical partition-retirement event: {0}")]
    MalformedRetirement(String),
    #[error("unsupported body-event commitment scheme {0}")]
    UnsupportedCommitmentScheme(u32),
    #[error("unsupported body-event schema {0}")]
    UnsupportedBodySchema(u32),
    #[error("body-event identity differs from its canonical payload")]
    PayloadIdentityMismatch,
    #[error("body-event commitment differs from its canonical payload")]
    CommitmentMismatch,
    #[error("parent leaf set is not exactly the event-touched entity set")]
    IncompleteParentLeafSet,
    #[error(
        "body-event transition for {entity:?} expected previous {expected:?}, found {actual:?}"
    )]
    TransitionMismatch {
        entity: EntityRef,
        expected: Option<B256>,
        actual: Option<B256>,
    },
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{address, Bytes, U256};
    use outbe_primitives::time::WorldwideDay;

    use super::*;
    use crate::{encode_tribute_v1, TributeBodyV1};

    fn entity(byte: u8) -> WwdEntityId {
        WwdEntityId::from_day_and_digest(WorldwideDay::new(17), [byte; 32])
    }

    fn commitment(byte: u8) -> Commitment {
        Commitment::try_from([byte; 32]).unwrap()
    }

    #[test]
    fn retirement_requires_the_exact_tribute_emitter_and_signature() {
        let day = WorldwideDay::new(20_260_717);
        let data = TributePartitionRetired {
            worldwideDay: day.value(),
        }
        .encode_log_data();

        assert_eq!(
            decode_partition_retirement(TRIBUTE_ADDRESS, &data).unwrap(),
            Some(PartitionRef::TributeWwd(day))
        );
        assert_eq!(
            decode_partition_retirement(NOD_ADDRESS, &data).unwrap(),
            None
        );
        assert_eq!(
            decode_partition_retirement(
                TRIBUTE_ADDRESS,
                &LogData::new_unchecked(vec![], Bytes::new())
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn stored_receipt_event_is_recomputed_before_becoming_a_leaf_mutation() {
        let id = entity(3);
        let body = TributeBodyV1 {
            tribute_id: id,
            owner: address!("3000000000000000000000000000000000000003"),
            worldwide_day: id.worldwide_day(),
            issuance_amount_minor: U256::from(10),
            issuance_currency: 840,
            nominal_amount_minor: U256::from(20),
            reference_currency: 978,
            tribute_price_minor: U256::from(30),
            exclude_from_intex_issuance: false,
        };
        let payload = encode_tribute_v1(&body).unwrap();
        let expected =
            body_commitment(ACTIVE_COMMITMENT_SCHEME, BODY_SCHEMA_V1, id, &payload).unwrap();
        let data = TributeBodyStored {
            tributeId: id.to_u256(),
            commitmentSchemeVersion: ACTIVE_COMMITMENT_SCHEME,
            schemaVersion: BODY_SCHEMA_V1,
            previousCommitment: B256::ZERO,
            newCommitment: B256::from(*expected.as_bytes()),
            canonicalPayload: payload.into(),
        }
        .encode_log_data();

        assert_eq!(
            decode_canonical_body_event(TRIBUTE_ADDRESS, &data).unwrap(),
            Some(CanonicalBodyEvent {
                entity: EntityRef::Tribute(id),
                previous: None,
                next: Some(expected),
            })
        );

        let mut tampered = TributeBodyStored::decode_log_data(&data).unwrap();
        tampered.newCommitment = B256::from([7_u8; 32]);
        assert_eq!(
            decode_canonical_body_event(TRIBUTE_ADDRESS, &tampered.encode_log_data()),
            Err(ReplayEventError::CommitmentMismatch)
        );
    }

    #[test]
    fn ordered_transitions_collapse_to_effective_final_leaves_and_reject_wrong_parent() {
        let created_then_deleted = EntityRef::Tribute(entity(4));
        let updated = EntityRef::NodItem(entity(5));
        let old = commitment(1);
        let middle = commitment(2);
        let new = commitment(3);
        let events = vec![
            CanonicalBodyEvent {
                entity: created_then_deleted,
                previous: None,
                next: Some(middle),
            },
            CanonicalBodyEvent {
                entity: updated,
                previous: Some(old),
                next: Some(middle),
            },
            CanonicalBodyEvent {
                entity: created_then_deleted,
                previous: Some(middle),
                next: None,
            },
            CanonicalBodyEvent {
                entity: updated,
                previous: Some(middle),
                next: Some(new),
            },
        ];
        let parent = BTreeMap::from([(created_then_deleted, None), (updated, Some(old))]);

        assert_eq!(
            reconstruct_effective_final_mutations(&events, &parent).unwrap(),
            vec![FinalLeafMutation {
                entity: updated,
                final_leaf: Some(new),
            }]
        );

        let wrong_parent =
            BTreeMap::from([(created_then_deleted, None), (updated, Some(commitment(4)))]);
        assert!(matches!(
            reconstruct_effective_final_mutations(&events, &wrong_parent),
            Err(ReplayEventError::TransitionMismatch { entity, .. }) if entity == updated
        ));
    }
}
