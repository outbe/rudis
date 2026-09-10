use alloy_primitives::{Bytes, B256};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use outbe_poseidon::{Poseidon, PoseidonHasher};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    body_commitment, collection_key, collection_root,
    commitment::{field_to_be32, TAG_TOP_NODE},
    protobuf::{decode_stored_nod_bucket_v1, decode_stored_nod_item_v1, decode_stored_tribute_v1},
    schema::Collection,
    sharding::{aggregate_b256_shard_roots, shard_index},
    smt::{derive_tree_key, PoseidonSmt, TreeKey, TreeLeaf, TreeProof, TreeRoot},
    staging::{AuthenticatedCatalogView, StagingCkbStore},
    CeDomain, CompressedTreeService, ExactParentIdentity, FinalizedMarker, StoredBody,
    TreeNamespace, WwdEntityId, ACTIVE_COMMITMENT_SCHEME,
};

pub const PROOF_ENCODING_VERSION_V1: u32 = 1;
const MAX_COMPILED_PROOF_BYTES: usize = 64 * 1024;
const MAX_CANONICAL_BODY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PointReadRequestV1 {
    pub domain_id: u16,
    #[serde(with = "entity_id_hex")]
    pub raw_id: WwdEntityId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PointProofCommonV1 {
    pub proof_encoding_version: u32,
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub domain_id: u16,
    #[serde(with = "entity_id_hex")]
    pub raw_id: WwdEntityId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CkbCompiledProofV1(Bytes);

impl CkbCompiledProofV1 {
    fn from_tree(proof: &TreeProof) -> Result<Self, PointReadServiceError> {
        Self::new(proof.as_bytes().to_vec())
    }

    pub fn new(bytes: Vec<u8>) -> Result<Self, PointReadServiceError> {
        if bytes.is_empty() || bytes.len() > MAX_COMPILED_PROOF_BYTES {
            return Err(PointReadServiceError::MalformedProofLength {
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.into()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    fn tree_proof(&self) -> Result<TreeProof, PointReadServiceError> {
        if self.0.is_empty() || self.0.len() > MAX_COMPILED_PROOF_BYTES {
            return Err(PointReadServiceError::MalformedProofLength {
                actual: self.0.len(),
            });
        }
        Ok(TreeProof::from_bytes(self.0.to_vec()))
    }
}

impl Serialize for CkbCompiledProofV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(self.as_bytes())))
    }
}

impl<'de> Deserialize<'de> for CkbCompiledProofV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        let encoded = String::deserialize(deserializer)?;
        let encoded = encoded
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("compiled proof must have a 0x prefix"))?;
        if encoded.len() > MAX_COMPILED_PROOF_BYTES * 2 {
            return Err(D::Error::custom("compiled proof exceeds v1 bound"));
        }
        let bytes = hex::decode(encoded).map_err(D::Error::custom)?;
        Self::new(bytes).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PresentEvidenceV1 {
    pub shard_smt_proof: CkbCompiledProofV1,
    pub shard_top_siblings: [B256; 4],
    pub root_catalog_proof: CkbCompiledProofV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsentEvidenceV1 {
    CollectionAbsent {
        root_catalog_proof: CkbCompiledProofV1,
    },
    EntityAbsentInCollection {
        shard_smt_proof: CkbCompiledProofV1,
        shard_top_siblings: [B256; 4],
        root_catalog_proof: CkbCompiledProofV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointReadResultV1 {
    Present {
        common: PointProofCommonV1,
        #[serde(with = "body_bytes_hex")]
        body_bytes: Bytes,
        evidence: PresentEvidenceV1,
    },
    Absent {
        common: PointProofCommonV1,
        evidence: AbsentEvidenceV1,
    },
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedHeaderV1 {
    pub block_number: u64,
    pub block_hash: B256,
    pub extra_data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifiedPointReadV1 {
    Present,
    Absent,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PointReadRequestError {
    #[error("unknown compressed-entity domain ID {0}")]
    UnknownDomain(u16),
}

#[derive(Debug, Error)]
pub enum PointReadServiceError {
    #[error("compressed-entity proof service is not ready at genesis")]
    GenesisUnavailable,
    #[error("compressed-entity proof materialization is inconsistent: {0}")]
    Materialization(String),
    #[error("compiled proof length {actual} is outside v1 bounds")]
    MalformedProofLength { actual: usize },
    #[error("point proof package is invalid: {0}")]
    InvalidPackage(&'static str),
}

#[derive(Clone, Debug)]
struct FrozenPointReadV1 {
    marker: FinalizedMarker,
    result: FrozenResultV1,
}

#[derive(Clone, Debug)]
enum FrozenResultV1 {
    Present {
        common: PointProofCommonV1,
        expected_leaf: B256,
        evidence: PresentEvidenceV1,
    },
    Absent {
        common: PointProofCommonV1,
        evidence: AbsentEvidenceV1,
    },
}

impl CompressedTreeService {
    /// Freezes tree evidence first; both callbacks run only after the sole MDBX
    /// read transaction has been dropped.
    pub fn serve_point_read_v1<H, B>(
        &self,
        chain_id: u64,
        request: PointReadRequestV1,
        header_lookup: H,
        body_lookup: B,
    ) -> Result<PointReadResultV1, PointReadRequestError>
    where
        H: FnOnce(u64, B256) -> Option<SelectedHeaderV1>,
        B: FnOnce(CeDomain, WwdEntityId) -> Option<Vec<u8>>,
    {
        let domain = domain(request.domain_id)?;
        let frozen = match self.freeze_point_read(chain_id, request, domain) {
            Ok(frozen) => frozen,
            Err(_) => return Ok(PointReadResultV1::Unavailable),
        };
        let Some(header) = header_lookup(frozen.marker.height, frozen.marker.block_hash) else {
            return Ok(PointReadResultV1::Unavailable);
        };
        if validate_header(&frozen.marker, &header).is_err() {
            return Ok(PointReadResultV1::Unavailable);
        }
        match frozen.result {
            FrozenResultV1::Absent { common, evidence } => {
                Ok(PointReadResultV1::Absent { common, evidence })
            }
            FrozenResultV1::Present {
                common,
                expected_leaf,
                evidence,
            } => {
                let Some(body_bytes) = body_lookup(domain, request.raw_id) else {
                    return Ok(PointReadResultV1::Unavailable);
                };
                match canonical_body_leaf(domain, request.raw_id, &body_bytes) {
                    Ok(actual) if actual == expected_leaf => Ok(PointReadResultV1::Present {
                        common,
                        body_bytes: body_bytes.into(),
                        evidence,
                    }),
                    _ => Ok(PointReadResultV1::Unavailable),
                }
            }
        }
    }

    fn freeze_point_read(
        &self,
        chain_id: u64,
        request: PointReadRequestV1,
        domain: CeDomain,
    ) -> Result<FrozenPointReadV1, PointReadServiceError> {
        let snapshot = self
            .open_finalized_snapshot()
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let marker = snapshot
            .marker()
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        if marker.height == 0 {
            return Err(PointReadServiceError::GenesisUnavailable);
        }
        let view = AuthenticatedCatalogView::open(
            snapshot,
            ExactParentIdentity {
                commitment_scheme_version: marker.commitment_scheme_version,
                block_number: marker.height,
                block_hash: marker.block_hash,
                root: marker.new_root,
            },
        )
        .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let common = PointProofCommonV1 {
            proof_encoding_version: PROOF_ENCODING_VERSION_V1,
            chain_id,
            block_number: marker.height,
            block_hash: marker.block_hash,
            domain_id: request.domain_id,
            raw_id: request.raw_id,
        };
        let collection = collection_key(domain, request.raw_id)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let catalog_key = TreeKey::from_be_bytes(*collection.as_bytes())
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let catalog_root = TreeRoot::from_be_bytes(view.catalog_root().0)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let catalog = PoseidonSmt::open_with_store(
            catalog_root,
            StagingCkbStore::new(view.clone(), TreeNamespace::Catalog, view.catalog_root()),
        );
        let catalog_leaf = catalog
            .get(catalog_key)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let catalog_proof = catalog
            .prove(vec![catalog_key])
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        catalog
            .verify(
                catalog_root,
                &catalog_proof,
                vec![(catalog_key, catalog_leaf)],
            )
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let root_catalog_proof = CkbCompiledProofV1::from_tree(&catalog_proof)?;
        if catalog_leaf == TreeLeaf::ZERO {
            if view
                .collection_has_records(collection)
                .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?
            {
                return Err(PointReadServiceError::Materialization(
                    "orphan records behind absent catalog leaf".into(),
                ));
            }
            return Ok(FrozenPointReadV1 {
                marker,
                result: FrozenResultV1::Absent {
                    common,
                    evidence: AbsentEvidenceV1::CollectionAbsent { root_catalog_proof },
                },
            });
        }
        let count = view
            .collection_root_count(collection)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        if count != domain.shard_count() as usize {
            return Err(PointReadServiceError::Materialization(
                "incomplete collection shard-root vector".into(),
            ));
        }
        let mut roots = Vec::with_capacity(count);
        for shard in 0..domain.shard_count() {
            roots.push(
                view.tree_root(TreeNamespace::CollectionShard(collection, shard))
                    .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?
                    .ok_or_else(|| {
                        PointReadServiceError::Materialization("missing shard root".into())
                    })?,
            );
        }
        let top = aggregate_b256_shard_roots(&roots)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let expected_collection = collection_root(domain, collection, top)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        if expected_collection != B256::from(catalog_leaf.as_bytes()) {
            return Err(PointReadServiceError::Materialization(
                "catalog leaf does not match shard roots".into(),
            ));
        }
        let tree_key = derive_tree_key(collection_for_domain(domain), request.raw_id)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let selected = shard_index(tree_key, domain.shard_count())
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let namespace = TreeNamespace::CollectionShard(collection, selected);
        let shard_root = TreeRoot::from_be_bytes(roots[selected as usize].0)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let shard = PoseidonSmt::open_with_store(
            shard_root,
            StagingCkbStore::new(view.clone(), namespace, roots[selected as usize]),
        );
        let leaf = shard
            .get(tree_key)
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let proof = shard
            .prove(vec![tree_key])
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        shard
            .verify(shard_root, &proof, vec![(tree_key, leaf)])
            .map_err(|e| PointReadServiceError::Materialization(e.to_string()))?;
        let evidence = PresentEvidenceV1 {
            shard_smt_proof: CkbCompiledProofV1::from_tree(&proof)?,
            shard_top_siblings: top_siblings(&roots, selected)?,
            root_catalog_proof,
        };
        let result = if leaf == TreeLeaf::ZERO {
            FrozenResultV1::Absent {
                common,
                evidence: AbsentEvidenceV1::EntityAbsentInCollection {
                    shard_smt_proof: evidence.shard_smt_proof,
                    shard_top_siblings: evidence.shard_top_siblings,
                    root_catalog_proof: evidence.root_catalog_proof,
                },
            }
        } else {
            FrozenResultV1::Present {
                common,
                expected_leaf: B256::from(leaf.as_bytes()),
                evidence,
            }
        };
        Ok(FrozenPointReadV1 { marker, result })
    }
}

pub fn verify_point_read_v1(
    expected_chain_id: u64,
    expected_request: PointReadRequestV1,
    selected_header: &SelectedHeaderV1,
    result: &PointReadResultV1,
) -> Result<VerifiedPointReadV1, PointReadServiceError> {
    let domain = domain(expected_request.domain_id)
        .map_err(|_| PointReadServiceError::InvalidPackage("unknown domain"))?;
    let common = match result {
        PointReadResultV1::Unavailable => {
            return Err(PointReadServiceError::InvalidPackage(
                "unavailable is not a proof package",
            ))
        }
        PointReadResultV1::Present { common, .. } | PointReadResultV1::Absent { common, .. } => {
            common
        }
    };
    validate_common(expected_chain_id, expected_request, selected_header, common)?;
    let (expected_leaf, verdict) = match result {
        PointReadResultV1::Unavailable => unreachable!(),
        PointReadResultV1::Present { body_bytes, .. } => {
            if body_bytes.is_empty() {
                return Err(PointReadServiceError::InvalidPackage("empty present body"));
            }
            (
                canonical_body_leaf(domain, expected_request.raw_id, body_bytes.as_ref())?,
                VerifiedPointReadV1::Present,
            )
        }
        PointReadResultV1::Absent { .. } => (B256::ZERO, VerifiedPointReadV1::Absent),
    };
    let artifact = header_artifact(selected_header)?;
    let collection = collection_key(domain, expected_request.raw_id)
        .map_err(|_| PointReadServiceError::InvalidPackage("collection derivation"))?;
    let catalog_key = TreeKey::from_be_bytes(*collection.as_bytes())
        .map_err(|_| PointReadServiceError::InvalidPackage("catalog key"))?;
    let (computed_collection, catalog_proof) = match result {
        PointReadResultV1::Present { evidence, .. } => (
            verify_collection(
                domain,
                expected_request.raw_id,
                collection,
                expected_leaf,
                evidence,
            )?,
            &evidence.root_catalog_proof,
        ),
        PointReadResultV1::Absent { evidence, .. } => match evidence {
            AbsentEvidenceV1::CollectionAbsent { root_catalog_proof } => {
                (B256::ZERO, root_catalog_proof)
            }
            AbsentEvidenceV1::EntityAbsentInCollection {
                shard_smt_proof,
                shard_top_siblings,
                root_catalog_proof,
            } => {
                let e = PresentEvidenceV1 {
                    shard_smt_proof: shard_smt_proof.clone(),
                    shard_top_siblings: *shard_top_siblings,
                    root_catalog_proof: root_catalog_proof.clone(),
                };
                (
                    verify_collection(domain, expected_request.raw_id, collection, B256::ZERO, &e)?,
                    root_catalog_proof,
                )
            }
        },
        PointReadResultV1::Unavailable => unreachable!(),
    };
    let catalog_root = catalog_proof
        .tree_proof()?
        .compute_root(
            catalog_key,
            TreeLeaf::from_be_bytes(computed_collection.0)
                .map_err(|_| PointReadServiceError::InvalidPackage("catalog leaf"))?,
        )
        .map_err(|_| PointReadServiceError::InvalidPackage("catalog proof"))?;
    let sealed = crate::sealed_root(B256::from(catalog_root.as_bytes()))
        .map_err(|_| PointReadServiceError::InvalidPackage("sealed root"))?;
    if sealed != artifact.r_sealed {
        return Err(PointReadServiceError::InvalidPackage(
            "header root mismatch",
        ));
    }
    Ok(verdict)
}

fn verify_collection(
    domain: CeDomain,
    raw_id: WwdEntityId,
    collection: crate::CollectionKey,
    leaf: B256,
    evidence: &PresentEvidenceV1,
) -> Result<B256, PointReadServiceError> {
    let key = derive_tree_key(collection_for_domain(domain), raw_id)
        .map_err(|_| PointReadServiceError::InvalidPackage("tree key"))?;
    let shard = shard_index(key, domain.shard_count())
        .map_err(|_| PointReadServiceError::InvalidPackage("shard index"))?;
    if evidence.shard_top_siblings.len() != domain.shard_count().trailing_zeros() as usize {
        return Err(PointReadServiceError::InvalidPackage("top sibling count"));
    }
    let mut current = evidence
        .shard_smt_proof
        .tree_proof()?
        .compute_root(
            key,
            TreeLeaf::from_be_bytes(leaf.0)
                .map_err(|_| PointReadServiceError::InvalidPackage("leaf field"))?,
        )
        .map_err(|_| PointReadServiceError::InvalidPackage("shard proof"))?
        .as_bytes();
    for (level, sibling) in evidence.shard_top_siblings.iter().enumerate() {
        TreeRoot::from_be_bytes(sibling.0)
            .map_err(|_| PointReadServiceError::InvalidPackage("non-canonical top sibling"))?;
        current = top_hash(level as u32, shard, current, sibling.0)?;
        TreeRoot::from_be_bytes(current)
            .map_err(|_| PointReadServiceError::InvalidPackage("invalid top root"))?;
    }
    collection_root(domain, collection, B256::from(current))
        .map_err(|_| PointReadServiceError::InvalidPackage("collection root"))
}

fn validate_common(
    chain_id: u64,
    request: PointReadRequestV1,
    header: &SelectedHeaderV1,
    common: &PointProofCommonV1,
) -> Result<(), PointReadServiceError> {
    if common.proof_encoding_version != PROOF_ENCODING_VERSION_V1
        || common.chain_id != chain_id
        || common.domain_id != request.domain_id
        || common.raw_id != request.raw_id
        || common.block_number == 0
        || common.block_number != header.block_number
        || common.block_hash != header.block_hash
    {
        return Err(PointReadServiceError::InvalidPackage("common binding"));
    }
    Ok(())
}

fn validate_header(
    marker: &FinalizedMarker,
    header: &SelectedHeaderV1,
) -> Result<(), PointReadServiceError> {
    if marker.height != header.block_number || marker.block_hash != header.block_hash {
        return Err(PointReadServiceError::InvalidPackage(
            "marker/header identity",
        ));
    }
    let artifact = header_artifact(header)?;
    if artifact.commitment_scheme_version != marker.commitment_scheme_version
        || artifact.r_sealed != marker.new_root
    {
        return Err(PointReadServiceError::InvalidPackage("marker/header root"));
    }
    Ok(())
}

fn header_artifact(
    header: &SelectedHeaderV1,
) -> Result<outbe_primitives::reshare_artifact::CompressedEntitiesRootArtifact, PointReadServiceError>
{
    if header.block_number == 0 {
        return Err(PointReadServiceError::InvalidPackage("genesis header"));
    }
    let decoded =
        outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(&header.extra_data)
            .map_err(|_| PointReadServiceError::InvalidPackage("header artifacts"))?;
    let artifact = decoded
        .compressed_entities_root
        .ok_or(PointReadServiceError::InvalidPackage("missing tag 0x08"))?;
    if artifact.commitment_scheme_version != ACTIVE_COMMITMENT_SCHEME {
        return Err(PointReadServiceError::InvalidPackage("fork scheme"));
    }
    Ok(artifact)
}

fn canonical_body_leaf(
    domain: CeDomain,
    raw_id: WwdEntityId,
    bytes: &[u8],
) -> Result<B256, PointReadServiceError> {
    let stored = StoredBody::decode(bytes)
        .map_err(|_| PointReadServiceError::InvalidPackage("stored body envelope"))?;
    let body_id = match domain {
        CeDomain::Tribute => decode_stored_tribute_v1(bytes)
            .map(|b| b.tribute_id)
            .map_err(|_| PointReadServiceError::InvalidPackage("tribute body"))?,
        CeDomain::NodItem => decode_stored_nod_item_v1(bytes)
            .map(|b| b.nod_id)
            .map_err(|_| PointReadServiceError::InvalidPackage("nod item body"))?,
        CeDomain::NodBucket => decode_stored_nod_bucket_v1(bytes)
            .map(|b| b.entity_id())
            .map_err(|_| PointReadServiceError::InvalidPackage("nod bucket body"))?,
    };
    if body_id != raw_id {
        return Err(PointReadServiceError::InvalidPackage("body identity"));
    }
    body_commitment(
        ACTIVE_COMMITMENT_SCHEME,
        stored.schema_version(),
        raw_id,
        stored.payload(),
    )
    .map(|leaf| B256::from(*leaf.as_bytes()))
    .map_err(|_| PointReadServiceError::InvalidPackage("body commitment"))
}

fn top_siblings(roots: &[B256], selected: u32) -> Result<[B256; 4], PointReadServiceError> {
    let mut level_roots: Vec<[u8; 32]> = roots.iter().map(|r| r.0).collect();
    let mut position = selected as usize;
    let mut siblings = Vec::with_capacity(roots.len().trailing_zeros() as usize);
    let mut level = 0_u32;
    while level_roots.len() > 1 {
        siblings.push(B256::from(level_roots[position ^ 1]));
        let mut parents = Vec::with_capacity(level_roots.len() / 2);
        for pair in level_roots.chunks_exact(2) {
            parents.push(top_hash(level, 0, pair[0], pair[1])?);
        }
        level_roots = parents;
        position /= 2;
        level += 1;
    }
    siblings.try_into().map_err(|_| {
        PointReadServiceError::Materialization("v1 requires exactly four top siblings".into())
    })
}

fn top_hash(
    level: u32,
    shard_index: u32,
    current: [u8; 32],
    sibling: [u8; 32],
) -> Result<[u8; 32], PointReadServiceError> {
    let (left, right) = if ((shard_index >> level) & 1) == 0 {
        (current, sibling)
    } else {
        (sibling, current)
    };
    let inputs = [
        Fr::from(level),
        Fr::from_be_bytes_mod_order(&left),
        Fr::from_be_bytes_mod_order(&right),
    ];
    Poseidon::<Fr>::with_domain_tag_circom(inputs.len(), Fr::from(TAG_TOP_NODE))
        .and_then(|mut h| h.hash(&inputs))
        .map(field_to_be32)
        .map_err(|_| PointReadServiceError::InvalidPackage("top hash"))
}

fn domain(id: u16) -> Result<CeDomain, PointReadRequestError> {
    match id {
        1 => Ok(CeDomain::Tribute),
        2 => Ok(CeDomain::NodItem),
        3 => Ok(CeDomain::NodBucket),
        other => Err(PointReadRequestError::UnknownDomain(other)),
    }
}

const fn collection_for_domain(domain: CeDomain) -> Collection {
    match domain {
        CeDomain::Tribute => Collection::Tribute,
        CeDomain::NodItem => Collection::NodItem,
        CeDomain::NodBucket => Collection::NodBucket,
    }
}

mod entity_id_hex {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    use crate::WwdEntityId;

    pub fn serialize<S>(value: &WwdEntityId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(value.as_slice())))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<WwdEntityId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let encoded = encoded
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("entity ID must have a 0x prefix"))?;
        let bytes = hex::decode(encoded).map_err(D::Error::custom)?;
        WwdEntityId::try_from(bytes.as_slice()).map_err(D::Error::custom)
    }
}

mod body_bytes_hex {
    use alloy_primitives::Bytes;
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    use super::MAX_CANONICAL_BODY_BYTES;

    pub fn serialize<S>(value: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(value)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let encoded = encoded
            .strip_prefix("0x")
            .ok_or_else(|| D::Error::custom("body bytes must have a 0x prefix"))?;
        if encoded.len() > MAX_CANONICAL_BODY_BYTES * 2 {
            return Err(D::Error::custom("body bytes exceed v1 bound"));
        }
        hex::decode(encoded)
            .map(Bytes::from)
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, MutexGuard};

    use alloy_primitives::{Address, U256};
    use outbe_primitives::time::WorldwideDay;
    use proptest::prelude::*;

    use super::*;
    use crate::{
        encode_nod_bucket_v1, encode_nod_item_v1, encode_tribute_v1, CandidateCacheLimits, CeMdbx,
        CeTopologyV1, EntityRef, EnvironmentIdentity, FinalLeafMutation, NodBucketBodyV1,
        NodItemBodyV1, PartitionRef, TributeBodyV1, LOCAL_STORAGE_SCHEMA_VERSION,
    };
    use outbe_primitives::reshare_artifact::{
        encode_outbe_block_artifacts, CompressedEntitiesRootArtifact, OutbeBlockArtifacts,
    };

    static PROOF_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn proof_test_guard() -> MutexGuard<'static, ()> {
        PROOF_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn service() -> (tempfile::TempDir, Arc<CompressedTreeService>, B256) {
        let directory = tempfile::tempdir().unwrap();
        let genesis_hash = B256::repeat_byte(0x11);
        let db = CeMdbx::open(
            directory.path(),
            EnvironmentIdentity {
                local_storage_schema_version: LOCAL_STORAGE_SCHEMA_VERSION,
                chain_id: 7,
                genesis_hash,
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                topology: CeTopologyV1.encode(),
                tree_format: "ckb-smt-v0.6.1-poseidon-catalog-v3".into(),
                vendor_revision: "adr013-test".into(),
            },
            FinalizedMarker {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                height: 0,
                block_hash: genesis_hash,
                parent_block_hash: B256::ZERO,
                parent_root: B256::ZERO,
                new_root: crate::sealed_root(B256::ZERO).unwrap(),
            },
        )
        .unwrap();
        let service = Arc::new(
            CompressedTreeService::new(
                db,
                CandidateCacheLimits {
                    max_candidates: 2,
                    max_encoded_bytes: 1_000_000,
                },
            )
            .unwrap(),
        );
        (directory, service, genesis_hash)
    }

    fn bucket_body(last: u8) -> (WwdEntityId, Vec<u8>, crate::Commitment) {
        let body = NodBucketBodyV1 {
            bucket_key: B256::repeat_byte(last),
            worldwide_day: WorldwideDay::new(20_260_717),
            floor_price_minor: U256::from(10),
            is_qualified: true,
            total_nods: 3,
            entry_price_minor: U256::from(11),
            reference_currency: 840,
        };
        let id = body.entity_id();
        let stored = StoredBody::new_v1(encode_nod_bucket_v1(&body).unwrap()).unwrap();
        let leaf = body_commitment(
            ACTIVE_COMMITMENT_SCHEME,
            stored.schema_version(),
            id,
            stored.payload(),
        )
        .unwrap();
        (id, stored.encode(), leaf)
    }

    fn stored_body(id: WwdEntityId, payload: Vec<u8>) -> (Vec<u8>, crate::Commitment) {
        let stored = StoredBody::new_v1(payload).unwrap();
        let leaf = body_commitment(
            ACTIVE_COMMITMENT_SCHEME,
            stored.schema_version(),
            id,
            stored.payload(),
        )
        .unwrap();
        (stored.encode(), leaf)
    }

    fn finalize_one(
        service: &CompressedTreeService,
        genesis_hash: B256,
        entity: EntityRef,
        leaf: crate::Commitment,
    ) -> (FinalizedMarker, SelectedHeaderV1) {
        let parent_root = crate::sealed_root(B256::ZERO).unwrap();
        let block_hash = B256::repeat_byte(0x22);
        let provisional = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: genesis_hash,
                root: parent_root,
            })
            .unwrap()
            .prepare_seal(
                1,
                &[FinalLeafMutation {
                    entity,
                    final_leaf: Some(leaf),
                }],
                &[],
            )
            .unwrap();
        let root = provisional.new_root();
        service.publish_candidate(block_hash, provisional).unwrap();
        let marker = service
            .apply_finalized(1, block_hash, root)
            .unwrap()
            .marker();
        let extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            compressed_entities_root: Some(CompressedEntitiesRootArtifact {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                r_sealed: root,
            }),
            ..Default::default()
        })
        .unwrap()
        .to_vec();
        (
            marker,
            SelectedHeaderV1 {
                block_number: 1,
                block_hash,
                extra_data,
            },
        )
    }

    fn finalize_empty(service: &CompressedTreeService, genesis_hash: B256) -> SelectedHeaderV1 {
        let parent_root = crate::sealed_root(B256::ZERO).unwrap();
        let provisional = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: 0,
                block_hash: genesis_hash,
                root: parent_root,
            })
            .unwrap()
            .prepare_seal(1, &[], &[])
            .unwrap();
        let root = provisional.new_root();
        let block_hash = B256::repeat_byte(0x24);
        service.publish_candidate(block_hash, provisional).unwrap();
        service.apply_finalized(1, block_hash, root).unwrap();
        SelectedHeaderV1 {
            block_number: 1,
            block_hash,
            extra_data: encode_outbe_block_artifacts(&OutbeBlockArtifacts {
                compressed_entities_root: Some(CompressedEntitiesRootArtifact {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    r_sealed: root,
                }),
                ..Default::default()
            })
            .unwrap()
            .to_vec(),
        }
    }

    #[test]
    fn present_and_both_absence_variants_verify_against_header() {
        let _guard = proof_test_guard();
        let (_dir, service, genesis_hash) = service();
        let (id, body, leaf) = bucket_body(7);
        let (marker, header) = finalize_one(&service, genesis_hash, EntityRef::NodBucket(id), leaf);
        let request = PointReadRequestV1 {
            domain_id: 3,
            raw_id: id,
        };
        let present = service
            .serve_point_read_v1(
                7,
                request,
                |height, hash| {
                    assert_eq!((height, hash), (marker.height, marker.block_hash));
                    Some(header.clone())
                },
                |domain, raw_id| {
                    assert_eq!((domain, raw_id), (CeDomain::NodBucket, id));
                    Some(body.clone())
                },
            )
            .unwrap();
        assert_eq!(
            verify_point_read_v1(7, request, &header, &present).unwrap(),
            VerifiedPointReadV1::Present
        );

        let (missing, _, _) = bucket_body(8);
        let missing_request = PointReadRequestV1 {
            domain_id: 3,
            raw_id: missing,
        };
        let entity_absent = service
            .serve_point_read_v1(
                7,
                missing_request,
                |_, _| Some(header.clone()),
                |_, _| panic!("absence must not read Mongo"),
            )
            .unwrap();
        assert!(matches!(
            entity_absent,
            PointReadResultV1::Absent {
                evidence: AbsentEvidenceV1::EntityAbsentInCollection { .. },
                ..
            }
        ));
        assert_eq!(
            verify_point_read_v1(7, missing_request, &header, &entity_absent).unwrap(),
            VerifiedPointReadV1::Absent
        );

        let tribute_request = PointReadRequestV1 {
            domain_id: 1,
            raw_id: missing,
        };
        let collection_absent = service
            .serve_point_read_v1(
                7,
                tribute_request,
                |_, _| Some(header.clone()),
                |_, _| panic!("absence must not read Mongo"),
            )
            .unwrap();
        assert!(matches!(
            collection_absent,
            PointReadResultV1::Absent {
                evidence: AbsentEvidenceV1::CollectionAbsent { .. },
                ..
            }
        ));
        assert_eq!(
            verify_point_read_v1(7, tribute_request, &header, &collection_absent).unwrap(),
            VerifiedPointReadV1::Absent
        );
    }

    #[test]
    fn bad_header_body_and_request_fail_closed() {
        let _guard = proof_test_guard();
        let (_genesis_dir, genesis_service, _) = service();
        let (genesis_id, _, _) = bucket_body(6);
        assert_eq!(
            genesis_service
                .serve_point_read_v1(
                    7,
                    PointReadRequestV1 {
                        domain_id: CeDomain::NodBucket.id(),
                        raw_id: genesis_id,
                    },
                    |_, _| panic!("genesis must not perform a header lookup"),
                    |_, _| panic!("genesis must not perform a body lookup"),
                )
                .unwrap(),
            PointReadResultV1::Unavailable
        );
        let (_dir, service, genesis_hash) = service();
        let (id, body, leaf) = bucket_body(7);
        let (_, header) = finalize_one(&service, genesis_hash, EntityRef::NodBucket(id), leaf);
        let request = PointReadRequestV1 {
            domain_id: 3,
            raw_id: id,
        };
        let mut wrong_header = header.clone();
        wrong_header.block_hash = B256::repeat_byte(0x99);
        assert_eq!(
            service
                .serve_point_read_v1(
                    7,
                    request,
                    |_, _| Some(wrong_header),
                    |_, _| Some(body.clone())
                )
                .unwrap(),
            PointReadResultV1::Unavailable
        );
        assert_eq!(
            service
                .serve_point_read_v1(
                    7,
                    request,
                    |_, _| Some(header.clone()),
                    |_, _| Some(vec![1, 2, 3]),
                )
                .unwrap(),
            PointReadResultV1::Unavailable
        );
        assert_eq!(
            service
                .serve_point_read_v1(7, request, |_, _| Some(header.clone()), |_, _| None)
                .unwrap(),
            PointReadResultV1::Unavailable
        );
        let (_, wrong_identity_body, _) = bucket_body(8);
        assert_eq!(
            service
                .serve_point_read_v1(
                    7,
                    request,
                    |_, _| Some(header.clone()),
                    |_, _| Some(wrong_identity_body),
                )
                .unwrap(),
            PointReadResultV1::Unavailable
        );
        let changed = NodBucketBodyV1 {
            bucket_key: B256::repeat_byte(7),
            worldwide_day: WorldwideDay::new(20_260_717),
            floor_price_minor: U256::from(999),
            is_qualified: true,
            total_nods: 3,
            entry_price_minor: U256::from(11),
            reference_currency: 840,
        };
        assert_eq!(changed.entity_id(), id);
        let (wrong_leaf_body, _) = stored_body(id, encode_nod_bucket_v1(&changed).unwrap());
        assert_eq!(
            service
                .serve_point_read_v1(
                    7,
                    request,
                    |_, _| Some(header.clone()),
                    |_, _| Some(wrong_leaf_body),
                )
                .unwrap(),
            PointReadResultV1::Unavailable
        );
        assert_eq!(
            service.serve_point_read_v1(
                7,
                PointReadRequestV1 {
                    domain_id: 99,
                    raw_id: id
                },
                |_, _| None,
                |_, _| None,
            ),
            Err(PointReadRequestError::UnknownDomain(99))
        );
    }

    #[test]
    fn present_golden_packages_cover_every_closed_domain() {
        let _guard = proof_test_guard();
        let mut transport_hashes = Vec::new();
        let day = WorldwideDay::new(20_260_717);
        let tribute_id = WwdEntityId::from_day_and_digest(day, [0x31; 32]);
        let tribute = TributeBodyV1 {
            tribute_id,
            owner: Address::repeat_byte(0x41),
            worldwide_day: day,
            issuance_amount_minor: U256::from(10),
            issuance_currency: 840,
            nominal_amount_minor: U256::from(11),
            reference_currency: 978,
            tribute_price_minor: U256::from(12),
            exclude_from_intex_issuance: false,
        };
        let nod_id = WwdEntityId::from_day_and_digest(day, [0x32; 32]);
        let nod = NodItemBodyV1 {
            nod_id,
            owner: Address::repeat_byte(0x42),
            gratis_load_minor: U256::from(1),
            worldwide_day: day,
            league_id: 7,
            floor_price_minor: U256::from(2),
            bucket_key: B256::repeat_byte(0x43),
            issuance_currency: 840,
            reference_currency: 978,
            issued_at: 123,
        };
        let (bucket_id, bucket_bytes, bucket_leaf) = bucket_body(0x33);
        let cases = [
            {
                let (bytes, leaf) = stored_body(tribute_id, encode_tribute_v1(&tribute).unwrap());
                (
                    CeDomain::Tribute,
                    EntityRef::Tribute(tribute_id),
                    tribute_id,
                    bytes,
                    leaf,
                )
            },
            {
                let (bytes, leaf) = stored_body(nod_id, encode_nod_item_v1(&nod).unwrap());
                (
                    CeDomain::NodItem,
                    EntityRef::NodItem(nod_id),
                    nod_id,
                    bytes,
                    leaf,
                )
            },
            (
                CeDomain::NodBucket,
                EntityRef::NodBucket(bucket_id),
                bucket_id,
                bucket_bytes,
                bucket_leaf,
            ),
        ];
        for (domain, entity, id, body, leaf) in cases {
            let (_dir, node, genesis_hash) = service();
            let (_, header) = finalize_one(&node, genesis_hash, entity, leaf);
            let request = PointReadRequestV1 {
                domain_id: domain.id(),
                raw_id: id,
            };
            let package = node
                .serve_point_read_v1(7, request, |_, _| Some(header.clone()), |_, _| Some(body))
                .unwrap();
            assert_eq!(
                verify_point_read_v1(7, request, &header, &package).unwrap(),
                VerifiedPointReadV1::Present
            );
            let json = serde_json::to_string(&package).unwrap();
            transport_hashes.push(alloy_primitives::keccak256(json.as_bytes()));
            assert!(json.contains("\"present\""));
            assert!(json.contains("\"body_bytes\":\"0x"));
            assert!(json.contains("\"shard_smt_proof\":\"0x"));
            assert_eq!(
                serde_json::from_str::<PointReadResultV1>(&json).unwrap(),
                package
            );

            let missing_id = WwdEntityId::from_day_and_digest(id.worldwide_day(), [0x99; 32]);
            let missing_request = PointReadRequestV1 {
                domain_id: domain.id(),
                raw_id: missing_id,
            };
            let entity_absent = node
                .serve_point_read_v1(
                    7,
                    missing_request,
                    |_, _| Some(header.clone()),
                    |_, _| panic!("authenticated entity absence must not read Mongo"),
                )
                .unwrap();
            assert!(matches!(
                entity_absent,
                PointReadResultV1::Absent {
                    evidence: AbsentEvidenceV1::EntityAbsentInCollection { .. },
                    ..
                }
            ));
            assert_eq!(
                verify_point_read_v1(7, missing_request, &header, &entity_absent).unwrap(),
                VerifiedPointReadV1::Absent
            );
            transport_hashes.push(alloy_primitives::keccak256(
                serde_json::to_string(&entity_absent).unwrap().as_bytes(),
            ));

            let (_empty_dir, empty_service, empty_genesis) = service();
            let empty_header = finalize_empty(&empty_service, empty_genesis);
            let collection_absent = empty_service
                .serve_point_read_v1(
                    7,
                    request,
                    |_, _| Some(empty_header.clone()),
                    |_, _| panic!("authenticated collection absence must not read Mongo"),
                )
                .unwrap();
            assert!(matches!(
                collection_absent,
                PointReadResultV1::Absent {
                    evidence: AbsentEvidenceV1::CollectionAbsent { .. },
                    ..
                }
            ));
            assert_eq!(
                verify_point_read_v1(7, request, &empty_header, &collection_absent).unwrap(),
                VerifiedPointReadV1::Absent
            );
            transport_hashes.push(alloy_primitives::keccak256(
                serde_json::to_string(&collection_absent)
                    .unwrap()
                    .as_bytes(),
            ));
        }
        assert_eq!(
            transport_hashes,
            [
                alloy_primitives::b256!(
                    "122835a3da15ee4370013c6f90edcaa3bbaa636530d341b6d605d5a68ec889c6"
                ),
                alloy_primitives::b256!(
                    "157bbc65cbc812a2d6d3c376f666f245721d40f10abb844589c32b4ffe1886da"
                ),
                alloy_primitives::b256!(
                    "a975d4736ef74939d9eca29e329d6ab1aa2aad157cc971d6315e3dc1bdf5fe9b"
                ),
                alloy_primitives::b256!(
                    "37fc86dbe097723b0bda2d83b6558bc4c059f54cf181d2d9ab257416c3c3bc49"
                ),
                alloy_primitives::b256!(
                    "75f42cf8413503971fe749902ab06d199bcad96e39e49ba68ec24c8f5a1666fd"
                ),
                alloy_primitives::b256!(
                    "d4382908cd4da41da05e5df6cbe86c130c0609e7818077c7d38184b87d127748"
                ),
                alloy_primitives::b256!(
                    "3a24b33f4a1b870ffaf9bff3aab2824df6982dcb96eced6dbc9dfdc35db740d9"
                ),
                alloy_primitives::b256!(
                    "c20d4efc5ab9a3ceb5ecefe77fc9b4a581c4d84e810e0ca617e75acace9ae2d9"
                ),
                alloy_primitives::b256!(
                    "c401b4fc8759510f0def36b6a90258d98bb4317347ecc84395a776fd5968b18f"
                ),
            ],
            "exact present/entity-absent/collection-absent JSON transports for all domains"
        );
    }

    #[test]
    fn json_request_and_decoder_bounds_are_pinned() {
        let _guard = proof_test_guard();
        let id = WwdEntityId::from_day_and_digest(WorldwideDay::new(20_260_717), [0x55; 32]);
        let request = PointReadRequestV1 {
            domain_id: 2,
            raw_id: id,
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            format!(
                "{{\"domain_id\":2,\"raw_id\":\"0x{}\"}}",
                hex::encode(id.as_slice())
            )
        );
        assert_eq!(
            serde_json::from_str::<PointReadRequestV1>(&serde_json::to_string(&request).unwrap())
                .unwrap(),
            request
        );
        assert!(
            serde_json::from_str::<PointReadRequestV1>("{\"domain_id\":2,\"raw_id\":\"55\"}")
                .is_err()
        );
        assert!(
            serde_json::from_value::<CkbCompiledProofV1>(serde_json::json!(format!(
                "0x{}",
                "00".repeat(MAX_COMPILED_PROOF_BYTES + 1)
            )))
            .is_err()
        );
        let oversized = serde_json::json!({
            "present": {
                "common": {
                    "proof_encoding_version": 1,
                    "chain_id": 7,
                    "block_number": 1,
                    "block_hash": B256::ZERO,
                    "domain_id": 2,
                    "raw_id": format!("0x{}", hex::encode(id.as_slice()))
                },
                "body_bytes": format!("0x{}", "00".repeat(MAX_CANONICAL_BODY_BYTES + 1)),
                "evidence": {
                    "shard_smt_proof": "0x01",
                    "shard_top_siblings": vec![B256::ZERO; 4],
                    "root_catalog_proof": "0x01"
                }
            }
        });
        assert!(serde_json::from_value::<PointReadResultV1>(oversized).is_err());
    }

    #[test]
    fn adversarial_mutations_and_saved_proof_after_advance_are_rejected_or_remain_historical() {
        let _guard = proof_test_guard();
        let (_dir, service, genesis_hash) = service();
        let (id, body, leaf) = bucket_body(7);
        let (marker, header) = finalize_one(&service, genesis_hash, EntityRef::NodBucket(id), leaf);
        let request = PointReadRequestV1 {
            domain_id: 3,
            raw_id: id,
        };
        let package = service
            .serve_point_read_v1(7, request, |_, _| Some(header.clone()), |_, _| Some(body))
            .unwrap();

        let mut wrong_chain = package.clone();
        if let PointReadResultV1::Present { common, .. } = &mut wrong_chain {
            common.chain_id = 8;
        }
        assert!(verify_point_read_v1(7, request, &header, &wrong_chain).is_err());
        let mut wrong_identity = package.clone();
        if let PointReadResultV1::Present { common, .. } = &mut wrong_identity {
            common.raw_id = WwdEntityId::from_day_and_digest(id.worldwide_day(), [0x77; 32]);
        }
        assert!(verify_point_read_v1(7, request, &header, &wrong_identity).is_err());
        let mut wrong_body = package.clone();
        if let PointReadResultV1::Present { body_bytes, .. } = &mut wrong_body {
            let mut mutated = body_bytes.to_vec();
            mutated[0] ^= 1;
            *body_bytes = mutated.into();
        }
        assert!(verify_point_read_v1(7, request, &header, &wrong_body).is_err());
        let mut wrong_sibling = package.clone();
        if let PointReadResultV1::Present { evidence, .. } = &mut wrong_sibling {
            evidence.shard_top_siblings[0] = B256::repeat_byte(0x66);
        }
        assert!(verify_point_read_v1(7, request, &header, &wrong_sibling).is_err());
        let mut wrong_proof = package.clone();
        if let PointReadResultV1::Present { evidence, .. } = &mut wrong_proof {
            let mut mutated = evidence.shard_smt_proof.0.to_vec();
            mutated[0] ^= 1;
            evidence.shard_smt_proof.0 = mutated.into();
        }
        assert!(verify_point_read_v1(7, request, &header, &wrong_proof).is_err());

        for mutate in [
            |common: &mut PointProofCommonV1| common.proof_encoding_version += 1,
            |common: &mut PointProofCommonV1| common.block_number += 1,
            |common: &mut PointProofCommonV1| common.block_hash = B256::repeat_byte(0x81),
            |common: &mut PointProofCommonV1| common.domain_id = CeDomain::NodItem.id(),
        ] {
            let mut candidate = package.clone();
            if let PointReadResultV1::Present { common, .. } = &mut candidate {
                mutate(common);
            }
            assert!(verify_point_read_v1(7, request, &header, &candidate).is_err());
        }

        let (shard_proof, catalog_proof, siblings) = match &package {
            PointReadResultV1::Present { evidence, .. } => (
                evidence.shard_smt_proof.clone(),
                evidence.root_catalog_proof.clone(),
                evidence.shard_top_siblings,
            ),
            _ => unreachable!(),
        };
        for (is_catalog, proof) in [(false, shard_proof.clone()), (true, catalog_proof.clone())] {
            for byte in 0..proof.0.len() {
                let mut candidate = package.clone();
                if let PointReadResultV1::Present { evidence, .. } = &mut candidate {
                    let target = if is_catalog {
                        &mut evidence.root_catalog_proof
                    } else {
                        &mut evidence.shard_smt_proof
                    };
                    let mut bytes = target.0.to_vec();
                    bytes[byte] ^= 1;
                    target.0 = bytes.into();
                }
                assert!(
                    verify_point_read_v1(7, request, &header, &candidate).is_err(),
                    "every byte of each compiled proof is authenticated: catalog={is_catalog}, byte={byte}"
                );
            }
            for malformed in [proof.0[..proof.0.len() - 1].to_vec(), {
                let mut trailing = proof.0.to_vec();
                trailing.push(0);
                trailing
            }] {
                let mut candidate = package.clone();
                if let PointReadResultV1::Present { evidence, .. } = &mut candidate {
                    if is_catalog {
                        evidence.root_catalog_proof.0 = malformed.into();
                    } else {
                        evidence.shard_smt_proof.0 = malformed.into();
                    }
                }
                assert!(verify_point_read_v1(7, request, &header, &candidate).is_err());
            }
        }
        for level in 0..siblings.len() {
            let mut candidate = package.clone();
            if let PointReadResultV1::Present { evidence, .. } = &mut candidate {
                evidence.shard_top_siblings[level] = B256::repeat_byte(0x82 + level as u8);
            }
            assert!(verify_point_read_v1(7, request, &header, &candidate).is_err());
        }

        let common = match &package {
            PointReadResultV1::Present { common, .. } => common.clone(),
            _ => unreachable!(),
        };
        let wrong_result_variants = [
            PointReadResultV1::Unavailable,
            PointReadResultV1::Absent {
                common: common.clone(),
                evidence: AbsentEvidenceV1::CollectionAbsent {
                    root_catalog_proof: catalog_proof.clone(),
                },
            },
            PointReadResultV1::Absent {
                common,
                evidence: AbsentEvidenceV1::EntityAbsentInCollection {
                    shard_smt_proof: shard_proof,
                    shard_top_siblings: siblings,
                    root_catalog_proof: catalog_proof,
                },
            },
        ];
        for candidate in wrong_result_variants {
            assert!(verify_point_read_v1(7, request, &header, &candidate).is_err());
        }

        let stored = StoredBody::decode(match &package {
            PointReadResultV1::Present { body_bytes, .. } => body_bytes,
            _ => unreachable!(),
        })
        .unwrap();
        let wrong_schema = StoredBody::new(stored.schema_version() + 1, stored.payload().to_vec())
            .unwrap()
            .encode();
        let mut candidate = package.clone();
        if let PointReadResultV1::Present { body_bytes, .. } = &mut candidate {
            *body_bytes = wrong_schema.into();
        }
        assert!(verify_point_read_v1(7, request, &header, &candidate).is_err());

        let mut bad_headers = Vec::new();
        let mut wrong_number = header.clone();
        wrong_number.block_number += 1;
        bad_headers.push(wrong_number);
        let mut wrong_hash = header.clone();
        wrong_hash.block_hash = B256::repeat_byte(0x83);
        bad_headers.push(wrong_hash);
        let mut malformed_artifacts = header.clone();
        malformed_artifacts.extra_data.push(0);
        bad_headers.push(malformed_artifacts);
        let mut missing_artifact = header.clone();
        missing_artifact.extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts::default())
            .unwrap()
            .to_vec();
        bad_headers.push(missing_artifact);
        for (scheme, root) in [
            (ACTIVE_COMMITMENT_SCHEME + 1, marker.new_root),
            (ACTIVE_COMMITMENT_SCHEME, B256::repeat_byte(0x84)),
        ] {
            let mut wrong_artifact = header.clone();
            wrong_artifact.extra_data = encode_outbe_block_artifacts(&OutbeBlockArtifacts {
                compressed_entities_root: Some(CompressedEntitiesRootArtifact {
                    commitment_scheme_version: scheme,
                    r_sealed: root,
                }),
                ..Default::default()
            })
            .unwrap()
            .to_vec();
            bad_headers.push(wrong_artifact);
        }
        for candidate_header in bad_headers {
            assert!(verify_point_read_v1(7, request, &candidate_header, &package).is_err());
        }

        let next_hash = B256::repeat_byte(0x44);
        let provisional = service
            .open_parent(ExactParentIdentity {
                commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                block_number: marker.height,
                block_hash: marker.block_hash,
                root: marker.new_root,
            })
            .unwrap()
            .prepare_seal(2, &[], &[])
            .unwrap();
        let next_root = provisional.new_root();
        service.publish_candidate(next_hash, provisional).unwrap();
        service.apply_finalized(2, next_hash, next_root).unwrap();
        assert_eq!(
            verify_point_read_v1(7, request, &header, &package).unwrap(),
            VerifiedPointReadV1::Present,
            "issued evidence remains valid for its independently supplied historical header"
        );
    }

    #[test]
    fn one_snapshot_survives_two_finalized_writes_before_mongo_read() {
        let _guard = proof_test_guard();
        let (_dir, service, genesis_hash) = service();
        let (id, body_h1, leaf_h1) = bucket_body(7);
        let (marker_h1, header_h1) =
            finalize_one(&service, genesis_hash, EntityRef::NodBucket(id), leaf_h1);
        let (_, _body_h2, leaf_h2) = bucket_body(8);
        let request = PointReadRequestV1 {
            domain_id: 3,
            raw_id: id,
        };
        let writer = Arc::clone(&service);
        let selected_header = header_h1.clone();
        let package = service
            .serve_point_read_v1(
                7,
                request,
                move |height, hash| {
                    assert_eq!((height, hash), (1, marker_h1.block_hash));
                    let block2 = B256::repeat_byte(0x52);
                    let candidate2 = writer
                        .open_parent(ExactParentIdentity {
                            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                            block_number: marker_h1.height,
                            block_hash: marker_h1.block_hash,
                            root: marker_h1.new_root,
                        })
                        .unwrap()
                        .prepare_seal(
                            2,
                            &[FinalLeafMutation {
                                entity: EntityRef::NodBucket(id),
                                final_leaf: Some(leaf_h2),
                            }],
                            &[],
                        )
                        .unwrap();
                    let root2 = candidate2.new_root();
                    writer.publish_candidate(block2, candidate2).unwrap();
                    let marker2 = writer.apply_finalized(2, block2, root2).unwrap().marker();

                    let block3 = B256::repeat_byte(0x53);
                    let candidate3 = writer
                        .open_parent(ExactParentIdentity {
                            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                            block_number: marker2.height,
                            block_hash: marker2.block_hash,
                            root: marker2.new_root,
                        })
                        .unwrap()
                        .prepare_seal(
                            3,
                            &[FinalLeafMutation {
                                entity: EntityRef::NodBucket(id),
                                final_leaf: None,
                            }],
                            &[],
                        )
                        .unwrap();
                    let root3 = candidate3.new_root();
                    writer.publish_candidate(block3, candidate3).unwrap();
                    writer.apply_finalized(3, block3, root3).unwrap();
                    Some(selected_header.clone())
                },
                |_, _| Some(body_h1),
            )
            .unwrap();
        assert_eq!(service.finalized_marker().unwrap().height, 3);
        assert_eq!(
            verify_point_read_v1(7, request, &header_h1, &package).unwrap(),
            VerifiedPointReadV1::Present
        );
    }

    #[test]
    fn two_nodes_emit_identical_packages_for_the_same_finalized_state() {
        let _guard = proof_test_guard();
        let (_dir_a, node_a, genesis_a) = service();
        let (_dir_b, node_b, genesis_b) = service();
        let (id, body, leaf) = bucket_body(9);
        let (_, header_a) = finalize_one(&node_a, genesis_a, EntityRef::NodBucket(id), leaf);
        let (_, header_b) = finalize_one(&node_b, genesis_b, EntityRef::NodBucket(id), leaf);
        assert_eq!(header_a, header_b);
        let request = PointReadRequestV1 {
            domain_id: CeDomain::NodBucket.id(),
            raw_id: id,
        };
        let package_a = node_a
            .serve_point_read_v1(
                7,
                request,
                |_, _| Some(header_a.clone()),
                |_, _| Some(body.clone()),
            )
            .unwrap();
        let package_b = node_b
            .serve_point_read_v1(7, request, |_, _| Some(header_b.clone()), |_, _| Some(body))
            .unwrap();
        assert_eq!(package_a, package_b);
        assert_eq!(
            verify_point_read_v1(7, request, &header_a, &package_b).unwrap(),
            VerifiedPointReadV1::Present
        );
    }

    #[test]
    fn pre_retirement_reader_finishes_and_next_request_proves_collection_absence() {
        let _guard = proof_test_guard();
        let (_dir, service, genesis_hash) = service();
        let day = WorldwideDay::new(20_260_717);
        let id = WwdEntityId::from_day_and_digest(day, [0x71; 32]);
        let tribute = TributeBodyV1 {
            tribute_id: id,
            owner: Address::repeat_byte(0x72),
            worldwide_day: day,
            issuance_amount_minor: U256::from(1),
            issuance_currency: 840,
            nominal_amount_minor: U256::from(2),
            reference_currency: 978,
            tribute_price_minor: U256::from(3),
            exclude_from_intex_issuance: false,
        };
        let (body, leaf) = stored_body(id, encode_tribute_v1(&tribute).unwrap());
        let (marker1, header1) = finalize_one(&service, genesis_hash, EntityRef::Tribute(id), leaf);
        let request = PointReadRequestV1 {
            domain_id: 1,
            raw_id: id,
        };
        let writer = Arc::clone(&service);
        let old_header = header1.clone();
        let marker2 = std::cell::Cell::new(None);
        let old_package = service
            .serve_point_read_v1(
                7,
                request,
                |_, _| {
                    let block2 = B256::repeat_byte(0x62);
                    let candidate = writer
                        .open_parent(ExactParentIdentity {
                            commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                            block_number: marker1.height,
                            block_hash: marker1.block_hash,
                            root: marker1.new_root,
                        })
                        .unwrap()
                        .prepare_seal(2, &[], &[PartitionRef::TributeWwd(day)])
                        .unwrap();
                    let root2 = candidate.new_root();
                    writer.publish_candidate(block2, candidate).unwrap();
                    marker2.set(Some(
                        writer.apply_finalized(2, block2, root2).unwrap().marker(),
                    ));
                    Some(old_header.clone())
                },
                |_, _| Some(body),
            )
            .unwrap();
        assert_eq!(
            verify_point_read_v1(7, request, &header1, &old_package).unwrap(),
            VerifiedPointReadV1::Present
        );
        let marker2 = marker2.get().unwrap();
        let header2 = SelectedHeaderV1 {
            block_number: marker2.height,
            block_hash: marker2.block_hash,
            extra_data: encode_outbe_block_artifacts(&OutbeBlockArtifacts {
                compressed_entities_root: Some(CompressedEntitiesRootArtifact {
                    commitment_scheme_version: ACTIVE_COMMITMENT_SCHEME,
                    r_sealed: marker2.new_root,
                }),
                ..Default::default()
            })
            .unwrap()
            .to_vec(),
        };
        let absent = service
            .serve_point_read_v1(
                7,
                request,
                |_, _| Some(header2.clone()),
                |_, _| panic!("retired collection absence must not read Mongo"),
            )
            .unwrap();
        assert!(matches!(
            absent,
            PointReadResultV1::Absent {
                evidence: AbsentEvidenceV1::CollectionAbsent { .. },
                ..
            }
        ));
        assert_eq!(
            verify_point_read_v1(7, request, &header2, &absent).unwrap(),
            VerifiedPointReadV1::Absent
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn proof_and_package_decoders_never_panic_on_bounded_adversarial_bytes(
            proof in proptest::collection::vec(any::<u8>(), 0..2048),
            raw in proptest::collection::vec(any::<u8>(), 0..1024),
        ) {
            let _guard = proof_test_guard();
            let proof_json = serde_json::json!(format!("0x{}", hex::encode(proof)));
            let _ = serde_json::from_value::<CkbCompiledProofV1>(proof_json);
            let _ = serde_json::from_slice::<PointReadResultV1>(&raw);
            let _ = serde_json::from_slice::<PointReadRequestV1>(&raw);
        }
    }
}
