use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};
use base64::Engine;
use outbe_compressed_entities::{ExecutionScope, ParentBodySource, WwdEntityId};
use outbe_primitives::dispatch::{dispatch_call, metadata, view};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;
use outbe_primitives::time::WorldwideDay;

use crate::api;
use crate::errors::NodError;
use crate::schema::{NodBucketState, NodCertifiedGenerationProjection, NodContract, NodItemState};

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/INod.sol"
);

/// Dispatches Nod calls through the block-scoped compressed-body lifecycle.
pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    scope: &ExecutionScope,
    parent: &impl ParentBodySource,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(data, INod::INodCalls::abi_decode, |call| {
        let nod = NodContract::new(storage.clone());
        use INod::INodCalls::*;
        match call {
            supportsInterface(c) => view(c, |c| {
                let id: [u8; 4] = c.interfaceId.0;
                Ok(id == ERC165_INTERFACE_ID)
            }),
            name(_) => metadata::<INod::nameCall>(|| Ok(NodContract::name().to_string())),
            symbol(_) => metadata::<INod::symbolCall>(|| Ok(NodContract::symbol().to_string())),
            totalSupply(_) => {
                metadata::<INod::totalSupplyCall>(|| nod.total_supply().map(U256::from))
            }
            balanceOf(c) => view(c, |c| {
                let count = api::list_by_owner(&storage, scope, parent, c.owner)?.len();
                Ok(U256::from(count))
            }),
            ownerOf(c) => view(c, |c| {
                let nod_id = WwdEntityId::from(c.nodId);
                Ok(api::get_item(&storage, scope, parent, nod_id)?
                    .ok_or(NodError::NodNotFound)?
                    .owner)
            }),
            tokenURI(c) => view(c, |c| {
                let nod_id = WwdEntityId::from(c.nodId);
                let item =
                    api::get_item(&storage, scope, parent, nod_id)?.ok_or(NodError::NodNotFound)?;
                let bucket_id =
                    WwdEntityId::from_day_and_digest(item.worldwide_day, item.bucket_key.0);
                let bucket = api::get_bucket(&storage, scope, parent, bucket_id)?
                    .ok_or(NodError::BucketNotFound)?;
                token_uri(&item, &bucket)
            }),
            tokenByIndex(c) => view(c, |c| {
                let idx = usize::try_from(c.index).map_err(|_| NodError::IndexOutOfBounds)?;
                api::list_all(&storage, scope, parent)?
                    .get(idx)
                    .map(|item| item.nod_id.to_u256())
                    .ok_or_else(|| NodError::IndexOutOfBounds.into())
            }),
            tokenOfOwnerByIndex(c) => view(c, |c| {
                let idx = usize::try_from(c.index).map_err(|_| NodError::IndexOutOfBounds)?;
                api::list_by_owner(&storage, scope, parent, c.owner)?
                    .get(idx)
                    .map(|item| item.nod_id.to_u256())
                    .ok_or_else(|| NodError::IndexOutOfBounds.into())
            }),
            nodData(c) => view(c, |c| {
                let nod_id = WwdEntityId::from(c.nodId);
                let item =
                    api::get_item(&storage, scope, parent, nod_id)?.ok_or(NodError::NodNotFound)?;
                let bucket_id =
                    WwdEntityId::from_day_and_digest(item.worldwide_day, item.bucket_key.0);
                let bucket = api::get_bucket(&storage, scope, parent, bucket_id)?
                    .ok_or(NodError::BucketNotFound)?;
                let called_at = nod.bucket_called_at.read(&item.bucket_key)?;
                to_abi_data(&item, &bucket, called_at)
            }),
            certifiedGeneration(c) => view(c, |c| {
                let worldwide_day = WorldwideDay::new(c.worldwideDay);
                Ok(to_abi_certified_generation(
                    worldwide_day,
                    nod.ocomp_certified_generation(worldwide_day)?,
                ))
            }),
        }
    })
}

fn token_uri(item: &NodItemState, bucket: &NodBucketState) -> Result<String> {
    let nod_id_str = item.nod_id.to_u256().to_string();
    let cost_amount_minor =
        api::cost_amount_minor(bucket.entry_price_minor, item.gratis_load_minor)?;
    let json = format!(
        "{{\"name\":\"Nod #{}\",\"description\":\"{}\",\"attributes\":[{{\"trait_type\":\"token_id\",\"value\":\"{}\"}},{{\"trait_type\":\"worldwide_day\",\"value\":{}}},{{\"trait_type\":\"league_id\",\"value\":{}}},{{\"trait_type\":\"floor_price_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"gratis_load_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"cost_of_gratis_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"cost_amount_minor\",\"value\":\"{}\"}},{{\"trait_type\":\"is_qualified\",\"value\":{}}},{{\"trait_type\":\"issued_at\",\"value\":{}}},{{\"trait_type\":\"reference_currency\",\"value\":{}}},{{\"trait_type\":\"issuance_currency\",\"value\":{}}}]}}",
        nod_id_str,
        crate::constants::TOKEN_DESCRIPTION,
        nod_id_str,
        item.worldwide_day,
        item.league_id,
        item.floor_price_minor,
        item.gratis_load_minor,
        bucket.entry_price_minor,
        cost_amount_minor,
        if bucket.is_qualified { "true" } else { "false" },
        item.issued_at,
        item.reference_currency,
        item.issuance_currency,
    );
    let encoded = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
    Ok(format!("data:application/json;base64,{encoded}"))
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    #[test]
    fn token_uri_exposes_rudis_without_an_external_image_host() {
        let owner = Address::repeat_byte(0x11);
        let worldwide_day = WorldwideDay::new(20_260_907);
        let floor = U256::from(1_000_000);
        let bucket_key = NodContract::bucket_key(worldwide_day, floor, 840);
        let item = NodItemState {
            nod_id: NodContract::generate_nod_id(owner, worldwide_day).unwrap(),
            owner,
            gratis_load_minor: U256::from(1_000_000),
            worldwide_day,
            league_id: 4,
            floor_price_minor: floor,
            bucket_key,
            issuance_currency: 840,
            reference_currency: 840,
            issued_at: 1_788_739_200,
        };
        let bucket = NodBucketState {
            bucket_key,
            worldwide_day,
            floor_price_minor: floor,
            is_qualified: false,
            total_nods: 1,
            entry_price_minor: U256::from(1_000_000),
            reference_currency: 840,
        };
        let uri = token_uri(&item, &bucket).unwrap();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(uri.strip_prefix("data:application/json;base64,").unwrap())
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["description"], "Rudis Nod");
        assert!(json.get("image").is_none());
        assert!(!String::from_utf8(bytes).unwrap().contains("Outbe"));
    }
}

fn to_abi_data(
    item: &NodItemState,
    bucket: &NodBucketState,
    called_at: u64,
) -> Result<INod::NodData> {
    Ok(INod::NodData {
        nodId: item.nod_id.to_u256(),
        owner: item.owner,
        worldwideDay: item.worldwide_day.into(),
        leagueId: item.league_id,
        floorPriceMinor: item.floor_price_minor,
        gratisLoadMinor: item.gratis_load_minor,
        costOfGratisMinor: bucket.entry_price_minor,
        costAmountMinor: api::cost_amount_minor(bucket.entry_price_minor, item.gratis_load_minor)?,
        isQualified: bucket.is_qualified,
        issuanceCurrency: item.issuance_currency,
        referenceCurrency: item.reference_currency,
        issuedAt: item.issued_at,
        calledAt: called_at,
    })
}

fn to_abi_certified_generation(
    worldwide_day: WorldwideDay,
    generation: Option<NodCertifiedGenerationProjection>,
) -> INod::CertifiedGenerationData {
    match generation {
        Some(generation) => INod::CertifiedGenerationData {
            exists: true,
            worldwideDay: generation.worldwide_day.into(),
            generation: generation.generation,
            nodRoot: generation.nod_root,
            bucketRoot: generation.bucket_root,
            outputManifestRoot: generation.output_manifest_root,
            tributeCount: generation.tribute_count,
            nodCount: generation.nod_count,
            bucketCount: generation.bucket_count,
            nodAmountTotal: generation.nod_amount_total,
            nodGratisConsumed: generation.nod_gratis_consumed,
            issuedAt: generation.issued_at,
        },
        None => INod::CertifiedGenerationData {
            exists: false,
            worldwideDay: worldwide_day.into(),
            generation: 0,
            nodRoot: Default::default(),
            bucketRoot: Default::default(),
            outputManifestRoot: Default::default(),
            tributeCount: 0,
            nodCount: 0,
            bucketCount: 0,
            nodAmountTotal: U256::ZERO,
            nodGratisConsumed: U256::ZERO,
            issuedAt: 0,
        },
    }
}
