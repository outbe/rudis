use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{sol, SolInterface};
use outbe_primitives::{
    dispatch::{dispatch_call, reject_value, view},
    error::Result,
    storage::StorageHandle,
};

use crate::{poc_schema_limits, schema::OcompRegistry};

pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IOcompRegistry.sol"
);

pub fn dispatch(
    storage: StorageHandle,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(
        data,
        IOcompRegistry::IOcompRegistryCalls::abi_decode,
        |call| {
            use IOcompRegistry::IOcompRegistryCalls::*;
            let registry = OcompRegistry::new(storage);
            match call {
                initialized(call) => view(call, |_| Ok(!registry.install_hash.read()?.is_zero())),
                activeProtocolBundleHash(call) => {
                    view(call, |_| registry.active_protocol_bundle_hash.read())
                }
                activeRequestProfile(call) => view(call, |_| {
                    registry.active_request_profile.read().map(Bytes::from)
                }),
                activeProtocolBundle(call) => view(call, |_| {
                    registry.active_protocol_bundle.read().map(Bytes::from)
                }),
                stagedSuccessor(call) => view(call, |_| {
                    Ok(IOcompRegistry::stagedSuccessorReturn {
                        proposalId: registry.staged_proposal_id.read()?,
                        canonicalSuccessor: Bytes::from(registry.staged_successor.read()?),
                    })
                }),
                retiringProtocolBundleHash(call) => view(call, |_| {
                    Ok(registry
                        .retiring_authority(&poc_schema_limits())?
                        .map_or(B256::ZERO, |authority| {
                            authority.request_profile.protocol_bundle_hash
                        }))
                }),
                lineageProtocolBundleHash(call) => {
                    view(call, |call| registry.lineage_bundle.read(&call.lineage))
                }
                liveLineageCount(call) => view(call, |call| {
                    registry.live_lineage_count.read(&call.protocolBundleHash)
                }),
                retentionUntil(call) => view(call, |call| {
                    registry.retention_until.read(&call.protocolBundleHash)
                }),
            }
        },
    )
}
