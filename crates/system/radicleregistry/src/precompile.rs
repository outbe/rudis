use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};
use outbe_primitives::{
    dispatch::{dispatch_call, mutate_void, reject_value, view},
    error::Result,
    storage::StorageHandle,
};

use crate::schema::RadicleRegistry;

pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!(
    #![sol(alloy_sol_types = alloy_sol_types, extra_derives(Debug, PartialEq))]
    "../../../contracts/precompiles/src/IRadicleRegistry.sol"
);

pub fn dispatch(
    storage: StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    reject_value(&value)?;
    dispatch_call(
        data,
        IRadicleRegistry::IRadicleRegistryCalls::abi_decode,
        |call| {
            use IRadicleRegistry::IRadicleRegistryCalls::*;
            let mut registry = RadicleRegistry::new(storage);
            match call {
                registerRepository(call) => mutate_void(call, caller, |sender, call| {
                    registry
                        .register_repository(call.repoId, sender)
                        .map(|_| ())
                }),
                repositoryCount(call) => view(call, |_| registry.repository_count.read()),
                repositoryAt(call) => view(call, |call| registry.repository_at(call.index)),
                repositoryRegistrant(call) => {
                    view(call, |call| registry.registrant_of(call.repoId))
                }
                registryGeneration(call) => view(call, |_| registry.registry_generation.read()),
                maxRepositories(call) => view(call, |_| registry.config_max_repositories.read()),
            }
        },
    )
}
