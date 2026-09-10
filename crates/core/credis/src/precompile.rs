use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolInterface};

use outbe_primitives::dispatch::{dispatch_call, view};
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::error::Result;

use crate::errors::CredisError;
use crate::schema::CredisContract;

/// Selectors on this precompile that accept native value. The route table binds
/// this to the address's `ValuePolicy` at compile time, so a selector added here
/// without flipping the route fails the build.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[];

sol!("../../../contracts/precompiles/src/ICredis.sol");

pub fn dispatch(
    storage: outbe_primitives::storage::StorageHandle,
    data: &[u8],
    _caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_primitives::dispatch::reject_value(&value)?;
    dispatch_call(data, ICredis::ICredisCalls::abi_decode, |call| {
        let contract = CredisContract::new(storage.clone());
        use ICredis::ICredisCalls::*;
        match call {
            totalSupply(c) => view(c, |_| Ok(U256::from(contract.total_positions()?))),
            getPosition(c) => view(c, |c| {
                let position = contract.get_position(c.positionId)?;
                Ok(abi_position(&position))
            }),
            ownerOf(c) => view(c, |c| {
                let position = contract.get_position(c.positionId)?;
                Ok(position.smart_account)
            }),
            positionByIndex(c) => view(c, |c| {
                let index = u64::try_from(c.index).map_err(|_| CredisError::IndexOutOfBounds)?;
                Ok(abi_position(&contract.position_at(index)?))
            }),
            balanceOf(c) => view(c, |c| {
                Ok(U256::from(contract.position_count_of(c.smartAccount)?))
            }),
            positionOfAddressByIndex(c) => view(c, |c| {
                let index = u32::try_from(c.index).map_err(|_| CredisError::IndexOutOfBounds)?;
                let position = contract.position_of_address_at(c.smartAccount, index)?;
                Ok(abi_position(&position))
            }),
            hasCalledPosition(c) => view(c, |c| contract.has_called_position(c.smartAccount)),
            accruedInterest(c) => view(c, |c| {
                let position = contract.get_position(c.positionId)?;
                let timestamp = contract.storage.timestamp()?.to::<u64>();
                CredisContract::accrued_interest(&position, timestamp)
            }),
            credisPrincipalAndOutstandingOf(c) => view(c, |c| {
                let (principal, outstanding) =
                    contract.principal_and_outstanding_of(c.smartAccount)?;
                Ok(ICredis::credisPrincipalAndOutstandingOfReturn {
                    _0: principal,
                    _1: outstanding,
                })
            }),
            supportsInterface(c) => view(c, |c| {
                let id: [u8; 4] = c.interfaceId.0;
                Ok(id == ERC165_INTERFACE_ID)
            }),
        }
    })
}

fn abi_position(p: &crate::schema::Position) -> ICredis::Position {
    ICredis::Position {
        positionId: p.position_id,
        smartAccount: p.smart_account,
        cca: p.cca,
        asset: p.asset,
        issuanceCurrency: p.issuance_currency,
        referenceCurrency: p.reference_currency,
        eoaCiphertext: p.eoa_ct.clone().into(),
        principal: p.principal,
        outstanding: p.outstanding,
        collateral: p.collateral,
        collateralLocked: p.collateral_locked,
        policyRate: p.policy_rate,
        entryPrice: p.entry_price,
        callPrice: p.call_price,
        originatedAt: p.originated_at,
        lastSettledAt: p.last_settled_at,
        calledAt: p.called_at,
        state: p.state,
    }
}
