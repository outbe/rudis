//! Behavior of `#[contract_dispatch]` on a contract that has a payable method.
//!
//! No production module declares `#[contract_payable]` yet, so this is the only
//! place the generated payable arm is instantiated. It pins the two properties
//! the precompile value boundary relies on: value reaches the payable selector,
//! and every sibling selector still refuses it.

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::SolCall;
#[allow(unused_imports)]
use outbe_macros::{contract_dispatch, contract_payable, contract_public, contract_view};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;

const CHAIN_ID: u64 = 1;
const CALLER: Address = Address::repeat_byte(0xC0);

/// The module's declared payable surface, exactly as a precompile crate exposes
/// it. `mutate_void_payable` refuses any selector missing from this list.
pub const PAYABLE_SELECTORS: &[[u8; 4]] = &[__VaultAbi::fundCall::SELECTOR];

struct Vault<'storage> {
    storage: StorageHandle<'storage>,
}

impl<'storage> Vault<'storage> {
    fn new(storage: StorageHandle<'storage>) -> Self {
        Self { storage }
    }
}

#[contract_dispatch]
impl Vault<'_> {
    #[contract_public("fund(uint256)")]
    #[contract_payable]
    fn _abi_fund(&mut self, _caller: Address, value: U256, amount: U256) -> Result<()> {
        if value != amount {
            return Err(PrecompileError::Revert("value must equal amount".into()));
        }
        let _ = self.storage.chain_id()?;
        Ok(())
    }

    #[contract_public("note(uint256)")]
    fn _abi_note(&mut self, _caller: Address, amount: U256) -> Result<()> {
        let _ = amount;
        Ok(())
    }

    #[contract_public("total() view returns (uint256)")]
    #[contract_view]
    fn _abi_total(&mut self) -> Result<U256> {
        Ok(U256::ZERO)
    }
}

fn call(data: Vec<u8>, value: u64) -> Result<Bytes> {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    StorageHandle::enter(&mut provider, |storage| {
        dispatch(storage, &data, CALLER, U256::from(value))
    })
}

#[test]
fn payable_selector_receives_the_value() {
    let amount = U256::from(9u64);
    let data = __VaultAbi::fundCall { amount }.abi_encode();

    call(data.clone(), 9).expect("declared payable selector must receive the value");

    // The handler compares `msg.value` with its argument, so a mismatch proves
    // the value actually reached it rather than arriving as zero.
    assert!(matches!(
        call(data, 8),
        Err(PrecompileError::Revert(message)) if message == "value must equal amount"
    ));
}

/// The trap this guards: a contract with one payable method used to drop its
/// value check for every other selector, so a funded call to a sibling was
/// silently accepted and stranded at the address.
#[test]
fn non_payable_siblings_still_refuse_value() {
    let mutating = __VaultAbi::noteCall {
        amount: U256::from(1u64),
    }
    .abi_encode();
    let view = __VaultAbi::totalCall {}.abi_encode();

    for data in [mutating, view] {
        assert!(
            matches!(
                call(data.clone(), 1),
                Err(PrecompileError::Revert(ref message))
                    if message == "non-payable function called with value"
            ),
            "a non-payable selector of a payable contract must refuse value"
        );
        call(data, 0).expect("the same selector must still work without value");
    }
}
