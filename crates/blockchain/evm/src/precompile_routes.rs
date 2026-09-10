//! Compact exact-address routing for existing Outbe precompiles.
//!
//! This module owns only execution facts consumed by the dispatcher: exact address,
//! dispatch adapter and base-gas function. Activation, persistence, warming,
//! sponsorship and future address classes intentionally remain outside this table.

use alloy_primitives::{Address, Bytes, U256};
use outbe_compressed_entities::ExecutionScope;
use outbe_offchain_data::RuntimeBodyReaders;
use outbe_primitives::{
    addresses::*,
    error::{PrecompileError, Result},
    storage::{gas::PRECOMPILE_BASE_GAS, StorageHandle},
};

pub(crate) type DispatchFn = fn(StorageHandle, &[u8], Address, U256) -> Result<Bytes>;
type ReaderDispatchFn =
    fn(StorageHandle, &ExecutionScope, &RuntimeBodyReaders, &[u8], Address, U256) -> Result<Bytes>;
pub(crate) type BaseGasFn = fn(&[u8]) -> u64;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReaderMode {
    None,
    Required,
    Optional,
}

#[derive(Clone, Copy)]
enum DispatchAdapter {
    Basic(DispatchFn),
    ReadersRequired(ReaderDispatchFn),
    ReadersOptional {
        without_readers: DispatchFn,
        with_readers: ReaderDispatchFn,
    },
}

/// Whether a route's dispatch may receive credited native value. Declared on
/// the same line as the dispatch function, alongside the module's own
/// `PAYABLE_SELECTORS`; `define_exact_routes!` asserts at compile time that the
/// two agree, so a module cannot start accepting `msg.value` without the route
/// declaring it, and a route cannot declare it without the module.
///
/// The module's list is in turn what its own dispatch checks: a payable module
/// refuses value for every selector it has not published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValuePolicy {
    /// No selector is payable; the boundary rejects any credited value before
    /// dispatch, so value cannot strand at the address.
    Reject,
    /// At least one selector is payable. The boundary credits value to the
    /// address, and the module refuses it for every selector outside its
    /// published list.
    Payable,
}

/// `const`-usable form of the payable check, for the route-table conformance
/// assertion below.
const fn policy_is_payable(policy: ValuePolicy) -> bool {
    matches!(policy, ValuePolicy::Payable)
}

#[derive(Clone, Copy)]
pub(crate) struct ExactRoute {
    dispatch: DispatchAdapter,
    base_gas: BaseGasFn,
    value_policy: ValuePolicy,
    payable_selectors: &'static [[u8; 4]],
}

#[derive(Clone, Copy)]
pub(crate) enum Route {
    Exact(ExactRoute),
    StablecoinClass,
}

pub(crate) struct RouteCall<'input> {
    pub(crate) callee: Address,
    pub(crate) data: &'input [u8],
    pub(crate) caller: Address,
    pub(crate) value: U256,
}

impl Route {
    /// The value policy the boundary applies to this route.
    ///
    /// Exact routes carry their own from the route table. The stablecoin class
    /// permits value because an empty-calldata send to a reserved token address
    /// is an ordinary native transfer that [`stablecoin_class_dispatch`] returns
    /// from without touching token state; denying it would make native value
    /// unspendable across the whole reserved class, including for an externally
    /// owned account whose address happens to fall in the prefix.
    ///
    /// The class is the one route this policy is not compile-time bound to a
    /// published selector list, because it has no single dispatch module. What
    /// keeps value from stranding there is instead tested directly:
    /// [`stablecoin_class_dispatch`] refuses a plain send at a Factory-issued
    /// address, and the token dispatch refuses value on every selector.
    pub(crate) fn value_policy(self) -> ValuePolicy {
        match self {
            Self::Exact(route) => route.value_policy,
            Self::StablecoinClass => ValuePolicy::Payable,
        }
    }

    pub(crate) fn base_gas(self, input: &[u8]) -> u64 {
        match self {
            Self::Exact(route) => route.base_gas(input),
            Self::StablecoinClass => {
                outbe_primitives::stablecoin_fork::STABLECOIN_V1_GAS.dispatch_base
            }
        }
    }

    pub(crate) fn dispatch(
        self,
        storage: StorageHandle,
        execution_scope: &ExecutionScope,
        readers: Option<&RuntimeBodyReaders>,
        call: RouteCall<'_>,
    ) -> Result<Bytes> {
        match self {
            Self::Exact(route) => route.dispatch(
                storage,
                execution_scope,
                readers,
                call.data,
                call.caller,
                call.value,
            ),
            Self::StablecoinClass => {
                stablecoin_class_dispatch(storage, call.callee, call.data, call.caller, call.value)
            }
        }
    }
}

impl ExactRoute {
    pub(crate) fn base_gas(self, input: &[u8]) -> u64 {
        (self.base_gas)(input)
    }

    #[cfg(test)]
    pub(crate) const fn reader_mode(self) -> ReaderMode {
        match self.dispatch {
            DispatchAdapter::Basic(_) => ReaderMode::None,
            DispatchAdapter::ReadersRequired(_) => ReaderMode::Required,
            DispatchAdapter::ReadersOptional { .. } => ReaderMode::Optional,
        }
    }

    pub(crate) fn dispatch(
        self,
        storage: StorageHandle,
        execution_scope: &ExecutionScope,
        readers: Option<&RuntimeBodyReaders>,
        data: &[u8],
        caller: Address,
        value: U256,
    ) -> Result<Bytes> {
        // The boundary only decided that this *address* may be credited. Which
        // selectors may keep the value is the module's published list, enforced
        // here so a module cannot omit the check and silently accept value on
        // every selector it exposes. Payable modules repeat it at their own
        // entry, which is what covers callers that reach them directly.
        outbe_primitives::dispatch::reject_value_unless_payable(
            data,
            self.payable_selectors,
            &value,
        )?;
        match (self.dispatch, readers) {
            (DispatchAdapter::Basic(dispatch), _) => dispatch(storage, data, caller, value),
            (DispatchAdapter::ReadersRequired(dispatch), Some(readers)) => {
                dispatch(storage, execution_scope, readers, data, caller, value)
            }
            (DispatchAdapter::ReadersRequired(_), None) => Err(PrecompileError::Fatal(
                "execution body read authority was not supplied".into(),
            )),
            (DispatchAdapter::ReadersOptional { with_readers, .. }, Some(readers)) => {
                with_readers(storage, execution_scope, readers, data, caller, value)
            }
            (
                DispatchAdapter::ReadersOptional {
                    without_readers, ..
                },
                None,
            ) => without_readers(storage, data, caller, value),
        }
    }
}

fn default_base_gas(_input: &[u8]) -> u64 {
    PRECOMPILE_BASE_GAS
}

fn stablecoin_policy_dispatch(
    storage: StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_stablecoinpolicy::precompile::dispatch(storage, data, caller, value)
}

fn stablecoin_factory_dispatch(
    storage: StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_stablecoinfactory::precompile::dispatch(storage, data, caller, value)
}

fn stablecoin_class_dispatch(
    storage: StorageHandle,
    token: Address,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    let plain_native_transfer = data.is_empty() && !value.is_zero();

    // A plain native send must not be able to abort the whole transaction: a
    // registry error is fatal to a token call, but here it degrades to a revert
    // so the frame simply rolls back and the value returns to the sender.
    let registered =
        match outbe_stablecoinfactory::StablecoinFactoryApi::token_id_of(storage.clone(), token) {
            Ok(registered) => registered,
            Err(_) if plain_native_transfer => {
                return Err(PrecompileError::Revert(
                    "stablecoin registry unavailable".into(),
                ))
            }
            Err(error) => return Err(error),
        };

    let Some(factory_token_id) = registered else {
        // Reserving the address class must not make native value unspendable at
        // an address the Factory never issued - an externally owned account
        // whose address happens to fall in the prefix must still receive plain
        // transfers. This uses only revm's ordinary CALL balance semantics; it
        // invokes no token ABI and falls through to no account bytecode.
        if plain_native_transfer {
            return Ok(Bytes::new());
        }
        return Err(PrecompileError::Revert(
            "unregistered stablecoin address".into(),
        ));
    };

    // A Factory-derived token address has no key and no selector that moves
    // native balance, so accepting a plain transfer there would strand the value
    // permanently. Refuse it instead, and let the frame's checkpoint return the
    // funds to the sender.
    if plain_native_transfer {
        return Err(PrecompileError::Revert(
            "stablecoin token cannot receive native value".into(),
        ));
    }

    let expected_address = outbe_primitives::stablecoin::stablecoin_address(
        factory_token_id,
        STABLECOIN_ADDRESS_PREFIX,
    );
    if expected_address != token {
        return Err(PrecompileError::Fatal(format!(
            "stablecoin Factory reverse id does not derive callee {token}"
        )));
    }

    storage.with_account_info(token, |info| {
        let marker = info
            .code
            .as_ref()
            .map(revm::state::Bytecode::original_bytes)
            .unwrap_or_default();
        if marker.as_ref() != STABLECOIN_MARKER_CODE {
            return Err(PrecompileError::Fatal(format!(
                "stablecoin {token} marker code mismatch"
            )));
        }
        Ok(())
    })?;

    if let Err(error) = outbe_stablecoin::api::schema_version(storage.clone(), token) {
        return match error {
            PrecompileError::Revert(_) | PrecompileError::RevertBytes(_) => {
                Err(PrecompileError::Fatal(format!(
                    "stablecoin {token} schema is not initialized for V1"
                )))
            }
            other => Err(other),
        };
    }

    let identity = outbe_stablecoin::api::identity(storage.clone(), token)?;
    if identity.token_id != factory_token_id {
        return Err(PrecompileError::Fatal(format!(
            "stablecoin {token} identity does not match Factory registration"
        )));
    }

    outbe_stablecoin::precompile::dispatch(storage, token, data, caller, value)
}

fn vote_dispatch(
    storage: StorageHandle,
    data: &[u8],
    caller: Address,
    value: U256,
) -> Result<Bytes> {
    outbe_vote::precompile::dispatch_with_handlers(
        storage,
        data,
        caller,
        value,
        crate::handlers::vote::registry(),
    )
}

macro_rules! define_exact_routes {
    ($($address:path => ($dispatch:expr, $gas:expr, $value_policy:expr, $payable_selectors:expr)),+ $(,)?) => {
        pub(crate) const EXACT_ADDRESSES: &[Address] = &[$($address),+];

        // Binds each route's declared policy to the payable surface its own
        // dispatch module reports. Declaring a payable selector without
        // flipping the route (or the reverse) fails the build here.
        $(
            const _: () = assert!(
                policy_is_payable($value_policy) == !$payable_selectors.is_empty(),
                concat!(
                    "route ValuePolicy disagrees with the dispatch module's PAYABLE_SELECTORS for ",
                    stringify!($address),
                ),
            );
        )+

        pub(crate) fn lookup(address: &Address) -> Option<ExactRoute> {
            match *address {
                $(
                    $address => Some(ExactRoute {
                        dispatch: $dispatch,
                        base_gas: $gas,
                        value_policy: $value_policy,
                        payable_selectors: $payable_selectors,
                    }),
                )+
                _ => None,
            }
        }
    };
}

// The only declaration of existing exact routes. Constant match patterns make a
// duplicate address an unreachable-pattern error under the workspace's denied
// warnings; the const validator below independently rejects duplicates and Ethereum
// precompile overlap during compilation.
define_exact_routes! {
    GRATIS_ADDRESS => (DispatchAdapter::Basic(outbe_gratis::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_gratis::precompile::PAYABLE_SELECTORS),
    GRATIS_FACTORY_ADDRESS => (DispatchAdapter::Basic(outbe_gratisfactory::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_gratisfactory::precompile::PAYABLE_SELECTORS),
    PROMIS_ADDRESS => (DispatchAdapter::Basic(outbe_promis::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_promis::precompile::PAYABLE_SELECTORS),
    PROMIS_FACTORY_ADDRESS => (DispatchAdapter::Basic(outbe_promisfactory::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_promisfactory::precompile::PAYABLE_SELECTORS),
    TRIBUTE_ADDRESS => (DispatchAdapter::ReadersRequired(outbe_tribute::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_tribute::precompile::PAYABLE_SELECTORS),
    NOD_ADDRESS => (DispatchAdapter::ReadersRequired(outbe_nod::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_nod::precompile::PAYABLE_SELECTORS),
    NOD_FACTORY_ADDRESS => (DispatchAdapter::ReadersRequired(outbe_nodfactory::precompile::dispatch), outbe_nodfactory::precompile::base_gas, ValuePolicy::Reject, outbe_nodfactory::precompile::PAYABLE_SELECTORS),
    GEM_ADDRESS => (DispatchAdapter::Basic(outbe_gem::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_gem::precompile::PAYABLE_SELECTORS),
    GEM_FACTORY_ADDRESS => (DispatchAdapter::Basic(outbe_gemfactory::precompile::dispatch), outbe_gemfactory::precompile::base_gas, ValuePolicy::Reject, outbe_gemfactory::precompile::PAYABLE_SELECTORS),
    INTEX_ADDRESS => (DispatchAdapter::Basic(outbe_intex::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_intex::precompile::PAYABLE_SELECTORS),
    INTEX_FACTORY_ADDRESS => (DispatchAdapter::Basic(outbe_intexfactory::precompile::dispatch), outbe_intexfactory::precompile::base_gas, ValuePolicy::Payable, outbe_intexfactory::precompile::PAYABLE_SELECTORS),
    DESIS_ADDRESS => (DispatchAdapter::Basic(outbe_desis::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_desis::precompile::PAYABLE_SELECTORS),
    PAYNOTE_ADDRESS => (DispatchAdapter::Basic(outbe_paynote::precompile::dispatch), outbe_paynote::precompile::base_gas, ValuePolicy::Reject, outbe_paynote::precompile::PAYABLE_SELECTORS),
    VAULT_ROUTER_ADDRESS => (DispatchAdapter::Basic(outbe_vaultrouter::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_vaultrouter::precompile::PAYABLE_SELECTORS),
    CREDIS_ADDRESS => (DispatchAdapter::Basic(outbe_credis::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_credis::precompile::PAYABLE_SELECTORS),
    CREDIS_FACTORY_ADDRESS => (DispatchAdapter::Basic(outbe_credisfactory::precompile::dispatch), default_base_gas, ValuePolicy::Payable, outbe_credisfactory::precompile::PAYABLE_SELECTORS),
    CCA_ADDRESS => (DispatchAdapter::Basic(outbe_cca::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_cca::precompile::PAYABLE_SELECTORS),
    TRIBUTE_FACTORY_ADDRESS => (DispatchAdapter::ReadersRequired(outbe_tributefactory::precompile::dispatch), outbe_tributefactory::precompile::base_gas, ValuePolicy::Reject, outbe_tributefactory::precompile::PAYABLE_SELECTORS),
    VALIDATOR_SET_ADDRESS => (DispatchAdapter::Basic(outbe_validatorset::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_validatorset::precompile::PAYABLE_SELECTORS),
    SLASH_INDICATOR_ADDRESS => (DispatchAdapter::Basic(outbe_slashindicator::precompile::dispatch), outbe_slashindicator::precompile::base_gas, ValuePolicy::Reject, outbe_slashindicator::precompile::PAYABLE_SELECTORS),
    STAKING_ADDRESS => (DispatchAdapter::Basic(outbe_staking::precompile::dispatch), default_base_gas, ValuePolicy::Payable, outbe_staking::precompile::PAYABLE_SELECTORS),
    REWARDS_ADDRESS => (DispatchAdapter::Basic(outbe_rewards::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_rewards::precompile::PAYABLE_SELECTORS),
    AGENT_REWARD_ADDRESS => (DispatchAdapter::Basic(outbe_agentreward::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_agentreward::precompile::PAYABLE_SELECTORS),
    METADOSIS_ADDRESS => (DispatchAdapter::Basic(outbe_metadosis::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_metadosis::precompile::PAYABLE_SELECTORS),
    FIDELITY_ADDRESS => (DispatchAdapter::Basic(outbe_fidelity::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_fidelity::precompile::PAYABLE_SELECTORS),
    PROMIS_LIMIT_ADDRESS => (DispatchAdapter::Basic(outbe_promislimit::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_promislimit::precompile::PAYABLE_SELECTORS),
    ORACLE_ADDRESS => (DispatchAdapter::Basic(outbe_oracle::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_oracle::precompile::PAYABLE_SELECTORS),
    ZEROFEE_ADDRESS => (DispatchAdapter::Basic(outbe_zerofee::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_zerofee::precompile::PAYABLE_SELECTORS),
    OUTBE_SYSTEM_TX_ADDRESS => (DispatchAdapter::ReadersOptional {
        without_readers: crate::begin_block_precompile::dispatch,
        with_readers: crate::begin_block_precompile::dispatch_with_readers,
    }, default_base_gas, ValuePolicy::Reject, crate::begin_block_precompile::PAYABLE_SELECTORS),
    DEBUG_SUBCALL_PRECOMPILE_ADDRESS => (DispatchAdapter::Basic(crate::debug_subcall::dispatch), default_base_gas, ValuePolicy::Reject, crate::debug_subcall::PAYABLE_SELECTORS),
    ZKPROOF_POSEIDON_ADDRESS => (DispatchAdapter::Basic(crate::zk::dispatch_poseidon), crate::zk::poseidon_base_gas, ValuePolicy::Reject, crate::zk::POSEIDON_PAYABLE_SELECTORS),
    ZKPROOF_GROTH16_ADDRESS => (DispatchAdapter::Basic(crate::zk::dispatch_groth16), crate::zk::groth16_base_gas, ValuePolicy::Reject, crate::zk::GROTH16_PAYABLE_SELECTORS),
    EMIT_ADDRESS => (DispatchAdapter::Basic(outbe_emit::precompile::dispatch), outbe_emit::precompile::base_gas, ValuePolicy::Payable, outbe_emit::precompile::PAYABLE_SELECTORS),
    TEE_REGISTRY_ADDRESS => (DispatchAdapter::Basic(outbe_teeregistry::v1_precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_teeregistry::v1_precompile::PAYABLE_SELECTORS),
    L2_REGISTRY_ADDRESS => (DispatchAdapter::Basic(outbe_l2registry::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_l2registry::precompile::PAYABLE_SELECTORS),
    STABLECOIN_FACTORY_ADDRESS => (DispatchAdapter::Basic(stablecoin_factory_dispatch), default_base_gas, ValuePolicy::Reject, outbe_stablecoinfactory::precompile::PAYABLE_SELECTORS),
    STABLECOIN_POLICY_REGISTRY_ADDRESS => (DispatchAdapter::Basic(stablecoin_policy_dispatch), default_base_gas, ValuePolicy::Reject, outbe_stablecoinpolicy::precompile::PAYABLE_SELECTORS),
    RADICLE_REGISTRY_ADDRESS => (DispatchAdapter::Basic(outbe_radicleregistry::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_radicleregistry::precompile::PAYABLE_SELECTORS),
    OCOMP_REGISTRY_ADDRESS => (DispatchAdapter::Basic(outbe_ocompregistry::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_ocompregistry::precompile::PAYABLE_SELECTORS),
    GOVERNANCE_ADDRESS => (DispatchAdapter::Basic(outbe_governance::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_governance::precompile::PAYABLE_SELECTORS),
    VOTE_ADDRESS => (DispatchAdapter::Basic(vote_dispatch), default_base_gas, ValuePolicy::Payable, outbe_vote::precompile::PAYABLE_SELECTORS),
    UPDATE_ADDRESS => (DispatchAdapter::Basic(outbe_update::precompile::dispatch), default_base_gas, ValuePolicy::Reject, outbe_update::precompile::PAYABLE_SELECTORS),
}

pub(crate) fn resolve(address: &Address) -> Option<Route> {
    lookup(address)
        .map(Route::Exact)
        .or_else(|| is_stablecoin_address(*address).then_some(Route::StablecoinClass))
}

const fn addresses_equal(left: Address, right: Address) -> bool {
    let mut index = 0;
    while index < 20 {
        if left.0 .0[index] != right.0 .0[index] {
            return false;
        }
        index += 1;
    }
    true
}

const fn is_ethereum_precompile(address: Address) -> bool {
    let mut index = 0;
    while index < 19 {
        if address.0 .0[index] != 0 {
            return false;
        }
        index += 1;
    }
    address.0 .0[19] >= 1 && address.0 .0[19] <= 10
}

const fn assert_valid_production_routes(addresses: &[Address]) {
    let mut index = 0;
    while index < addresses.len() {
        if is_ethereum_precompile(addresses[index]) {
            panic!("Outbe exact route overlaps an Ethereum precompile");
        }
        if is_stablecoin_address(addresses[index]) {
            panic!("Outbe exact route overlaps the Stablecoin address class");
        }
        let mut other = index + 1;
        while other < addresses.len() {
            if addresses_equal(addresses[index], addresses[other]) {
                panic!("duplicate Outbe exact route");
            }
            other += 1;
        }
        index += 1;
    }
}

const _: () = assert_valid_production_routes(EXACT_ADDRESSES);

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidationError {
    Duplicate(Address),
    EthereumOverlap(Address),
}

#[cfg(test)]
fn validate_exact_addresses(addresses: &[Address]) -> std::result::Result<(), ValidationError> {
    for (index, address) in addresses.iter().copied().enumerate() {
        if is_ethereum_precompile(address) {
            return Err(ValidationError::EthereumOverlap(address));
        }
        if addresses[index + 1..].contains(&address) {
            return Err(ValidationError::Duplicate(address));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;
    use alloy_sol_types::{sol, SolCall};
    use outbe_primitives::stablecoin::StablecoinCreatePayload;
    use outbe_stablecoin::{FactoryTokenInitialization, StablecoinFactoryApi as TokenFactoryApi};
    use outbe_stablecoinfactory::{
        precompile::IStablecoinFactory, FactoryReservation, StablecoinFactoryApi as RegistryApi,
    };
    use outbe_stablecoinpolicy::precompile::IStablecoinPolicyRegistry;
    use revm::state::Bytecode;

    sol! {
        interface ITeeRegistryRouteTest {
            function isNodeHostEnclaveReady(uint8 rethP2pPrefix, bytes32 rethP2pX)
                external
                view
                returns (bool);
        }
    }

    #[test]
    fn production_exact_routes_validate() {
        assert_eq!(validate_exact_addresses(EXACT_ADDRESSES), Ok(()));
    }

    #[test]
    fn duplicate_and_ethereum_overlap_are_rejected() {
        let duplicate = Address::repeat_byte(0x44);
        assert_eq!(
            validate_exact_addresses(&[duplicate, duplicate]),
            Err(ValidationError::Duplicate(duplicate))
        );

        let ethereum = Address::with_last_byte(1);
        assert_eq!(
            validate_exact_addresses(&[ethereum]),
            Err(ValidationError::EthereumOverlap(ethereum))
        );
    }

    #[test]
    fn required_reader_route_fails_before_module_dispatch_when_authority_is_absent() {
        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let error = lookup(&TRIBUTE_ADDRESS)
            .unwrap()
            .dispatch(
                storage,
                &ExecutionScope::new(),
                None,
                &[],
                Address::ZERO,
                U256::ZERO,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            PrecompileError::Fatal(message)
                if message == "execution body read authority was not supplied"
        ));
    }

    #[test]
    fn reader_modes_match_existing_execution_requirements() {
        for address in [
            TRIBUTE_ADDRESS,
            TRIBUTE_FACTORY_ADDRESS,
            NOD_ADDRESS,
            NOD_FACTORY_ADDRESS,
        ] {
            assert_eq!(
                lookup(&address).unwrap().reader_mode(),
                ReaderMode::Required
            );
        }
        assert_eq!(
            lookup(&OUTBE_SYSTEM_TX_ADDRESS).unwrap().reader_mode(),
            ReaderMode::Optional
        );
        assert_eq!(
            lookup(&VOTE_ADDRESS).unwrap().reader_mode(),
            ReaderMode::None
        );
        assert_eq!(
            lookup(&RADICLE_REGISTRY_ADDRESS).unwrap().reader_mode(),
            ReaderMode::None
        );
    }

    #[test]
    fn radicle_registry_route_uses_standard_base_gas() {
        let route = lookup(&RADICLE_REGISTRY_ADDRESS).expect("RadicleRegistry route");
        assert_eq!(route.base_gas(&[]), PRECOMPILE_BASE_GAS);
        assert_eq!(
            route.base_gas(&[0xde, 0xad, 0xbe, 0xef]),
            PRECOMPILE_BASE_GAS
        );
    }

    #[test]
    fn tee_route_accepts_v1_and_rejects_the_legacy_registration_selector() {
        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let route = lookup(&TEE_REGISTRY_ADDRESS).unwrap();

        let v1 = ITeeRegistryRouteTest::isNodeHostEnclaveReadyCall {
            rethP2pPrefix: 2,
            // SEC1 compressed secp256k1 generator point.
            rethP2pX: b256!("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        }
        .abi_encode();
        let output = route
            .dispatch(
                StorageHandle::new(&mut provider),
                &ExecutionScope::new(),
                None,
                &v1,
                Address::ZERO,
                U256::ZERO,
            )
            .unwrap();
        assert!(
            !ITeeRegistryRouteTest::isNodeHostEnclaveReadyCall::abi_decode_returns(&output)
                .unwrap()
        );

        // Use the exact legacy signature rather than the Rust method name.
        let mut legacy = vec![0_u8; 4 + 32 * 6];
        legacy[..4].copy_from_slice(
            &alloy_primitives::keccak256(
                b"registerEnclave(uint256,uint256,uint256,uint256,uint256,uint16)",
            )[..4],
        );
        assert!(route
            .dispatch(
                StorageHandle::new(&mut provider),
                &ExecutionScope::new(),
                None,
                &legacy,
                Address::ZERO,
                U256::ZERO,
            )
            .is_err());
    }

    #[test]
    fn policy_route_is_available_from_genesis() {
        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let route = lookup(&STABLECOIN_POLICY_REGISTRY_ADDRESS).unwrap();
        let data = IStablecoinPolicyRegistry::policyExistsCall {
            policyId: U256::from(1u64),
        }
        .abi_encode();

        let output = route
            .dispatch(
                storage,
                &ExecutionScope::new(),
                None,
                &data,
                Address::ZERO,
                U256::ZERO,
            )
            .unwrap();
        assert!(IStablecoinPolicyRegistry::policyExistsCall::abi_decode_returns(&output).unwrap());
    }

    #[test]
    fn factory_route_is_available_from_genesis() {
        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let route = lookup(&STABLECOIN_FACTORY_ADDRESS).unwrap();
        let data = IStablecoinFactory::tokenCountCall {}.abi_encode();

        let output = route
            .dispatch(
                storage,
                &ExecutionScope::new(),
                None,
                &data,
                Address::ZERO,
                U256::ZERO,
            )
            .unwrap();
        assert_eq!(
            IStablecoinFactory::tokenCountCall::abi_decode_returns(&output).unwrap(),
            U256::ZERO
        );
    }

    fn class_address(last: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[..2].copy_from_slice(&STABLECOIN_ADDRESS_PREFIX);
        bytes[19] = last;
        Address::from(bytes)
    }

    fn class_call(callee: Address, data: &[u8]) -> RouteCall<'_> {
        RouteCall {
            callee,
            data,
            caller: Address::ZERO,
            value: U256::ZERO,
        }
    }

    fn install_token(storage: StorageHandle<'_>, marker: bool, initialize: bool) -> Address {
        let issuer = Address::repeat_byte(0x44);
        let payload = StablecoinCreatePayload {
            issuer,
            name: "Example Dollar".into(),
            ticker: "EXUSD".into(),
            iso4217: 840,
            decimals: 6,
            supply_cap: U256::from(1_000_000u64),
            policy_id: U256::from(1u64),
        };
        let (token_id, token) = outbe_primitives::stablecoin::predict_stablecoin(
            storage.chain_id().unwrap(),
            STABLECOIN_FACTORY_ADDRESS,
            issuer,
            &payload.ticker,
            STABLECOIN_ADDRESS_PREFIX,
        )
        .unwrap();
        let reservation = FactoryReservation {
            proposal_id: U256::from(1u64),
            token_id,
            ticker: payload.ticker.clone(),
            token,
        };
        RegistryApi::reserve(storage.clone(), &reservation).unwrap();
        RegistryApi::consume(storage.clone(), reservation.proposal_id).unwrap();
        if marker {
            storage
                .set_code(
                    token,
                    Bytecode::new_raw(Bytes::from_static(&STABLECOIN_MARKER_CODE)),
                )
                .unwrap();
        }
        if initialize {
            TokenFactoryApi::new(storage.clone())
                .initialize(&FactoryTokenInitialization {
                    token_address: token,
                    token_id,
                    creation_protocol_version: 0,
                    payload,
                })
                .unwrap();
        }
        token
    }

    /// A Factory-issued token address has no key and no selector that moves
    /// native balance, so a plain transfer there would be unrecoverable.
    #[test]
    fn registered_stablecoin_token_refuses_a_plain_native_transfer() {
        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let token = install_token(storage.clone(), true, true);
        let route = resolve(&token).unwrap();

        assert!(matches!(
            route.dispatch(
                storage,
                &ExecutionScope::new(),
                None,
                RouteCall {
                    value: U256::from(1u64),
                    ..class_call(token, &[])
                },
            ),
            Err(PrecompileError::Revert(message))
                if message == "stablecoin token cannot receive native value"
        ));
    }

    #[test]
    fn stablecoin_class_is_claimed_and_unknown_members_fail_closed() {
        let token = class_address(0x11);
        assert!(matches!(resolve(&token), Some(Route::StablecoinClass)));

        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let route = resolve(&token).unwrap();
        assert_eq!(
            route
                .dispatch(
                    storage.clone(),
                    &ExecutionScope::new(),
                    None,
                    RouteCall {
                        value: U256::from(1u64),
                        ..class_call(token, &[])
                    },
                )
                .unwrap(),
            Bytes::new()
        );
        assert!(matches!(
            route.dispatch(
                storage,
                &ExecutionScope::new(),
                None,
                class_call(token, &[]),
            ),
            Err(PrecompileError::Revert(message)) if message == "unregistered stablecoin address"
        ));
    }

    #[test]
    fn class_authentication_requires_registration_marker_schema_and_matching_full_id() {
        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let token = install_token(storage.clone(), false, false);
        let route = resolve(&token).unwrap();

        assert!(matches!(
            route.dispatch(
                storage.clone(),
                &ExecutionScope::new(),
                None,
                class_call(token, &[]),
            ),
            Err(PrecompileError::Fatal(message)) if message.contains("marker code mismatch")
        ));

        storage
            .set_code(
                token,
                Bytecode::new_raw(Bytes::from_static(&STABLECOIN_MARKER_CODE)),
            )
            .unwrap();
        assert!(matches!(
            route.dispatch(
                storage.clone(),
                &ExecutionScope::new(),
                None,
                class_call(token, &[]),
            ),
            Err(PrecompileError::Fatal(_))
        ));
    }

    #[test]
    fn authenticated_class_dispatch_uses_the_actual_callee() {
        let mut provider = outbe_primitives::storage::hashmap::HashMapStorageProvider::new(1);
        let storage = StorageHandle::new(&mut provider);
        let token = install_token(storage.clone(), true, true);
        let call = outbe_stablecoin::precompile::IStablecoin::symbolCall {};
        let output = resolve(&token)
            .unwrap()
            .dispatch(
                storage.clone(),
                &ExecutionScope::new(),
                None,
                class_call(token, &call.abi_encode()),
            )
            .unwrap();
        assert_eq!(
            outbe_stablecoin::precompile::IStablecoin::symbolCall::abi_decode_returns(&output)
                .unwrap(),
            "EXUSD"
        );

        storage
            .sstore(token, U256::from(2u64), U256::from(0x99u64))
            .unwrap();
        assert!(matches!(
            resolve(&token).unwrap().dispatch(
                storage,
                &ExecutionScope::new(),
                None,
                class_call(token, &call.abi_encode()),
            ),
            Err(PrecompileError::Fatal(message)) if message.contains("identity does not match")
        ));
    }
}
