use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::{SolError, SolValue};
use outbe_primitives::error::PrecompileError;
use thiserror::Error;

use crate::abi::IStablecoin;

#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum StablecoinStateError {
    #[error("unexpected value {value}")]
    UnexpectedValue { value: U256 },

    #[error("stablecoin token is not initialized")]
    Uninitialized,

    #[error("stablecoin token is already initialized")]
    AlreadyInitialized,

    #[error("invalid stablecoin initialization identity")]
    InvalidInitializationIdentity,

    #[error("unknown stablecoin initialization policy {policy_id}")]
    UnknownInitializationPolicy { policy_id: U256 },

    #[error(
        "stablecoin migration required from schema {stored_schema_version} to {active_schema_version}"
    )]
    MigrationRequired {
        stored_schema_version: u64,
        active_schema_version: u64,
    },

    #[error("stablecoin initialization found non-pristine root slot {slot}")]
    NonPristineRoot { slot: u64 },

    #[error("invalid stablecoin address {account}")]
    InvalidAddress { account: Address },

    #[error("stablecoin amount must be non-zero")]
    InvalidAmount,

    #[error(
        "insufficient stablecoin balance for {account}: available {available}, required {required}"
    )]
    InsufficientBalance {
        account: Address,
        available: U256,
        required: U256,
    },

    #[error(
        "insufficient stablecoin allowance from {owner} to {spender}: available {available}, required {required}"
    )]
    InsufficientAllowance {
        owner: Address,
        spender: Address,
        available: U256,
        required: U256,
    },

    #[error(
        "stablecoin supply cap {supply_cap} would be exceeded by requested supply {requested_supply}"
    )]
    SupplyCapExceeded {
        supply_cap: U256,
        requested_supply: U256,
    },

    #[error("caller {caller} does not hold stablecoin role {role}")]
    Unauthorized { role: B256, caller: Address },

    #[error("unsupported stablecoin role {role}")]
    UnsupportedRole { role: B256 },

    #[error("stablecoin token is paused")]
    TokenPaused,

    #[error("stablecoin token is not paused")]
    TokenNotPaused,

    #[error(
        "requested stablecoin supply cap {requested_cap} is below total supply {total_supply}"
    )]
    SupplyCapBelowSupply {
        requested_cap: U256,
        total_supply: U256,
    },

    #[error("invalid pending stablecoin admin {candidate}")]
    InvalidPendingAdmin { candidate: Address },

    #[error("caller {caller} is not the pending stablecoin admin")]
    NotPendingAdmin { caller: Address },

    #[error("unknown stablecoin policy {policy_id}")]
    UnknownPolicy { policy_id: U256 },

    #[error("stablecoin policy {policy_id} denied operation {operation} for account {account}")]
    PolicyDenied {
        policy_id: U256,
        account: Address,
        operation: u8,
    },

    #[error("ERC-7943 cannot send from {account}")]
    ERC7943CannotSend { account: Address },

    #[error("ERC-7943 cannot receive to {account}")]
    ERC7943CannotReceive { account: Address },

    #[error("ERC-7943 cannot transfer {amount} from {from} to {to}")]
    ERC7943CannotTransfer {
        from: Address,
        to: Address,
        amount: U256,
    },

    #[error("ERC-7943 unfrozen balance for {account} is {unfrozen}, less than requested {amount}")]
    ERC7943InsufficientUnfrozenBalance {
        account: Address,
        amount: U256,
        unfrozen: U256,
    },

    #[error(
        "frozen owner {owner} cannot increase allowance from {current_allowance} to {requested_allowance}"
    )]
    FrozenAllowanceIncrease {
        owner: Address,
        current_allowance: U256,
        requested_allowance: U256,
    },

    #[error("forced self-transfer is forbidden")]
    ForcedSelfTransfer,

    #[error("stablecoin permit expired at deadline {deadline}")]
    PermitExpired { deadline: U256 },

    #[error("invalid stablecoin permit signature")]
    InvalidPermitSignature,
}

impl From<StablecoinStateError> for PrecompileError {
    fn from(error: StablecoinStateError) -> Self {
        match error {
            StablecoinStateError::UnexpectedValue { value } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::UnexpectedValue { value }.abi_encode()),
            ),
            StablecoinStateError::MigrationRequired {
                stored_schema_version,
                active_schema_version,
            } => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::MigrationRequired {
                    storedSchemaVersion: stored_schema_version,
                    activeSchemaVersion: active_schema_version,
                }
                .abi_encode(),
            )),
            fatal @ (StablecoinStateError::AlreadyInitialized
            | StablecoinStateError::NonPristineRoot { .. }) => {
                PrecompileError::Fatal(fatal.to_string())
            }
            StablecoinStateError::InvalidAddress { account } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::InvalidAddress { account }.abi_encode()),
            ),
            StablecoinStateError::InvalidAmount => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::InvalidAmount {}.abi_encode(),
            )),
            StablecoinStateError::InsufficientBalance {
                account,
                available,
                required,
            } => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::InsufficientBalance {
                    account,
                    available,
                    required,
                }
                .abi_encode(),
            )),
            StablecoinStateError::InsufficientAllowance {
                owner,
                spender,
                available,
                required,
            } => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::InsufficientAllowance {
                    owner,
                    spender,
                    available,
                    required,
                }
                .abi_encode(),
            )),
            StablecoinStateError::SupplyCapExceeded {
                supply_cap,
                requested_supply,
            } => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::SupplyCapExceeded {
                    supplyCap: supply_cap,
                    requestedSupply: requested_supply,
                }
                .abi_encode(),
            )),
            StablecoinStateError::Unauthorized { role, caller } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::Unauthorized { role, caller }.abi_encode()),
            ),
            StablecoinStateError::UnsupportedRole { role } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::UnsupportedRole { role }.abi_encode()),
            ),
            StablecoinStateError::TokenPaused => {
                PrecompileError::RevertBytes(Bytes::from(IStablecoin::TokenPaused {}.abi_encode()))
            }
            StablecoinStateError::TokenNotPaused => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::TokenNotPaused {}.abi_encode(),
            )),
            StablecoinStateError::SupplyCapBelowSupply {
                requested_cap,
                total_supply,
            } => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::SupplyCapBelowSupply {
                    requestedCap: requested_cap,
                    totalSupply: total_supply,
                }
                .abi_encode(),
            )),
            StablecoinStateError::InvalidPendingAdmin { candidate } => {
                PrecompileError::RevertBytes(Bytes::from(
                    IStablecoin::InvalidPendingAdmin { candidate }.abi_encode(),
                ))
            }
            StablecoinStateError::NotPendingAdmin { caller } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::NotPendingAdmin { caller }.abi_encode()),
            ),
            StablecoinStateError::UnknownPolicy { policy_id } => {
                PrecompileError::RevertBytes(Bytes::from(
                    IStablecoin::UnknownPolicy {
                        policyId: policy_id,
                    }
                    .abi_encode(),
                ))
            }
            StablecoinStateError::PolicyDenied {
                policy_id,
                account,
                operation,
            } => {
                let mut encoded = IStablecoin::PolicyDenied::SELECTOR.to_vec();
                encoded.extend((policy_id, account, U256::from(operation)).abi_encode_params());
                PrecompileError::RevertBytes(Bytes::from(encoded))
            }
            StablecoinStateError::ERC7943CannotSend { account } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::ERC7943CannotSend { account }.abi_encode()),
            ),
            StablecoinStateError::ERC7943CannotReceive { account } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::ERC7943CannotReceive { account }.abi_encode()),
            ),
            StablecoinStateError::ERC7943CannotTransfer { from, to, amount } => {
                PrecompileError::RevertBytes(Bytes::from(
                    IStablecoin::ERC7943CannotTransfer { from, to, amount }.abi_encode(),
                ))
            }
            StablecoinStateError::ERC7943InsufficientUnfrozenBalance {
                account,
                amount,
                unfrozen,
            } => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::ERC7943InsufficientUnfrozenBalance {
                    account,
                    amount,
                    unfrozen,
                }
                .abi_encode(),
            )),
            StablecoinStateError::FrozenAllowanceIncrease {
                owner,
                current_allowance,
                requested_allowance,
            } => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::FrozenAllowanceIncrease {
                    owner,
                    currentAllowance: current_allowance,
                    requestedAllowance: requested_allowance,
                }
                .abi_encode(),
            )),
            StablecoinStateError::ForcedSelfTransfer => PrecompileError::RevertBytes(Bytes::from(
                IStablecoin::ForcedSelfTransfer {}.abi_encode(),
            )),
            StablecoinStateError::PermitExpired { deadline } => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::PermitExpired { deadline }.abi_encode()),
            ),
            StablecoinStateError::InvalidPermitSignature => PrecompileError::RevertBytes(
                Bytes::from(IStablecoin::InvalidPermitSignature {}.abi_encode()),
            ),
            domain_error => PrecompileError::Revert(domain_error.to_string()),
        }
    }
}
