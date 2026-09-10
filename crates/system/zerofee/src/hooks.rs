use alloy_primitives::{Address, U256};
use outbe_primitives::{error::PrecompileError, storage::StorageHandle};

use crate::intexfactory::IntexFactoryPayContributorBatchHook;
use crate::oracle::OracleSubmitVoteHook;

/// A minimal, execution-layer independent transaction view for zero-fee hooks.
#[derive(Debug, Clone, Copy)]
pub struct ZeroFeeTransaction<'a> {
    /// Recovered signer of the signed EVM transaction.
    pub signer: Address,
    /// Call target. Contract creation transactions are represented as `None`.
    pub to: Option<Address>,
    /// Native value attached to the transaction.
    pub value: U256,
    /// ABI calldata bytes.
    pub input: &'a [u8],
    /// Transaction gas limit.
    pub gas_limit: u64,
    /// EIP-1559 max fee per gas.
    pub max_fee_per_gas: u128,
    /// EIP-1559 priority fee per gas, if present.
    pub max_priority_fee_per_gas: Option<u128>,
}

/// Stable identifier for a registered zero-fee hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroFeeHookId {
    /// `Oracle.submitVote(ExchangeRateTuple[])`.
    OracleSubmitVote,
    /// `IntexFactory.payContributorBatch(uint32,uint32,ContributorLeaf[],bytes32[])`.
    IntexFactoryPayContributorBatch,
}

/// A transaction that matched a hook's stateless zero-fee envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroFeeCandidate {
    /// Matching hook.
    pub hook: ZeroFeeHookId,
    /// Recovered transaction signer.
    pub signer: Address,
}

impl ZeroFeeCandidate {
    /// Creates a zero-fee candidate for a matching hook.
    pub const fn new(hook: ZeroFeeHookId, signer: Address) -> Self {
        Self { hook, signer }
    }
}

/// Stateful authorization outcome for a fee waiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroFeeAuthorization {
    /// Hook that authorized the fee waiver.
    pub hook: ZeroFeeHookId,
    /// Hook-specific account represented by the signer.
    ///
    /// For oracle votes this is the validator address, not necessarily the
    /// feeder address that signed the transaction.
    pub subject: Address,
}

/// Zero-fee policy rejection reason.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ZeroFeePolicyError {
    /// The zero-fee envelope targets an unknown hook.
    #[error("unknown zero-fee hook: {0:?}")]
    UnknownHook(ZeroFeeHookId),
    /// The transaction targets a zero-fee method but carries native value.
    #[error("zero-fee transaction must not transfer native value")]
    NonZeroValue,
    /// The transaction calldata exceeds the policy limit.
    #[error("zero-fee calldata size {size} exceeds limit {limit}")]
    CalldataTooLarge {
        /// Actual calldata size.
        size: usize,
        /// Maximum accepted calldata size.
        limit: usize,
    },
    /// The transaction gas limit exceeds the policy limit.
    #[error("zero-fee gas limit {gas_limit} exceeds limit {limit}")]
    GasLimitTooHigh {
        /// Actual gas limit.
        gas_limit: u64,
        /// Maximum accepted gas limit.
        limit: u64,
    },
    /// The transaction's fee cap is below the public txpool protocol minimum.
    #[error("zero-fee max_fee_per_gas {max_fee_per_gas} is below protocol minimum {minimum}")]
    FeeCapTooLow {
        /// Transaction max fee cap.
        max_fee_per_gas: u128,
        /// Minimum accepted fee cap.
        minimum: u128,
    },
    /// The transaction selector matched, but ABI decoding failed.
    #[error("zero-fee oracle vote calldata is malformed: {0}")]
    MalformedCalldata(String),
    /// The signer is not authorized to use this zero-fee policy.
    #[error("zero-fee signer is not authorized for this transaction hook")]
    UnauthorizedSigner,
    /// The represented validator already submitted an oracle vote this period.
    #[error("zero-fee oracle vote already exists for validator")]
    AlreadyVoted,
    /// Stateful precompile storage read failed.
    #[error("zero-fee policy storage read failed: {0}")]
    Storage(String),
    /// The signer has already burned today's free-tx quota.
    #[error("free-tx daily quota exhausted: used {used} of {limit}")]
    FreeTxDailyExhausted {
        /// Effective count already recorded for today.
        used: u32,
        /// Daily limit.
        limit: u32,
    },
    /// Contract creation is not allowed through the free-tx path.
    #[error("free-tx must not be a contract creation")]
    FreeTxDailyContractCreationForbidden,
    /// The sponsored tx envelope carries non-zero native value. Mirrors
    /// the generic 102 `NonZeroValue` but gives off-chain integrators a
    /// free-tx-specific code so wallets can present a clearer error.
    #[error("free-tx must not transfer native value")]
    FreeTxDailyValueNotZero,
    /// The sponsored tx envelope exceeds the free-tx gas limit.
    #[error("free-tx gas limit {gas_limit} exceeds free-tx limit {limit}")]
    FreeTxDailyGasLimitExceeded {
        /// Actual gas limit on the tx.
        gas_limit: u64,
        /// Sponsored-path maximum from `FREE_TX_DAILY_GAS_LIMIT`.
        limit: u64,
    },
    /// The sponsored tx envelope exceeds the free-tx calldata cap.
    #[error("free-tx calldata size {size} exceeds free-tx limit {limit}")]
    FreeTxDailyCalldataTooLarge {
        /// Actual calldata size.
        size: usize,
        /// Sponsored-path maximum from `FREE_TX_DAILY_CALLDATA_BYTES`.
        limit: usize,
    },
    /// The transaction target is not in the protocol-defined whitelist
    /// of outbe precompile addresses.
    #[error("free-tx target {to:?} is not a whitelisted precompile address")]
    FreeTxDailyTargetNotWhitelisted {
        /// Attempted call target.
        to: Address,
    },
}

impl From<PrecompileError> for ZeroFeePolicyError {
    fn from(value: PrecompileError) -> Self {
        Self::Storage(value.to_string())
    }
}

impl ZeroFeePolicyError {
    /// Stable numeric code emitted in the `OutbeFailure(code, reason)` log
    /// when the executor converts a zero-fee policy rejection into a
    /// `status=0` receipt. Codes occupy the `100..=199` band reserved for
    /// `outbe-zerofee` failure reasons (`crate::ZERO_FEE_POLICY_LOG_ADDRESS`).
    ///
    /// The values are part of the on-chain encoding and must not be
    /// reordered or reused after they ship; the match is exhaustive so
    /// adding a new variant is a compile error until a code is allocated.
    pub const fn code(&self) -> u16 {
        match self {
            Self::UnknownHook(_) => 101,
            Self::NonZeroValue => 102,
            Self::CalldataTooLarge { .. } => 103,
            Self::GasLimitTooHigh { .. } => 104,
            Self::FeeCapTooLow { .. } => 105,
            Self::MalformedCalldata(_) => 106,
            Self::UnauthorizedSigner => 107,
            Self::AlreadyVoted => 108,
            Self::Storage(_) => 109,
            Self::FreeTxDailyExhausted { .. } => 110,
            Self::FreeTxDailyContractCreationForbidden => 112,
            Self::FreeTxDailyValueNotZero => 113,
            Self::FreeTxDailyGasLimitExceeded { .. } => 114,
            Self::FreeTxDailyCalldataTooLarge { .. } => 115,
            Self::FreeTxDailyTargetNotWhitelisted { .. } => 116,
        }
    }
}

#[cfg(test)]
mod failure_code_tests {
    use super::*;

    fn all_variants() -> Vec<ZeroFeePolicyError> {
        vec![
            ZeroFeePolicyError::UnknownHook(ZeroFeeHookId::OracleSubmitVote),
            ZeroFeePolicyError::NonZeroValue,
            ZeroFeePolicyError::CalldataTooLarge { size: 0, limit: 0 },
            ZeroFeePolicyError::GasLimitTooHigh {
                gas_limit: 0,
                limit: 0,
            },
            ZeroFeePolicyError::FeeCapTooLow {
                max_fee_per_gas: 0,
                minimum: 0,
            },
            ZeroFeePolicyError::MalformedCalldata(String::new()),
            ZeroFeePolicyError::UnauthorizedSigner,
            ZeroFeePolicyError::AlreadyVoted,
            ZeroFeePolicyError::Storage(String::new()),
            ZeroFeePolicyError::FreeTxDailyExhausted { used: 0, limit: 0 },
            ZeroFeePolicyError::FreeTxDailyContractCreationForbidden,
            ZeroFeePolicyError::FreeTxDailyValueNotZero,
            ZeroFeePolicyError::FreeTxDailyGasLimitExceeded {
                gas_limit: 0,
                limit: 0,
            },
            ZeroFeePolicyError::FreeTxDailyCalldataTooLarge { size: 0, limit: 0 },
            ZeroFeePolicyError::FreeTxDailyTargetNotWhitelisted { to: Address::ZERO },
        ]
    }

    #[test]
    fn codes_are_in_zero_fee_band() {
        for err in all_variants() {
            let code = err.code();
            assert!(
                (100..=199).contains(&code),
                "code {code} for {err:?} outside the zero-fee band 100..=199"
            );
        }
    }

    #[test]
    fn codes_are_pairwise_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for err in all_variants() {
            let code = err.code();
            assert!(
                seen.insert(code),
                "duplicate ZeroFeePolicyError code {code}"
            );
        }
    }

    #[test]
    fn unauthorized_signer_reason_is_hook_neutral() {
        assert_eq!(
            ZeroFeePolicyError::UnauthorizedSigner.to_string(),
            "zero-fee signer is not authorized for this transaction hook"
        );
    }

    #[test]
    fn ocomp_result_vote_selector_is_not_owned_by_zero_fee_policy() {
        let tx = ZeroFeeTransaction {
            signer: Address::repeat_byte(0x11),
            to: Some(outbe_ocomp_protocol::abi::METADOSIS_ADDRESS),
            value: U256::ZERO,
            input: &outbe_ocomp_protocol::abi::SUBMIT_LYSIS_RESULT_SELECTOR,
            gas_limit: 30_000,
            max_fee_per_gas: u128::MAX,
            max_priority_fee_per_gas: Some(0),
        };

        assert_eq!(registry().classify(&tx).unwrap(), None);
    }
}

/// A deterministic hook that can waive native fee debit for a transaction class.
pub trait ZeroFeeHook: Sync {
    /// Stable hook identifier.
    fn id(&self) -> ZeroFeeHookId;

    /// Matches the stateless transaction envelope.
    ///
    /// `Ok(None)` means this hook does not own the transaction and normal fee
    /// rules should be used. `Ok(Some(_))` means the transaction explicitly asks
    /// this hook for a zero-fee waiver and must pass stateful authorization.
    fn classify(
        &self,
        tx: &ZeroFeeTransaction<'_>,
    ) -> Result<Option<ZeroFeeCandidate>, ZeroFeePolicyError>;

    /// Performs stateful authorization for a candidate matched by `classify`.
    ///
    /// Returning `Ok(_)` means native fee debit may be waived for this exact
    /// transaction class. Returning `Err(_)` rejects the zero-fee attempt.
    fn authorize_fee_waiver(
        &self,
        storage: StorageHandle,
        candidate: ZeroFeeCandidate,
    ) -> Result<ZeroFeeAuthorization, ZeroFeePolicyError>;
}

/// Registered zero-fee hook registry.
#[derive(Clone, Copy)]
pub struct ZeroFeeRegistry {
    hooks: &'static [&'static dyn ZeroFeeHook],
}

impl ZeroFeeRegistry {
    /// Creates a registry over a static hook list.
    pub const fn new(hooks: &'static [&'static dyn ZeroFeeHook]) -> Self {
        Self { hooks }
    }

    /// Classifies a transaction against registered hooks.
    pub fn classify(
        self,
        tx: &ZeroFeeTransaction<'_>,
    ) -> Result<Option<ZeroFeeCandidate>, ZeroFeePolicyError> {
        for hook in self.hooks {
            if let Some(candidate) = hook.classify(tx)? {
                return Ok(Some(candidate));
            }
        }

        Ok(None)
    }

    /// Runs the stateful hook for a zero-fee candidate.
    pub fn authorize_fee_waiver(
        self,
        storage: StorageHandle,
        candidate: ZeroFeeCandidate,
    ) -> Result<ZeroFeeAuthorization, ZeroFeePolicyError> {
        for hook in self.hooks {
            if hook.id() == candidate.hook {
                return hook.authorize_fee_waiver(storage, candidate);
            }
        }

        Err(ZeroFeePolicyError::UnknownHook(candidate.hook))
    }
}

static ORACLE_SUBMIT_VOTE_HOOK: OracleSubmitVoteHook = OracleSubmitVoteHook;
static INTEX_FACTORY_PAY_CONTRIBUTOR_BATCH_HOOK: IntexFactoryPayContributorBatchHook =
    IntexFactoryPayContributorBatchHook;
static ZERO_FEE_HOOKS: &[&dyn ZeroFeeHook] = &[
    &ORACLE_SUBMIT_VOTE_HOOK,
    &INTEX_FACTORY_PAY_CONTRIBUTOR_BATCH_HOOK,
];

/// Returns the Outbe system zero-fee hook registry.
pub const fn registry() -> ZeroFeeRegistry {
    ZeroFeeRegistry::new(ZERO_FEE_HOOKS)
}
