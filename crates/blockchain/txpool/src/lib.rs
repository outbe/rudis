//! Outbe transaction pool builder.
//!
//! The pool keeps standard Reth validation and adds deterministic ZeroFee
//! guards for whitelisted validator transactions.

pub mod maintain;

use alloy_eips::{eip7840::BlobParams, merge::EPOCH_SLOTS};
use alloy_primitives::{Address, B256, KECCAK256_EMPTY, U256};
use outbe_ocomp_protocol::system_carrier::{
    classify_ocomp_system_carrier, OcompSystemCarrierCandidate, OcompSystemCarrierError,
    OcompSystemCarrierView,
};
use outbe_primitives::{
    addresses::OUTBE_SYSTEM_TX_ADDRESS,
    storage::{
        readonly::{ReadOnlyStorageProvider, StorageReader},
        StorageHandle,
    },
    system_tx::OcompLifecycleActivation,
    OutbePrimitives,
};
use outbe_zerofee::{BootstrapTransactionView, ZeroFeeHookId, ZeroFeeTransaction};
use reth_chainspec::{ChainSpecProvider, EthChainSpec, EthereumHardforks};
use reth_evm::ConfigureEvm;
use reth_node_builder::{
    components::{PoolBuilder, TxPoolBuilder},
    node::{FullNodeTypes, NodeTypes},
    BuilderContext,
};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use reth_storage_api::{BlockNumReader, StateProvider, StateProviderFactory};
use reth_transaction_pool::{
    blobstore::DiskFileBlobStore,
    error::{InvalidPoolTransactionError, PoolTransactionError},
    validate::ValidTransaction,
    EthPoolTransaction, EthTransactionValidator, Pool, PoolTransaction, Priority,
    TransactionOrdering, TransactionOrigin, TransactionValidationOutcome,
    TransactionValidationTaskExecutor, TransactionValidator,
};
use std::{any::Any, fmt, marker::PhantomData, time::SystemTime};

fn is_reserved_system_tx<T>(tx: &T) -> bool
where
    T: alloy_consensus::Transaction + ?Sized,
{
    tx.to() == Some(OUTBE_SYSTEM_TX_ADDRESS)
}

fn zero_fee_transaction<'a, T>(tx: &'a T, signer: Address) -> ZeroFeeTransaction<'a>
where
    T: alloy_consensus::Transaction + ?Sized,
{
    ZeroFeeTransaction {
        signer,
        to: tx.to(),
        value: tx.value(),
        input: tx.input().as_ref(),
        gas_limit: tx.gas_limit(),
        max_fee_per_gas: tx.max_fee_per_gas(),
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
    }
}

fn bootstrap_transaction<'a, T>(
    tx: &'a T,
    signer: Address,
    network_chain_id: u64,
) -> Option<BootstrapTransactionView<'a>>
where
    T: alloy_consensus::Transaction + ?Sized,
{
    let authorization_list = tx.authorization_list()?;
    Some(BootstrapTransactionView {
        signer,
        tx_chain_id: tx.chain_id(),
        network_chain_id,
        nonce: tx.nonce(),
        to: tx.to(),
        value: tx.value(),
        input: tx.input().as_ref(),
        gas_limit: tx.gas_limit(),
        max_fee_per_gas: tx.max_fee_per_gas(),
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
        access_list_empty: tx.access_list().is_some_and(|list| list.is_empty()),
        authorization_list,
    })
}

fn classify_ocomp_carrier<T>(
    tx: &T,
) -> Result<Option<OcompSystemCarrierCandidate>, OcompSystemCarrierError>
where
    T: alloy_consensus::Transaction + ?Sized,
{
    classify_ocomp_system_carrier(
        OcompSystemCarrierView {
            is_eip1559: tx.ty() == alloy_consensus::TxType::Eip1559 as u8,
            to: tx.to(),
            value: tx.value(),
            input: tx.input().as_ref(),
            gas_limit: tx.gas_limit(),
            max_fee_per_gas: tx.max_fee_per_gas(),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
        },
        &outbe_ocomp_protocol::profile::poc_schema_limits(),
    )
}

/// Returns a reserved priority class for zero-fee hooks that must outrank the
/// normal tip market. Keep this match exhaustive so every new hook makes an
/// explicit ordering decision.
fn zero_fee_priority_class(hook: ZeroFeeHookId) -> Option<u8> {
    match hook {
        ZeroFeeHookId::OracleSubmitVote => Some(1),
        ZeroFeeHookId::IntexFactoryPayContributorBatch => Some(1),
    }
}

/// Outbe pool type with guarded ZeroFee validation.
pub type OutbeTransactionPool<Client, S, Evm, T = reth_transaction_pool::EthPooledTransaction> =
    Pool<
        TransactionValidationTaskExecutor<OutbeTransactionValidator<Client, T, Evm>>,
        OutbeTransactionOrdering<T>,
        S,
    >;

/// Orders hook-approved ZeroFee transactions ahead of the normal tip market.
#[derive(Debug)]
pub struct OutbeTransactionOrdering<T>(PhantomData<T>);

impl<T> Clone for OutbeTransactionOrdering<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OutbeTransactionOrdering<T> {}

impl<T> Default for OutbeTransactionOrdering<T> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<T> TransactionOrdering for OutbeTransactionOrdering<T>
where
    T: PoolTransaction + 'static,
{
    type PriorityValue = (u8, u128);
    type Transaction = T;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        let zero_fee_tx = zero_fee_transaction(transaction, transaction.sender());
        let normal_priority = || {
            transaction
                .effective_tip_per_gas(base_fee)
                .map(|tip| (0, tip))
                .into()
        };

        match classify_ocomp_carrier(transaction) {
            Ok(Some(_)) => return Priority::Value((2, 0)),
            Err(_) => return Priority::None,
            Ok(None) => {}
        }

        match outbe_zerofee::registry().classify(&zero_fee_tx) {
            Ok(Some(candidate)) => zero_fee_priority_class(candidate.hook)
                .map(|priority_class| Priority::Value((priority_class, 0)))
                .unwrap_or_else(normal_priority),
            Ok(None) => normal_priority(),
            Err(_) => Priority::None,
        }
    }
}

/// Builds the transaction pool used by Outbe nodes.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutbePoolBuilder {
    ocomp_lifecycle_activation: OcompLifecycleActivation,
}

impl OutbePoolBuilder {
    #[must_use]
    pub const fn with_ocomp_lifecycle_activation(
        mut self,
        activation: OcompLifecycleActivation,
    ) -> Self {
        self.ocomp_lifecycle_activation = activation;
        self
    }
}

impl<Types, Node, Evm> PoolBuilder<Node, Evm> for OutbePoolBuilder
where
    Types: NodeTypes<ChainSpec: EthChainSpec + EthereumHardforks, Primitives = OutbePrimitives>,
    Node: FullNodeTypes<Types = Types>,
    Evm: ConfigureEvm<Primitives = OutbePrimitives> + Clone + 'static,
{
    type Pool = OutbeTransactionPool<Node::Provider, DiskFileBlobStore, Evm>;

    async fn build_pool(
        self,
        ctx: &BuilderContext<Node>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let pool_config = ctx.pool_config();

        let blobs_disabled = ctx.config().txpool.disable_blobs_support
            || ctx.config().txpool.blobpool_max_count == 0;

        let blob_cache_size = if let Some(blob_cache_size) = pool_config.blob_cache_size {
            Some(blob_cache_size)
        } else {
            let current_timestamp = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();
            let blob_params = ctx
                .chain_spec()
                .blob_params_at_timestamp(current_timestamp)
                .unwrap_or_else(BlobParams::cancun);

            Some((blob_params.target_blob_count * EPOCH_SLOTS * 2) as u32)
        };

        let blob_store =
            reth_node_builder::components::create_blob_store_with_cache(ctx, blob_cache_size)?;

        let validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .set_eip4844(!blobs_disabled)
                .kzg_settings(ctx.kzg_settings()?)
                .with_max_tx_input_bytes(ctx.config().txpool.max_tx_input_bytes)
                .with_local_transactions_config(pool_config.local_transactions_config.clone())
                .set_tx_fee_cap(ctx.config().rpc.rpc_tx_fee_cap)
                .with_max_tx_gas_limit(ctx.config().txpool.max_tx_gas_limit)
                .with_minimum_priority_fee(ctx.config().txpool.minimum_priority_fee)
                .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
                .disable_balance_check()
                .build_with_tasks(ctx.task_executor().clone(), blob_store.clone())
                .map(|inner| {
                    OutbeTransactionValidator::new(inner, self.ocomp_lifecycle_activation)
                });

        if validator.validator().inner().eip4844() {
            let kzg_settings = validator.validator().inner().kzg_settings().clone();
            ctx.task_executor().spawn_blocking_task(async move {
                let _ = kzg_settings.get();
                tracing::debug!(target: "reth::cli", "Initialized KZG settings");
            });
        }

        let transaction_pool = TxPoolBuilder::new(ctx)
            .with_validator(validator)
            .build_with_ordering_and_spawn_maintenance_task(
                OutbeTransactionOrdering::default(),
                blob_store,
                pool_config,
            )?;

        tracing::info!(target: "reth::cli", "Outbe transaction pool initialized");
        tracing::debug!(target: "reth::cli", "Spawned txpool maintenance task");

        Ok(transaction_pool)
    }
}

#[derive(Debug)]
struct ValidOutcomeParts<T: reth_transaction_pool::PoolTransaction> {
    balance: U256,
    state_nonce: u64,
    bytecode_hash: Option<B256>,
    transaction: ValidTransaction<T>,
    propagate: bool,
    authorities: Option<Vec<Address>>,
}

#[derive(Debug)]
enum ValidOutcomeSplit<T: reth_transaction_pool::PoolTransaction> {
    Valid(ValidOutcomeParts<T>),
    Other(TransactionValidationOutcome<T>),
}

fn take_valid_outcome<T>(outcome: TransactionValidationOutcome<T>) -> ValidOutcomeSplit<T>
where
    T: reth_transaction_pool::PoolTransaction,
{
    let TransactionValidationOutcome::Valid {
        balance,
        state_nonce,
        bytecode_hash,
        transaction,
        propagate,
        authorities,
    } = outcome
    else {
        return ValidOutcomeSplit::Other(outcome);
    };

    ValidOutcomeSplit::Valid(ValidOutcomeParts {
        balance,
        state_nonce,
        bytecode_hash,
        transaction,
        propagate,
        authorities,
    })
}

fn valid_outcome<T>(parts: ValidOutcomeParts<T>) -> TransactionValidationOutcome<T>
where
    T: reth_transaction_pool::PoolTransaction,
{
    TransactionValidationOutcome::Valid {
        balance: parts.balance,
        state_nonce: parts.state_nonce,
        bytecode_hash: parts.bytecode_hash,
        transaction: parts.transaction,
        propagate: parts.propagate,
        authorities: parts.authorities,
    }
}

#[derive(Debug)]
enum ReservedSystemTxPolicy<T: reth_transaction_pool::PoolTransaction> {
    Continue(ValidOutcomeParts<T>),
    Reject(TransactionValidationOutcome<T>),
}

fn reject_reserved_system_tx_outcome<T>(parts: ValidOutcomeParts<T>) -> ReservedSystemTxPolicy<T>
where
    T: EthPoolTransaction + alloy_consensus::Transaction,
{
    if is_reserved_system_tx(parts.transaction.transaction()) {
        return ReservedSystemTxPolicy::Reject(TransactionValidationOutcome::Invalid(
            parts.transaction.into_transaction(),
            InvalidPoolTransactionError::other(OutbeReservedSystemTxPoolError),
        ));
    }
    ReservedSystemTxPolicy::Continue(parts)
}

/// Transaction validator that keeps reth's Ethereum checks and adds Outbe policy.
pub struct OutbeTransactionValidator<Client, Tx, Evm> {
    inner: EthTransactionValidator<Client, Tx, Evm>,
    ocomp_lifecycle_activation: OcompLifecycleActivation,
}

impl<Client, Tx, Evm> OutbeTransactionValidator<Client, Tx, Evm> {
    fn new(
        inner: EthTransactionValidator<Client, Tx, Evm>,
        ocomp_lifecycle_activation: OcompLifecycleActivation,
    ) -> Self {
        Self {
            inner,
            ocomp_lifecycle_activation,
        }
    }

    fn inner(&self) -> &EthTransactionValidator<Client, Tx, Evm> {
        &self.inner
    }
}

impl<Client, Tx, Evm> fmt::Debug for OutbeTransactionValidator<Client, Tx, Evm>
where
    EthTransactionValidator<Client, Tx, Evm>: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutbeTransactionValidator")
            .field("inner", &self.inner)
            .field(
                "ocomp_lifecycle_activation",
                &self.ocomp_lifecycle_activation,
            )
            .finish()
    }
}

impl<Client, Tx, Evm> TransactionValidator for OutbeTransactionValidator<Client, Tx, Evm>
where
    EthTransactionValidator<Client, Tx, Evm>: TransactionValidator<Transaction = Tx>,
    Client: StateProviderFactory
        + BlockNumReader
        + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>,
    Tx: EthPoolTransaction + alloy_consensus::Transaction,
    Evm: ConfigureEvm,
{
    type Transaction = Tx;
    type Block = <EthTransactionValidator<Client, Tx, Evm> as TransactionValidator>::Block;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        match classify_ocomp_carrier(&transaction) {
            Ok(Some(candidate)) => {
                return self.validate_ocomp_system_carrier(origin, transaction, candidate)
            }
            Err(error) => {
                return TransactionValidationOutcome::Invalid(
                    transaction,
                    InvalidPoolTransactionError::other(OutbeOcompSystemCarrierPoolError(
                        error.to_string(),
                    )),
                )
            }
            Ok(None) => {}
        }
        let outcome = self.inner.validate_transaction(origin, transaction).await;
        self.apply_outbe_policy(outcome)
    }

    fn on_new_head_block(&self, new_tip_block: &reth_primitives_traits::SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_tip_block);
    }
}

impl<Client, Tx, Evm> OutbeTransactionValidator<Client, Tx, Evm>
where
    Client: StateProviderFactory
        + BlockNumReader
        + ChainSpecProvider<ChainSpec: EthChainSpec + EthereumHardforks>,
    Tx: EthPoolTransaction + alloy_consensus::Transaction,
    Evm: ConfigureEvm,
{
    fn validate_ocomp_system_carrier(
        &self,
        origin: TransactionOrigin,
        transaction: Tx,
        candidate: OcompSystemCarrierCandidate,
    ) -> TransactionValidationOutcome<Tx> {
        let invalid = |transaction, reason: String| {
            TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::other(OutbeOcompSystemCarrierPoolError(reason)),
            )
        };
        let best_block = match self.inner.client().best_block_number() {
            Ok(number) => number,
            Err(error) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(error))
            }
        };
        let Some(next_block) = best_block.checked_add(1) else {
            return invalid(
                transaction,
                "OCOMP carrier next block height overflow".to_owned(),
            );
        };
        if !self.ocomp_lifecycle_activation.is_active_at(next_block) {
            return invalid(
                transaction,
                format!("OCOMP system carrier is not active at next block {next_block}"),
            );
        }
        if !self.inner.eip1559() {
            return invalid(
                transaction,
                "EIP-1559 is not active for the OCOMP system carrier".to_owned(),
            );
        }
        if transaction.nonce() == u64::MAX {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::Eip2681,
            );
        }
        let encoded_length = transaction.encoded_length();
        if encoded_length > self.inner.max_tx_input_bytes() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::OversizedData {
                    size: encoded_length,
                    limit: self.inner.max_tx_input_bytes(),
                },
            );
        }
        let gas_limit = transaction.gas_limit();
        if gas_limit > self.inner.block_gas_limit() {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidPoolTransactionError::ExceedsGasLimit(
                    gas_limit,
                    self.inner.block_gas_limit(),
                ),
            );
        }
        if transaction.chain_id() != Some(self.inner.chain_id()) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::ChainIdMismatch.into(),
            );
        }
        let is_local = self
            .inner
            .local_transactions_config()
            .is_local(origin, transaction.sender_ref());
        if is_local {
            if let Some(tx_fee_cap_wei) = *self.inner.tx_fee_cap() {
                if tx_fee_cap_wei != 0 {
                    let max_tx_fee_wei = transaction.cost().saturating_sub(transaction.value());
                    if max_tx_fee_wei > tx_fee_cap_wei {
                        return TransactionValidationOutcome::Invalid(
                            transaction,
                            InvalidPoolTransactionError::ExceedsFeeCap {
                                max_tx_fee_wei: max_tx_fee_wei.saturating_to(),
                                tx_fee_cap_wei,
                            },
                        );
                    }
                }
            }
        }

        let state = match self.inner.client().latest() {
            Ok(state) => state,
            Err(error) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(error))
            }
        };
        let account = match state.basic_account(transaction.sender_ref()) {
            Ok(account) => account.unwrap_or_default(),
            Err(error) => {
                return TransactionValidationOutcome::Error(*transaction.hash(), Box::new(error))
            }
        };
        match self
            .inner
            .validate_sender_bytecode(&transaction, &account, &state)
        {
            Err(outcome) => return outcome,
            Ok(Err(error)) => return TransactionValidationOutcome::Invalid(transaction, error),
            Ok(Ok(())) => {}
        }
        if transaction.requires_nonce_check() {
            if let Err(error) = self.inner.validate_sender_nonce(&transaction, &account) {
                return TransactionValidationOutcome::Invalid(transaction, error);
            }
        }

        let authorization = {
            let reader = RethStateReader { state: &state };
            let mut provider = ReadOnlyStorageProvider::new(reader);
            let storage = StorageHandle::new(&mut provider);
            match candidate {
                OcompSystemCarrierCandidate::ResultVote { prefix } => {
                    outbe_metadosis::resolve_historical_result_vote_carrier_signer(
                        storage,
                        &prefix,
                        transaction.sender(),
                        &outbe_ocomp_protocol::profile::poc_schema_limits(),
                    )
                }
                OcompSystemCarrierCandidate::NodMaterialization { .. } => {
                    outbe_validatorset::contract::ValidatorSet::new(storage)
                        .resolve_validator_for_role(
                            transaction.sender(),
                            outbe_validatorset::delegation::ValidatorDelegateRole::Ocomp,
                        )
                }
            }
        };
        match authorization {
            Ok(Some(_)) => {}
            Ok(None) => {
                return invalid(
                    transaction,
                    "OCOMP carrier signer is not authorized for this action".to_owned(),
                )
            }
            Err(error) => {
                return invalid(
                    transaction,
                    format!("OCOMP carrier authorization failed: {error}"),
                )
            }
        }

        TransactionValidationOutcome::Valid {
            balance: U256::MAX,
            state_nonce: account.nonce,
            bytecode_hash: account.bytecode_hash,
            transaction: ValidTransaction::new(transaction, None),
            propagate: match origin {
                TransactionOrigin::External => true,
                TransactionOrigin::Local => {
                    self.inner
                        .local_transactions_config()
                        .propagate_local_transactions
                }
                TransactionOrigin::Private => false,
            },
            authorities: None,
        }
    }

    fn apply_outbe_policy(
        &self,
        outcome: TransactionValidationOutcome<Tx>,
    ) -> TransactionValidationOutcome<Tx> {
        let mut parts = match take_valid_outcome(outcome) {
            ValidOutcomeSplit::Valid(parts) => parts,
            ValidOutcomeSplit::Other(outcome) => return outcome,
        };

        parts = match reject_reserved_system_tx_outcome(parts) {
            ReservedSystemTxPolicy::Continue(parts) => parts,
            ReservedSystemTxPolicy::Reject(outcome) => return outcome,
        };

        let tx = parts.transaction.transaction();
        let signer = tx.sender();
        let zero_fee_tx = zero_fee_transaction(tx, signer);
        let normal_fee_outcome = |parts: ValidOutcomeParts<Tx>| {
            let cost = *parts.transaction.transaction().cost();
            if cost > parts.balance {
                let balance = parts.balance;
                TransactionValidationOutcome::Invalid(
                    parts.transaction.into_transaction(),
                    InvalidPoolTransactionError::Overdraft { cost, balance },
                )
            } else {
                valid_outcome(parts)
            }
        };
        let classification = outbe_zerofee::registry().classify(&zero_fee_tx);
        match classification {
            Ok(Some(candidate)) => match self.validate_zero_fee_state(candidate) {
                Ok(()) => {
                    parts.balance = U256::MAX;
                    valid_outcome(parts)
                }
                Err(err) => TransactionValidationOutcome::Invalid(
                    parts.transaction.into_transaction(),
                    InvalidPoolTransactionError::other(OutbeZeroFeePoolError(err.to_string())),
                ),
            },
            Ok(None) => {
                let bootstrap_candidate = bootstrap_transaction(
                    parts.transaction.transaction(),
                    signer,
                    self.inner.chain_id(),
                )
                .and_then(|view| outbe_zerofee::classify_bootstrap(&view));
                if let Some(candidate) = bootstrap_candidate {
                    match self.validate_bootstrap_state(candidate) {
                        Ok(true) => {
                            parts.balance = U256::MAX;
                            return valid_outcome(parts);
                        }
                        Ok(false) => return normal_fee_outcome(parts),
                        Err(err) => {
                            return TransactionValidationOutcome::Invalid(
                                parts.transaction.into_transaction(),
                                InvalidPoolTransactionError::other(OutbeZeroFeePoolError(
                                    err.to_string(),
                                )),
                            )
                        }
                    }
                }

                match self.try_eip7702_sponsorship(signer, &zero_fee_tx) {
                    Ok(SponsorshipOutcome::Accepted) => {
                        parts.balance = U256::MAX;
                        valid_outcome(parts)
                    }
                    Ok(SponsorshipOutcome::NotSponsored) => normal_fee_outcome(parts),
                    Err(err) => TransactionValidationOutcome::Invalid(
                        parts.transaction.into_transaction(),
                        InvalidPoolTransactionError::other(OutbeZeroFeePoolError(err.to_string())),
                    ),
                }
            }
            Err(err) => TransactionValidationOutcome::Invalid(
                parts.transaction.into_transaction(),
                InvalidPoolTransactionError::other(OutbeZeroFeePoolError(err.to_string())),
            ),
        }
    }

    /// Probe whether `signer` has an EIP-7702 delegation to
    /// [`outbe_zerofee::ZEROFEE_ADDRESS`]; if so, run the same
    /// `classify_sponsorship` + `authorize_sponsorship` checks the
    /// executor will perform at block time.
    ///
    /// Returns [`SponsorshipOutcome::NotSponsored`] when no delegation
    /// is present (the tx then falls back to the standard
    /// cost-vs-balance Overdraft gate). Returns `Err(_)` for an
    /// authenticated sponsorship attempt that fails any of the policy
    /// rules - the pool rejects with the policy reason in the
    /// `InvalidPoolTransactionError::other` payload so the caller sees
    /// the same error code the executor would produce at block time.
    ///
    /// The latest-block view used here is necessarily stale relative to
    /// the block currently building; an admitted sponsored tx whose
    /// quota was already burned by an earlier in-block tx will be
    /// rejected at execution time via a `status=0` receipt (same
    /// pattern as the oracle `AlreadyVoted` flow).
    fn try_eip7702_sponsorship(
        &self,
        signer: Address,
        zero_fee_tx: &ZeroFeeTransaction<'_>,
    ) -> Result<SponsorshipOutcome, OutbeZeroFeePoolError> {
        let state = self
            .inner
            .client()
            .latest()
            .map_err(|e| OutbeZeroFeePoolError(e.to_string()))?;

        // Resolve the signer's account + (optional) delegation bytecode
        // from the latest committed state, then hand the already-fetched
        // values to the pure decision core. Splitting the I/O from the
        // policy keeps the composition (delegation match -> classify ->
        // precheck, with NO quota check) deterministically unit-testable
        // without a provider mock - see `sponsorship_decision` tests.
        let Some(account) = state
            .basic_account(&signer)
            .map_err(|e| OutbeZeroFeePoolError(e.to_string()))?
        else {
            return Ok(SponsorshipOutcome::NotSponsored);
        };

        let delegation_bytecode = match account.bytecode_hash {
            Some(hash) => state
                .bytecode_by_hash(&hash)
                .map_err(|e| OutbeZeroFeePoolError(e.to_string()))?,
            None => None,
        };
        let delegated_to = delegation_bytecode
            .as_ref()
            .and_then(|bc| bc.eip7702_address());

        sponsorship_decision(signer, delegated_to, zero_fee_tx)
    }

    fn validate_zero_fee_state(
        &self,
        candidate: outbe_zerofee::ZeroFeeCandidate,
    ) -> Result<(), OutbeZeroFeePoolError> {
        let state = self
            .inner
            .client()
            .latest()
            .map_err(|e| OutbeZeroFeePoolError(e.to_string()))?;

        let reader = RethStateReader { state: &state };
        let mut provider = ReadOnlyStorageProvider::new(reader);
        let storage = StorageHandle::new(&mut provider);

        outbe_zerofee::registry()
            .authorize_fee_waiver(storage, candidate)
            .map(|_| ())
            .map_err(|e| OutbeZeroFeePoolError(e.to_string()))
    }

    fn validate_bootstrap_state(
        &self,
        candidate: outbe_zerofee::BootstrapCandidate,
    ) -> Result<bool, OutbeZeroFeePoolError> {
        let state = self
            .inner
            .client()
            .latest()
            .map_err(|e| OutbeZeroFeePoolError(e.to_string()))?;
        let Some(account) = state
            .basic_account(&candidate.signer)
            .map_err(|e| OutbeZeroFeePoolError(e.to_string()))?
        else {
            return Ok(false);
        };

        Ok(outbe_zerofee::authorize_bootstrap(
            candidate,
            outbe_zerofee::BootstrapAccountView {
                balance: account.balance,
                nonce: account.nonce,
                code_empty: account
                    .bytecode_hash
                    .is_none_or(|code_hash| code_hash == KECCAK256_EMPTY),
            },
        ))
    }
}

/// Bridges Reth's state provider into Outbe's read-only precompile storage.
struct RethStateReader<'a, P> {
    state: &'a P,
}

impl<P> StorageReader for RethStateReader<'_, P>
where
    P: StateProvider,
{
    fn read_storage(&self, address: Address, key: B256) -> outbe_primitives::error::Result<U256> {
        self.state
            .storage(address, key)
            .map(|value| value.unwrap_or(U256::ZERO))
            .map_err(|e| {
                outbe_primitives::error::PrecompileError::Storage(format!("state read failed: {e}"))
            })
    }
}

/// Outcome of the EIP-7702 sponsorship probe in `apply_outbe_policy`.
#[derive(Debug, PartialEq, Eq)]
enum SponsorshipOutcome {
    /// Signer is delegated to ZEROFEE_ADDRESS and passes all policy checks.
    Accepted,
    /// Signer is not delegated to ZEROFEE_ADDRESS; fall back to normal
    /// cost-vs-balance gating.
    NotSponsored,
}

/// Pure decision core for EIP-7702 sponsorship pool admission, factored
/// out of [`OutbeTransactionValidator::try_eip7702_sponsorship`] so the
/// composition is testable without a provider mock.
///
/// Inputs are the values the caller already fetched from the latest
/// committed state: the signer, its native `balance`, and the address
/// its account code delegates to (`None` if it is not an EIP-7702
/// delegation). The decision:
///   - `delegated_to != Some(ZEROFEE_ADDRESS)` -> `NotSponsored` (normal
///     fee path; never an error).
///   - delegated but the envelope does not match `classify_sponsorship`
///     (most importantly `priority_fee > 0` - "I am paying") ->
///     `NotSponsored`. The tx is a normal paid transaction that merely
///     originates from a delegated account; it must go through the
///     standard cost-vs-balance gating, NOT be rejected. This keeps
///     EIP-7702 delegation additive and lets a signer pay once their
///     daily free quota is exhausted.
///   - delegated AND envelope matches -> run `precheck_sponsorship`
///     (self-sponsorship); its policy error is
///     returned so the pool rejects with the matching code.
///
/// Quota is deliberately NOT checked here: the executor is authoritative
/// and quota-exhausted txs must land in the block as soft-failures
/// (code 110), so the pool admits them.
fn sponsorship_decision(
    signer: Address,
    delegated_to: Option<Address>,
    zero_fee_tx: &ZeroFeeTransaction<'_>,
) -> Result<SponsorshipOutcome, OutbeZeroFeePoolError> {
    if delegated_to != Some(outbe_zerofee::ZEROFEE_ADDRESS) {
        return Ok(SponsorshipOutcome::NotSponsored);
    }

    // Envelope mismatch (e.g. priority_fee > 0) means the signer is not
    // opting into sponsorship - fall through to the normal fee path
    // rather than rejecting the tx.
    if outbe_zerofee::classify_sponsorship(zero_fee_tx).is_err() {
        return Ok(SponsorshipOutcome::NotSponsored);
    }

    outbe_zerofee::precheck_sponsorship(signer)
        .map_err(|e| OutbeZeroFeePoolError(e.to_string()))?;

    Ok(SponsorshipOutcome::Accepted)
}

#[derive(Debug, thiserror::Error)]
#[error("reserved system transaction address is not accepted from users")]
struct OutbeReservedSystemTxPoolError;

impl PoolTransactionError for OutbeReservedSystemTxPoolError {
    fn is_bad_transaction(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug, thiserror::Error)]
#[error("zero-fee policy rejected transaction: {0}")]
struct OutbeZeroFeePoolError(String);

impl PoolTransactionError for OutbeZeroFeePoolError {
    fn is_bad_transaction(&self) -> bool {
        false
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[derive(Debug, thiserror::Error)]
#[error("OCOMP system carrier rejected: {0}")]
struct OutbeOcompSystemCarrierPoolError(String);

impl PoolTransactionError for OutbeOcompSystemCarrierPoolError {
    fn is_bad_transaction(&self) -> bool {
        true
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::{SignableTransaction as _, Transaction as _, TxEip1559, TxEip7702};
    use alloy_eips::{
        eip1559::MIN_PROTOCOL_BASE_FEE, eip2718::Encodable2718 as _, eip7702::Authorization,
    };
    use alloy_primitives::{Bytes, Signature, TxKind, B256};
    use alloy_signer::SignerSync as _;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use outbe_primitives::addresses::{ORACLE_ADDRESS, OUTBE_SYSTEM_TX_ADDRESS};
    use reth_ethereum::TransactionSigned;
    use reth_primitives_traits::SignedTransaction as _;
    use reth_transaction_pool::EthPooledTransaction;

    const CHAIN_ID: u64 = 1;
    fn pooled_tx(
        to: Address,
        input: Bytes,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> EthPooledTransaction {
        pooled_tx_with_gas(
            to,
            input,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            1_000_000,
        )
    }

    fn pooled_tx_with_gas(
        to: Address,
        input: Bytes,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        gas_limit: u64,
    ) -> EthPooledTransaction {
        let tx: TransactionSigned = TxEip1559 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            to: TxKind::Call(to),
            value: U256::ZERO,
            input,
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into();

        let encoded_length = tx.encode_2718_len();
        let recovered = tx
            .try_into_recovered()
            .expect("test transaction signer should recover");

        EthPooledTransaction::new(recovered, encoded_length)
    }

    fn bootstrap_pooled_tx() -> (EthPooledTransaction, Address) {
        let signer: PrivateKeySigner = outbe_primitives::test_keys::hex(1).parse().unwrap();
        let signer_address = signer.address();
        let authorization = Authorization {
            chain_id: U256::from(CHAIN_ID),
            address: outbe_zerofee::ZEROFEE_ADDRESS,
            nonce: 1,
        };
        let signed_authorization = authorization.clone().into_signed(
            signer
                .sign_hash_sync(&authorization.signature_hash())
                .unwrap(),
        );
        let input: Bytes = outbe_zerofee::precompile::IZeroFee::authorizeSponsorshipCall {
            signer: signer_address,
        }
        .abi_encode()
        .into();
        let tx = TxEip7702 {
            chain_id: CHAIN_ID,
            nonce: 0,
            gas_limit: outbe_zerofee::FREE_TX_BOOTSTRAP_GAS_LIMIT,
            max_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: 0,
            to: outbe_zerofee::ZEROFEE_ADDRESS,
            value: U256::ZERO,
            access_list: Default::default(),
            authorization_list: vec![signed_authorization],
            input,
        };
        let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
        let tx: TransactionSigned = tx.into_signed(signature).into();
        let encoded_length = tx.encode_2718_len();
        let recovered = tx.try_into_recovered().unwrap();

        (
            EthPooledTransaction::new(recovered, encoded_length),
            signer_address,
        )
    }

    #[test]
    fn pool_admits_true_type4_bootstrap_with_one_atomic_unit() {
        use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
        use reth_transaction_pool::{
            blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
        };

        let (transaction, signer) = bootstrap_pooled_tx();
        let chain_spec = reth_chainspec::ChainSpecBuilder::mainnet()
            .prague_activated()
            .build();
        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new()
            .with_chain_spec(chain_spec)
            .with_genesis_block();
        provider.add_account(signer, ExtendedAccount::new(0, U256::from(1)));
        let inner = EthTransactionValidatorBuilder::new(
            provider,
            reth_ethereum::evm::EthEvmConfig::mainnet(),
        )
        .set_eip7702(true)
        .disable_balance_check()
        .build(InMemoryBlobStore::default());
        let validator =
            OutbeTransactionValidator::new(inner, OcompLifecycleActivation::at_block(1));

        let outcome = futures::executor::block_on(
            validator.validate_transaction(TransactionOrigin::External, transaction),
        );
        let TransactionValidationOutcome::Valid { balance, .. } = outcome else {
            panic!("one-unit bootstrap must be admitted, got {outcome:?}");
        };
        assert_eq!(balance, U256::MAX, "bootstrap must receive the pool waiver");
    }

    #[test]
    fn pool_rejects_true_type4_bootstrap_with_zero_balance() {
        use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
        use reth_transaction_pool::{
            blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
        };

        let (transaction, signer) = bootstrap_pooled_tx();
        let chain_spec = reth_chainspec::ChainSpecBuilder::mainnet()
            .prague_activated()
            .build();
        let provider = MockEthProvider::<reth_ethereum::EthPrimitives>::new()
            .with_chain_spec(chain_spec)
            .with_genesis_block();
        provider.add_account(signer, ExtendedAccount::new(0, U256::ZERO));
        let inner = EthTransactionValidatorBuilder::new(
            provider,
            reth_ethereum::evm::EthEvmConfig::mainnet(),
        )
        .set_eip7702(true)
        .disable_balance_check()
        .build(InMemoryBlobStore::default());
        let validator =
            OutbeTransactionValidator::new(inner, OcompLifecycleActivation::at_block(1));

        let outcome = futures::executor::block_on(
            validator.validate_transaction(TransactionOrigin::External, transaction),
        );
        let TransactionValidationOutcome::Invalid(_, error) = outcome else {
            panic!("zero-balance bootstrap must be rejected, got {outcome:?}");
        };
        assert!(matches!(
            error,
            InvalidPoolTransactionError::Overdraft { balance, .. } if balance.is_zero()
        ));
    }

    fn oracle_submit_vote_input() -> Bytes {
        outbe_oracle::precompile::IOracle::submitVoteCall {
            tuples: vec![outbe_oracle::precompile::IOracle::ExchangeRateTuple {
                base: outbe_oracle::api::COEN_ASSET,
                quote: outbe_oracle::api::currency_address(840),
                exchangeRate: U256::from(1_000_000u64),
                volume: U256::from(10_000_000_000u64),
            }],
        }
        .abi_encode()
        .into()
    }

    fn ocomp_submit_result_vote_input() -> Bytes {
        use outbe_ocomp_protocol::{
            abi::SUBMIT_LYSIS_RESULT_SELECTOR, encode_envelope, profile::poc_schema_limits,
            registry::ObjectKind, vote::ResultVotePrefixV1, OCB1_HEADER_LEN,
        };

        let prefix = ResultVotePrefixV1 {
            protocol_bundle_hash: B256::repeat_byte(0x31),
            job_id: B256::repeat_byte(0x32),
            attempt: 3,
            result_validator_set_epoch: 7,
            result_committee_set_hash: B256::repeat_byte(0x33),
            result_ocomp_binding_hash: B256::repeat_byte(0x34),
            ocomp_key_hash: B256::repeat_byte(0x35),
            key_epoch: 1,
        };
        let mut body = Vec::new();
        body.extend_from_slice(prefix.protocol_bundle_hash.as_slice());
        body.extend_from_slice(prefix.job_id.as_slice());
        body.extend_from_slice(&prefix.attempt.to_be_bytes());
        body.extend_from_slice(&prefix.result_validator_set_epoch.to_be_bytes());
        body.extend_from_slice(prefix.result_committee_set_hash.as_slice());
        body.extend_from_slice(prefix.result_ocomp_binding_hash.as_slice());
        body.extend_from_slice(prefix.ocomp_key_hash.as_slice());
        body.extend_from_slice(&prefix.key_epoch.to_be_bytes());
        body.resize(180, 0);
        let payload = encode_envelope(ObjectKind::ResultVoteV1, &body, poc_schema_limits().codec)
            .expect("canonical OCOMP vote prefix must encode");
        assert_eq!(payload.len(), OCB1_HEADER_LEN + body.len());

        let padded_len = (payload.len() + 31) & !31;
        let mut input = vec![0_u8; 68 + padded_len];
        input[..4].copy_from_slice(&SUBMIT_LYSIS_RESULT_SELECTOR);
        input[4..36].copy_from_slice(&U256::from(32).to_be_bytes::<32>());
        input[36..68].copy_from_slice(&U256::from(payload.len()).to_be_bytes::<32>());
        input[68..68 + payload.len()].copy_from_slice(&payload);
        input.into()
    }

    #[test]
    fn only_submit_vote_has_reserved_zero_fee_priority_class() {
        assert_eq!(
            zero_fee_priority_class(ZeroFeeHookId::OracleSubmitVote),
            Some(1)
        );
    }

    #[test]
    fn zero_fee_submit_vote_orders_above_any_fee_paying_transaction() {
        let ordering = OutbeTransactionOrdering::<EthPooledTransaction>::default();
        let zero_fee_vote = pooled_tx(
            ORACLE_ADDRESS,
            oracle_submit_vote_input(),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
        );
        let expensive_normal_tx = pooled_tx(Address::ZERO, Bytes::new(), u128::MAX, u128::MAX);

        assert!(ordering.priority(&zero_fee_vote, 0) > ordering.priority(&expensive_normal_tx, 0));
    }

    #[test]
    fn canonical_ocomp_system_carrier_has_reserved_priority() {
        let ordering = OutbeTransactionOrdering::<EthPooledTransaction>::default();
        let system_carrier = pooled_tx_with_gas(
            outbe_ocomp_protocol::abi::METADOSIS_ADDRESS,
            ocomp_submit_result_vote_input(),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
            outbe_ocomp_protocol::system_carrier::OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
        );
        let expensive_normal_tx = pooled_tx(Address::ZERO, Bytes::new(), u128::MAX, u128::MAX);

        assert!(ordering.priority(&system_carrier, 0) > ordering.priority(&expensive_normal_tx, 0));
    }

    #[test]
    fn truncated_ocomp_vote_gets_no_pool_priority() {
        let ordering = OutbeTransactionOrdering::<EthPooledTransaction>::default();
        let malformed_vote = pooled_tx_with_gas(
            outbe_ocomp_protocol::abi::METADOSIS_ADDRESS,
            Bytes::copy_from_slice(&outbe_ocomp_protocol::abi::SUBMIT_LYSIS_RESULT_SELECTOR),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
            outbe_ocomp_protocol::system_carrier::OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
        );

        assert_eq!(ordering.priority(&malformed_vote, 0), Priority::None);
    }

    #[test]
    fn pool_classifies_ocomp_carrier_before_ordinary_intrinsic_gas() {
        use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
        use reth_transaction_pool::{
            blobstore::InMemoryBlobStore, validate::EthTransactionValidatorBuilder,
        };

        let carrier = pooled_tx_with_gas(
            outbe_ocomp_protocol::abi::METADOSIS_ADDRESS,
            ocomp_submit_result_vote_input(),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
            outbe_ocomp_protocol::system_carrier::OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
        );
        let provider = MockEthProvider::default().with_genesis_block();
        provider.add_account(
            carrier.sender(),
            ExtendedAccount::new(carrier.nonce(), U256::MAX),
        );
        let inner = EthTransactionValidatorBuilder::new(
            provider,
            reth_ethereum::evm::EthEvmConfig::mainnet(),
        )
        .build(InMemoryBlobStore::default());
        let validator =
            OutbeTransactionValidator::new(inner, OcompLifecycleActivation::at_block(1));

        let outcome = futures::executor::block_on(
            validator.validate_transaction(TransactionOrigin::External, carrier),
        );
        let TransactionValidationOutcome::Invalid(_, error) = outcome else {
            panic!("carrier without pinned state must be rejected, got {outcome:?}");
        };
        assert!(
            error.to_string().contains("not authorized for this action"),
            "state authorization must run before ordinary intrinsic gas: {error}"
        );
        assert!(!error.to_string().contains("intrinsic"));
    }

    #[test]
    fn malformed_zero_fee_marker_gets_no_pool_priority() {
        let ordering = OutbeTransactionOrdering::<EthPooledTransaction>::default();
        let malformed_vote = pooled_tx(
            ORACLE_ADDRESS,
            Bytes::copy_from_slice(&outbe_oracle::precompile::IOracle::submitVoteCall::SELECTOR),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
        );

        assert_eq!(ordering.priority(&malformed_vote, 0), Priority::None);
    }

    #[test]
    fn reserved_system_address_is_detected_for_pool_rejection() {
        let reserved = pooled_tx(
            OUTBE_SYSTEM_TX_ADDRESS,
            Bytes::from_static(b"not-a-system-prefix"),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
        );
        let normal = pooled_tx(
            Address::ZERO,
            Bytes::new(),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
        );

        assert!(is_reserved_system_tx(&reserved));
        assert!(!is_reserved_system_tx(&normal));
    }

    #[test]
    fn reserved_system_address_invalidates_valid_pool_outcome() {
        let reserved = pooled_tx(
            OUTBE_SYSTEM_TX_ADDRESS,
            Bytes::from_static(b"not-a-system-prefix"),
            MIN_PROTOCOL_BASE_FEE as u128,
            0,
        );
        let valid = TransactionValidationOutcome::Valid {
            balance: U256::MAX,
            state_nonce: 0,
            bytecode_hash: None,
            transaction: ValidTransaction::Valid(reserved),
            propagate: true,
            authorities: None,
        };
        let ValidOutcomeSplit::Valid(parts) = take_valid_outcome(valid) else {
            panic!("valid outcome should split");
        };

        match reject_reserved_system_tx_outcome(parts) {
            ReservedSystemTxPolicy::Reject(TransactionValidationOutcome::Invalid(tx, err)) => {
                assert!(is_reserved_system_tx(&tx));
                assert!(err
                    .to_string()
                    .contains("reserved system transaction address"));
            }
            other => panic!("expected reserved-address invalid outcome, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------
    // EIP-7702 sponsorship admission - pin the pool/executor contract:
    //   1. classify_sponsorship rejects shape violations (executor would
    //      do the same - codes must match).
    //   2. precheck_sponsorship rejects self-sponsorship and zero-
    //      balance signers but DELIBERATELY does no quota check.
    // The pool's `try_eip7702_sponsorship` chains classify + precheck;
    // these tests cover both individually and the policy code surface.
    // -----------------------------------------------------------------

    use alloy_primitives::address;
    use outbe_primitives::addresses::{AGENT_REWARD_ADDRESS, ZEROFEE_ADDRESS};
    use outbe_zerofee::{classify_sponsorship, precheck_sponsorship, ZeroFeeTransaction};

    const NON_VALIDATOR_SIGNER: Address = address!("0x9999999999999999999999999999999999999999");

    fn sponsored_envelope<'a>(input: &'a [u8]) -> ZeroFeeTransaction<'a> {
        ZeroFeeTransaction {
            signer: NON_VALIDATOR_SIGNER,
            to: Some(AGENT_REWARD_ADDRESS),
            value: U256::ZERO,
            input,
            gas_limit: 100_000,
            max_fee_per_gas: MIN_PROTOCOL_BASE_FEE as u128,
            max_priority_fee_per_gas: Some(0),
        }
    }

    #[test]
    fn pool_classify_accepts_well_formed_sponsored_envelope() {
        assert!(classify_sponsorship(&sponsored_envelope(&[])).is_ok());
    }

    #[test]
    fn pool_classify_rejects_non_zero_value_with_plan_code_113() {
        let mut tx = sponsored_envelope(&[]);
        tx.value = U256::from(1);
        let err = classify_sponsorship(&tx).unwrap_err();
        assert_eq!(err.code(), 113);
    }

    #[test]
    fn pool_classify_rejects_oversized_gas_with_plan_code_114() {
        let mut tx = sponsored_envelope(&[]);
        tx.gas_limit = outbe_zerofee::FREE_TX_DAILY_GAS_LIMIT + 1;
        let err = classify_sponsorship(&tx).unwrap_err();
        assert_eq!(err.code(), 114);
    }

    #[test]
    fn pool_classify_rejects_oversized_calldata_with_plan_code_115() {
        let big = vec![0u8; outbe_zerofee::FREE_TX_DAILY_CALLDATA_BYTES + 1];
        let tx = sponsored_envelope(&big);
        let err = classify_sponsorship(&tx).unwrap_err();
        assert_eq!(err.code(), 115);
    }

    #[test]
    fn pool_classify_rejects_target_outside_whitelist_with_plan_code_116() {
        let mut tx = sponsored_envelope(&[]);
        // ZEROFEE_ADDRESS itself is not in the SPONSORED_TARGET_WHITELIST.
        tx.to = Some(ZEROFEE_ADDRESS);
        let err = classify_sponsorship(&tx).unwrap_err();
        assert_eq!(err.code(), 116);
    }

    #[test]
    fn pool_precheck_rejects_self_sponsorship_with_code_107() {
        let err = precheck_sponsorship(ZEROFEE_ADDRESS).unwrap_err();
        assert_eq!(err.code(), 107);
    }

    #[test]
    fn pool_precheck_admits_zero_balance_non_paymaster_signer() {
        assert!(precheck_sponsorship(NON_VALIDATOR_SIGNER).is_ok());
    }

    #[test]
    fn pool_precheck_admits_funded_non_paymaster_signer() {
        assert!(precheck_sponsorship(NON_VALIDATOR_SIGNER).is_ok());
    }

    #[test]
    fn pool_precheck_does_not_run_quota_check() {
        // The pool MUST admit even when storage state says the daily
        // quota is exhausted - the executor produces the soft-failure
        // receipt code 110 at block time. precheck has no StorageHandle
        // parameter to enforce this contract at compile time; this
        // smoke test pins the runtime behaviour.
        assert!(precheck_sponsorship(NON_VALIDATOR_SIGNER).is_ok());
    }

    // -----------------------------------------------------------------
    // sponsorship_decision - the pure pool-admission decision core.
    // These pin the EXACT composition try_eip7702_sponsorship performs
    // (delegation match -> classify -> precheck, no quota) without needing
    // a provider mock. A regression in the wiring (reordered checks,
    // dropped classify, an accidental quota gate, or wrong delegation
    // target match) is caught here by `cargo test`, not only by the
    // gated live e2e script.
    // -----------------------------------------------------------------

    fn ok_sponsored_envelope<'a>() -> ZeroFeeTransaction<'a> {
        sponsored_envelope(&[])
    }

    #[test]
    fn decision_not_sponsored_when_no_delegation() {
        let out = sponsorship_decision(NON_VALIDATOR_SIGNER, None, &ok_sponsored_envelope())
            .expect("no delegation must not error");
        assert_eq!(out, SponsorshipOutcome::NotSponsored);
    }

    #[test]
    fn decision_not_sponsored_when_delegated_elsewhere() {
        // Delegated to a non-paymaster address -> normal fee path.
        let out = sponsorship_decision(
            NON_VALIDATOR_SIGNER,
            Some(ORACLE_ADDRESS),
            &ok_sponsored_envelope(),
        )
        .expect("foreign delegation must not error");
        assert_eq!(out, SponsorshipOutcome::NotSponsored);
    }

    #[test]
    fn decision_accepts_delegated_funded_well_formed() {
        let out = sponsorship_decision(
            NON_VALIDATOR_SIGNER,
            Some(ZEROFEE_ADDRESS),
            &ok_sponsored_envelope(),
        )
        .expect("valid sponsored tx must be accepted");
        assert_eq!(out, SponsorshipOutcome::Accepted);
    }

    #[test]
    fn decision_accepts_zero_balance_delegated_well_formed() {
        let out = sponsorship_decision(
            NON_VALIDATOR_SIGNER,
            Some(ZEROFEE_ADDRESS),
            &ok_sponsored_envelope(),
        )
        .expect("zero native balance must not reject sponsorship");
        assert_eq!(out, SponsorshipOutcome::Accepted);
    }

    #[test]
    fn decision_value_bearing_delegated_tx_falls_through_to_normal_path() {
        // Delegated + funded, but the envelope carries native value, so
        // it is NOT a sponsorship request. It must fall through to the
        // normal fee path (NotSponsored), NOT be rejected - EIP-7702
        // delegation is additive and must never block a normal tx.
        let mut tx = ok_sponsored_envelope();
        tx.value = U256::from(1);
        let out = sponsorship_decision(NON_VALIDATOR_SIGNER, Some(ZEROFEE_ADDRESS), &tx)
            .expect("value-bearing delegated tx must not error");
        assert_eq!(out, SponsorshipOutcome::NotSponsored);
    }

    #[test]
    fn decision_paying_delegated_tx_falls_through_to_normal_path() {
        // The core fix: a delegated account that sets a tip
        // (priority_fee > 0) is paying, not requesting sponsorship.
        // It must reach the normal cost-vs-balance gate, so a signer
        // can keep transacting (and paying) after the daily free quota
        // is exhausted.
        let mut tx = ok_sponsored_envelope();
        tx.max_priority_fee_per_gas = Some(1);
        let out = sponsorship_decision(NON_VALIDATOR_SIGNER, Some(ZEROFEE_ADDRESS), &tx)
            .expect("paying delegated tx must not error");
        assert_eq!(
            out,
            SponsorshipOutcome::NotSponsored,
            "priority_fee>0 from a delegated account must be a normal paid tx"
        );
    }

    #[test]
    fn decision_non_whitelisted_target_delegated_tx_falls_through() {
        // Delegated, zero-tip, but target not in the sponsored whitelist
        // -> not a sponsorship request -> normal path (the signer pays to
        // call whatever contract they like; delegation does not gate it).
        let mut tx = ok_sponsored_envelope();
        tx.to = Some(ZEROFEE_ADDRESS); // not in SPONSORED_TARGET_WHITELIST
        let out = sponsorship_decision(NON_VALIDATOR_SIGNER, Some(ZEROFEE_ADDRESS), &tx)
            .expect("non-whitelisted delegated tx must not error");
        assert_eq!(out, SponsorshipOutcome::NotSponsored);
    }

    #[test]
    fn decision_does_not_quota_check() {
        // sponsorship_decision has no storage access at all - it cannot
        // perform a quota check by construction. A delegated, funded,
        // well-formed tx is always Accepted regardless of how many slots
        // the signer has burned; the executor enforces the quota. This
        // pins the F2 contract at the pool layer.
        for _ in 0..20 {
            let out = sponsorship_decision(
                NON_VALIDATOR_SIGNER,
                Some(ZEROFEE_ADDRESS),
                &ok_sponsored_envelope(),
            )
            .unwrap();
            assert_eq!(out, SponsorshipOutcome::Accepted);
        }
    }
}
