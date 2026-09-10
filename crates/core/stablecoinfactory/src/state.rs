use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::SolEvent;
use outbe_primitives::{
    addresses::{STABLECOIN_ADDRESS_PREFIX, STABLECOIN_FACTORY_ADDRESS, STABLECOIN_MARKER_CODE},
    error::{PrecompileError, Result},
    stablecoin::{decode_canonical_stablecoin_create, predict_stablecoin, validate_ticker},
    stablecoin_fork::STABLECOIN_LIST_PAGE_CAP,
};
use outbe_stablecoin::{
    FactoryTokenInitialization, StablecoinFactoryApi as StablecoinTokenFactoryApi,
};
use revm::state::Bytecode;

use crate::{
    abi::IStablecoinFactory,
    api::{FactoryReservation, ValidatedStablecoinCreate},
    errors::StablecoinFactoryError,
    schema::{ReservationRecord, StablecoinFactoryContract, FACTORY_SCHEMA_VERSION},
};

impl StablecoinFactoryContract<'_> {
    pub(crate) fn validate_create(
        &self,
        proposer: Address,
        raw_payload: &[u8],
    ) -> Result<ValidatedStablecoinCreate> {
        self.ensure_compatible_schema()?;
        let payload = decode_canonical_stablecoin_create(raw_payload)
            .map_err(|_| StablecoinFactoryError::NonCanonicalPayload)?;
        if proposer != payload.issuer {
            return Err(StablecoinFactoryError::InvalidIssuer {
                issuer: payload.issuer,
            }
            .into());
        }
        if !outbe_stablecoinpolicy::api::policy_exists(self.storage.clone(), payload.policy_id)? {
            return Err(StablecoinFactoryError::UnknownPolicy {
                policy_id: payload.policy_id,
            }
            .into());
        }

        let (token_id, token) = self.predict_token_address(payload.issuer, &payload.ticker)?;
        self.ensure_identity_available(token_id, &payload.ticker, token)?;
        Ok(ValidatedStablecoinCreate {
            payload,
            token_id,
            token,
        })
    }

    pub fn token_count(&self) -> Result<U256> {
        self.ensure_compatible_schema()?;
        Ok(U256::from(self.tokens.len()?))
    }

    pub fn list_tokens(&self, offset: U256, limit: U256) -> Result<Vec<Address>> {
        self.ensure_compatible_schema()?;
        let maximum = STABLECOIN_LIST_PAGE_CAP;
        if limit.is_zero() || limit > U256::from(maximum) {
            return Err(StablecoinFactoryError::InvalidListLimit { limit, maximum }.into());
        }

        let count = self.tokens.len()?;
        let Ok(offset) = u32::try_from(offset) else {
            return Ok(Vec::new());
        };
        if offset >= count {
            return Ok(Vec::new());
        }
        let limit = u32::try_from(limit)
            .map_err(|_| StablecoinFactoryError::InvalidListLimit { limit, maximum })?;
        let end = offset.saturating_add(limit).min(count);
        let mut tokens = Vec::with_capacity((end - offset) as usize);
        for index in offset..end {
            let token =
                self.tokens
                    .at(index)?
                    .ok_or_else(|| StablecoinFactoryError::Invariant {
                        reason: "token set length/data mismatch".into(),
                    })?;
            tokens.push(token);
        }
        Ok(tokens)
    }

    pub fn token_by_id(&self, token_id: B256) -> Result<Address> {
        self.ensure_compatible_schema()?;
        self.token_by_id_index.read(&token_id)
    }

    pub fn token_by_ticker(&self, ticker: &str) -> Result<Address> {
        self.ensure_compatible_schema()?;
        let ticker_hash = ticker_hash(ticker)?;
        self.token_by_ticker_index.read(&ticker_hash)
    }

    pub fn token_id_of(&self, token: Address) -> Result<B256> {
        self.ensure_compatible_schema()?;
        if !self.tokens.contains(&token)? {
            return Err(StablecoinFactoryError::UnknownStablecoin { token }.into());
        }
        self.token_id_of_index.read(&token)
    }

    pub fn is_stablecoin(&self, token: Address) -> Result<bool> {
        self.ensure_compatible_schema()?;
        self.tokens.contains(&token)
    }

    pub fn registered_token_id(&self, token: Address) -> Result<Option<B256>> {
        self.ensure_compatible_schema()?;
        if !self.tokens.contains(&token)? {
            return Ok(None);
        }
        Ok(Some(self.token_id_of_index.read(&token)?))
    }

    pub fn predict_token_address(&self, issuer: Address, ticker: &str) -> Result<(B256, Address)> {
        self.ensure_compatible_schema()?;
        if issuer.is_zero() {
            return Err(StablecoinFactoryError::InvalidIssuer { issuer }.into());
        }
        predict_stablecoin(
            self.storage.chain_id()?,
            STABLECOIN_FACTORY_ADDRESS,
            issuer,
            ticker,
            STABLECOIN_ADDRESS_PREFIX,
        )
        .map_err(|_| {
            StablecoinFactoryError::InvalidTicker {
                ticker: ticker.to_owned(),
            }
            .into()
        })
    }

    pub(crate) fn reserve(&mut self, reservation: &FactoryReservation) -> Result<()> {
        self.ensure_compatible_schema()?;
        if reservation.proposal_id.is_zero() {
            return Err(StablecoinFactoryError::Invariant {
                reason: "proposal id zero cannot own a reservation".into(),
            }
            .into());
        }
        let ticker_hash = ticker_hash(&reservation.ticker)?;
        self.ensure_identity_available(
            reservation.token_id,
            &reservation.ticker,
            reservation.token,
        )?;
        if self.reservations.exists(reservation.proposal_id)? {
            return Err(StablecoinFactoryError::Invariant {
                reason: format!(
                    "proposal {} already owns a reservation",
                    reservation.proposal_id
                ),
            }
            .into());
        }

        self.install_schema_for_write()?;
        self.pending_token_id
            .write(&reservation.token_id, reservation.proposal_id)?;
        self.pending_ticker
            .write(&ticker_hash, reservation.proposal_id)?;
        self.pending_address
            .write(&reservation.token, reservation.proposal_id)?;
        self.reservations.create(&ReservationRecord {
            proposal_id: reservation.proposal_id,
            exists: true,
            token_id: reservation.token_id,
            ticker_hash,
            token: reservation.token,
        })
    }

    pub(crate) fn execute_approved(
        &mut self,
        proposal_id: U256,
        proposer: Address,
        raw_payload: &[u8],
        creation_protocol_version: u64,
    ) -> Result<ValidatedStablecoinCreate> {
        let storage = self.storage.clone();
        storage.with_checkpoint(|| {
            let validated = self.validate_reserved_create(proposal_id, proposer, raw_payload)?;
            self.require_pristine_token_account(validated.token)?;

            StablecoinTokenFactoryApi::new(storage.clone()).initialize(
                &FactoryTokenInitialization {
                    token_address: validated.token,
                    token_id: validated.token_id,
                    creation_protocol_version,
                    payload: validated.payload.clone(),
                },
            )?;
            storage.set_code(
                validated.token,
                Bytecode::new_raw(Bytes::copy_from_slice(&STABLECOIN_MARKER_CODE)),
            )?;
            self.consume_and_register(proposal_id)?;
            storage.emit_event(
                STABLECOIN_FACTORY_ADDRESS,
                IStablecoinFactory::StablecoinCreated {
                    tokenId: validated.token_id,
                    token: validated.token,
                    issuer: validated.payload.issuer,
                    proposalId: proposal_id,
                    name: validated.payload.name.clone(),
                    ticker: validated.payload.ticker.clone(),
                    iso4217: validated.payload.iso4217,
                    decimals: validated.payload.decimals,
                    supplyCap: validated.payload.supply_cap,
                    policyId: validated.payload.policy_id,
                }
                .encode_log_data(),
            )?;
            Ok(validated)
        })
    }

    fn validate_reserved_create(
        &self,
        proposal_id: U256,
        proposer: Address,
        raw_payload: &[u8],
    ) -> Result<ValidatedStablecoinCreate> {
        self.ensure_compatible_schema()?;
        let payload = decode_canonical_stablecoin_create(raw_payload)
            .map_err(|_| StablecoinFactoryError::NonCanonicalPayload)?;
        if proposer != payload.issuer {
            return Err(StablecoinFactoryError::InvalidIssuer {
                issuer: payload.issuer,
            }
            .into());
        }
        if !outbe_stablecoinpolicy::api::policy_exists(self.storage.clone(), payload.policy_id)? {
            return Err(StablecoinFactoryError::UnknownPolicy {
                policy_id: payload.policy_id,
            }
            .into());
        }

        let (token_id, token) = self.predict_token_address(payload.issuer, &payload.ticker)?;
        let reservation = self.required_reservation(proposal_id)?;
        self.require_pending_triple(&reservation)?;
        let ticker_hash = ticker_hash(&payload.ticker)?;
        if reservation.token_id != token_id
            || reservation.ticker_hash != ticker_hash
            || reservation.token != token
        {
            return Err(StablecoinFactoryError::Invariant {
                reason: format!(
                    "proposal {proposal_id} payload does not match its Factory reservation"
                ),
            }
            .into());
        }
        self.require_permanent_indexes_empty(&reservation)?;
        Ok(ValidatedStablecoinCreate {
            payload,
            token_id,
            token,
        })
    }

    fn require_pristine_token_account(&self, token: Address) -> Result<()> {
        self.storage.with_account_info(token, |info| {
            let has_code = info
                .code
                .as_ref()
                .is_some_and(|code| !code.original_bytes().is_empty());
            let code_hash_is_empty = info.code_hash.is_zero() || info.code_hash == keccak256([]);
            if info.nonce != 0 || has_code || !code_hash_is_empty {
                return Err(StablecoinFactoryError::Invariant {
                    reason: format!(
                        "reserved stablecoin address {token} has pre-existing nonce or code"
                    ),
                }
                .into());
            }
            Ok(())
        })
    }

    fn ensure_identity_available(
        &self,
        token_id: B256,
        ticker: &str,
        token: Address,
    ) -> Result<()> {
        let ticker_hash = ticker_hash(ticker)?;
        let registered_by_id = self.token_by_id_index.read(&token_id)?;
        if !registered_by_id.is_zero() {
            return Err(StablecoinFactoryError::TokenIdAlreadyRegistered {
                token_id,
                token: registered_by_id,
            }
            .into());
        }
        let registered_by_ticker = self.token_by_ticker_index.read(&ticker_hash)?;
        if !registered_by_ticker.is_zero() {
            return Err(StablecoinFactoryError::TickerAlreadyRegistered {
                ticker: ticker.to_owned(),
                token: registered_by_ticker,
            }
            .into());
        }
        if let Some(existing_token_id) = self.registered_token_id(token)? {
            return Err(StablecoinFactoryError::TokenAddressCollision {
                token,
                existing_token_id,
                requested_token_id: token_id,
            }
            .into());
        }

        let token_id_owner = self.pending_token_id.read(&token_id)?;
        if !token_id_owner.is_zero() {
            return Err(StablecoinFactoryError::TokenIdReserved {
                token_id,
                proposal_id: token_id_owner,
            }
            .into());
        }
        let ticker_owner = self.pending_ticker.read(&ticker_hash)?;
        if !ticker_owner.is_zero() {
            return Err(StablecoinFactoryError::TickerReserved {
                ticker: ticker.to_owned(),
                proposal_id: ticker_owner,
            }
            .into());
        }
        let address_owner = self.pending_address.read(&token)?;
        if !address_owner.is_zero() {
            let existing = self.required_reservation(address_owner)?;
            return Err(StablecoinFactoryError::TokenAddressCollision {
                token,
                existing_token_id: existing.token_id,
                requested_token_id: token_id,
            }
            .into());
        }
        Ok(())
    }

    pub(crate) fn release(&mut self, proposal_id: U256) -> Result<ReservationRecord> {
        self.ensure_compatible_schema()?;
        let reservation = self.required_reservation(proposal_id)?;
        self.require_pending_triple(&reservation)?;
        self.clear_pending_triple(&reservation)?;
        self.reservations.delete(proposal_id)?;
        Ok(reservation)
    }

    pub(crate) fn consume_and_register(&mut self, proposal_id: U256) -> Result<ReservationRecord> {
        self.ensure_compatible_schema()?;
        let reservation = self.required_reservation(proposal_id)?;
        self.require_pending_triple(&reservation)?;
        self.require_permanent_indexes_empty(&reservation)?;

        if !self.tokens.insert(reservation.token)? {
            return Err(StablecoinFactoryError::Invariant {
                reason: "reserved token address is already in the permanent token set".into(),
            }
            .into());
        }
        self.token_by_id_index
            .write(&reservation.token_id, reservation.token)?;
        self.token_by_ticker_index
            .write(&reservation.ticker_hash, reservation.token)?;
        self.token_id_of_index
            .write(&reservation.token, reservation.token_id)?;
        self.clear_pending_triple(&reservation)?;
        self.reservations.delete(proposal_id)?;
        Ok(reservation)
    }

    fn ensure_compatible_schema(&self) -> Result<()> {
        let schema = self.schema_version.read()?;
        if schema == 0 || schema == FACTORY_SCHEMA_VERSION {
            return Ok(());
        }
        Err(PrecompileError::Fatal(format!(
            "stablecoin Factory schema {schema} is unsupported"
        )))
    }

    fn install_schema_for_write(&self) -> Result<()> {
        let schema = self.schema_version.read()?;
        match schema {
            0 => self.schema_version.write(FACTORY_SCHEMA_VERSION),
            FACTORY_SCHEMA_VERSION => Ok(()),
            _ => Err(PrecompileError::Fatal(format!(
                "stablecoin Factory schema {schema} is unsupported"
            ))),
        }
    }

    fn required_reservation(&self, proposal_id: U256) -> Result<ReservationRecord> {
        self.reservations.get(proposal_id)?.ok_or_else(|| {
            StablecoinFactoryError::Invariant {
                reason: format!("proposal {proposal_id} has no Factory reservation"),
            }
            .into()
        })
    }

    fn require_pending_triple(&self, reservation: &ReservationRecord) -> Result<()> {
        let by_id = self.pending_token_id.read(&reservation.token_id)?;
        let by_ticker = self.pending_ticker.read(&reservation.ticker_hash)?;
        let by_address = self.pending_address.read(&reservation.token)?;
        if by_id != reservation.proposal_id
            || by_ticker != reservation.proposal_id
            || by_address != reservation.proposal_id
        {
            return Err(StablecoinFactoryError::Invariant {
                reason: format!(
                    "proposal {} reservation triple does not match its record",
                    reservation.proposal_id
                ),
            }
            .into());
        }
        Ok(())
    }

    fn require_permanent_indexes_empty(&self, reservation: &ReservationRecord) -> Result<()> {
        let by_id = self.token_by_id_index.read(&reservation.token_id)?;
        let by_ticker = self.token_by_ticker_index.read(&reservation.ticker_hash)?;
        let by_address = self.registered_token_id(reservation.token)?;
        if !by_id.is_zero() || !by_ticker.is_zero() || by_address.is_some() {
            return Err(StablecoinFactoryError::Invariant {
                reason: format!(
                    "proposal {} reservation collides with permanent Factory state",
                    reservation.proposal_id
                ),
            }
            .into());
        }
        Ok(())
    }

    fn clear_pending_triple(&self, reservation: &ReservationRecord) -> Result<()> {
        self.pending_token_id.clear(&reservation.token_id)?;
        self.pending_ticker.clear(&reservation.ticker_hash)?;
        self.pending_address.clear(&reservation.token)
    }
}

fn ticker_hash(ticker: &str) -> Result<B256> {
    validate_ticker(ticker).map_err(|_| {
        PrecompileError::from(StablecoinFactoryError::InvalidTicker {
            ticker: ticker.to_owned(),
        })
    })?;
    Ok(keccak256(ticker.as_bytes()))
}
