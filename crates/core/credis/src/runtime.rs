//! Business logic for the Credis contract.
//!
//! A position lives on the COEN price path, not on a calendar. Nothing here is
//! scheduled off `originated_at`: the only time-driven quantity is the interest
//! day count, and even that is evaluated lazily at settlement rather than
//! accrued per block.

use alloy_primitives::{Address, U256};

use outbe_primitives::error::Result;
use outbe_primitives::time::SECONDS_PER_DAY;
use outbe_primitives::units::SCALE_1E6_U256;

use crate::constants::{CALL_RATE_PCT, CALL_WINDOW_SECS, DAYS_PER_YEAR, PRICE_RATE_DEN};
use crate::errors::CredisError;
use crate::precompile::ICredis;
use crate::schema::{CredisContract, CredisState, Position};

/// Terms captured when a position opens. Grouped rather than passed positionally
/// so a mis-ordered `U256` cannot silently swap principal for collateral.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPositionParams {
    /// The pledge handle the position id derives from.
    pub handle_id: U256,
    pub smart_account: Address,
    pub cca: Address,
    /// Sealed pledger EOA, opaque here.
    pub eoa_ct: Vec<u8>,
    pub asset: Address,
    /// ISO 4217 code of `asset`; denominates the position and keys the policy rate.
    pub issuance_currency: u16,
    /// ISO 4217 code of the elected threshold anchor. `entry_price` must be a
    /// COEN quote in THIS currency - the call is measured on its daily series.
    pub reference_currency: u16,
    /// `r`, 1e18 scaled, already multiplied by the policy-rate factor.
    pub policy_rate: U256,
    /// `P` - stablecoin minor units disbursed.
    pub principal: U256,
    /// `P0` - COEN price in the position's `reference_currency`, 1e6 oracle scale.
    pub entry_price: U256,
    /// `G` - pledged Gratis collateral.
    pub collateral: U256,
    pub originated_at: u64,
}

/// Outcome of [`CredisContract::settle`]. The caller moves the money: it pulls
/// `total_paid` from the payer into the vault and releases `gratis_released` to
/// the pledger - never to the payer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// Interest collected, in full, before any principal.
    pub interest: U256,
    /// Principal covered by this payment.
    pub principal_paid: U256,
    /// `interest + principal_paid` - what the payer owes for this settlement.
    pub total_paid: U256,
    /// Collateral freed and owed back to the pledger.
    pub gratis_released: U256,
    pub asset: Address,
    pub smart_account: Address,
    pub cca: Address,
    /// True when this settlement drove the outstanding principal to zero.
    pub closed: bool,
}

/// What a void writes off. `gratis_burned` is the unpaid share of the collateral;
/// the two written-off amounts are never collected from anyone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Void {
    pub gratis_burned: U256,
    pub principal_written_off: U256,
    pub interest_written_off: U256,
    pub smart_account: Address,
    pub cca: Address,
    /// Unpaid share of the original principal, scale `1e6`. Scales the
    /// originating CCA's penalty.
    pub unpaid_share: U256,
    /// Sealed pledger EOA - the caller opens it to key the confidential ledgers.
    pub eoa_ct: Vec<u8>,
}

/// `price x (100 + rate_pct) / 100`.
pub fn calc_call_price(price: U256) -> Result<U256> {
    price
        .checked_mul(U256::from(PRICE_RATE_DEN + CALL_RATE_PCT))
        .map(|v| v / U256::from(PRICE_RATE_DEN))
        .ok_or_else(|| CredisError::ArithmeticOverflow.into())
}

/// Timestamp after which a called position's remainder may be voided.
pub fn settlement_deadline(position: &Position) -> u64 {
    position.called_at.saturating_add(CALL_WINDOW_SECS)
}

impl CredisContract<'_> {
    /// Whole UTC days charged by a settlement at `now`, i.e. the day count the
    /// interest is computed over and the amount the accrual anchor advances by.
    /// The sub-day remainder is deliberately not consumed: it stays on the
    /// position and is charged by a later settlement.
    fn elapsed_days(position: &Position, now: u64) -> u64 {
        now.saturating_sub(position.last_settled_at) / SECONDS_PER_DAY
    }

    /// Interest accrued on the outstanding principal since the accrual anchor:
    /// simple, non-compounding, ACT/365 over **whole** elapsed UTC days rounded up.
    pub fn accrued_interest(position: &Position, now: u64) -> Result<U256> {
        let days = Self::elapsed_days(position, now);
        if days == 0 || position.outstanding.is_zero() || position.policy_rate.is_zero() {
            return Ok(U256::ZERO);
        }
        let numerator = position
            .outstanding
            .checked_mul(position.policy_rate)
            .and_then(|v| v.checked_mul(U256::from(days)))
            .ok_or(CredisError::ArithmeticOverflow)?;
        // Non-zero by construction: both factors are compile-time constants.
        // The scale must match `policy_rate`, which the oracle publishes at 1e6.
        let denominator = U256::from(DAYS_PER_YEAR)
            .checked_mul(SCALE_1E6_U256)
            .ok_or(CredisError::ArithmeticOverflow)?;
        Ok(numerator.div_ceil(denominator))
    }

    /// Opens a position and returns its derived
    /// `position_id = keccak256(handle_id || smart_account)`.
    ///
    /// Everything the position will ever need is sealed here: the call price
    /// derives from `entry_price`, and `policy_rate` is pinned. Collateral
    /// starts fully locked and the interest anchor starts at origination.
    pub fn open_position(&mut self, params: OpenPositionParams) -> Result<U256> {
        if params.principal.is_zero() || params.collateral.is_zero() {
            return Err(CredisError::InvalidAmount.into());
        }

        let position_id = CredisContract::position_id(params.handle_id, params.smart_account);
        if self.position_exists(position_id)? {
            return Err(CredisError::PositionAlreadyExists.into());
        }

        let position = Position {
            position_id,
            smart_account: params.smart_account,
            cca: params.cca,
            asset: params.asset,
            issuance_currency: params.issuance_currency,
            reference_currency: params.reference_currency,
            eoa_ct: params.eoa_ct,
            principal: params.principal,
            outstanding: params.principal,
            collateral: params.collateral,
            collateral_locked: params.collateral,
            policy_rate: params.policy_rate,
            entry_price: params.entry_price,
            call_price: calc_call_price(params.entry_price)?,
            originated_at: params.originated_at,
            last_settled_at: params.originated_at,
            called_at: 0,
            state: CredisState::Open as u8,
        };
        self.create_position_record(&position)?;
        self.append_to_address_index(params.smart_account, position_id)?;
        self.append_to_global_index(position_id)?;
        self.insert_active(position_id)?;

        self.emit(ICredis::PositionCreated {
            positionId: position_id,
            smartAccount: params.smart_account,
            cca: params.cca,
            principal: params.principal,
            collateral: params.collateral,
        })?;
        Ok(position_id)
    }

    /// Calls an open position, opening the settlement window. Settlement terms
    /// are unchanged throughout it. Idempotent: an already-called position
    /// returns `false` without moving its deadline.
    ///
    /// The caller is responsible for having established the sustained breach.
    pub fn mark_called(&mut self, position_id: U256, now: u64) -> Result<bool> {
        let mut position = self.load_position(position_id)?;
        if position.lifecycle_state()? != CredisState::Open {
            return Ok(false);
        }
        position.state = CredisState::Called as u8;
        position.called_at = now;
        self.update_position_record(&position)?;
        self.bump_called_count(position.smart_account)?;
        self.emit(ICredis::PositionCalled {
            positionId: position_id,
            calledAt: now,
            settlementDeadline: settlement_deadline(&position),
        })?;
        Ok(true)
    }

    /// Applies a settlement of `amount` - interest first, principal second.
    ///
    /// Any payer may settle any open or called position: the collateral
    /// released is owed to the pledger recorded on the position, so a payer can
    /// never redirect value to themselves.
    ///
    /// - a payment below the accrued interest is rejected outright;
    /// - only what the position needs is consumed, so an over-payment is not
    ///   over-pulled - the caller charges `Settlement::total_paid`;
    /// - collateral release is principal-proportional and floored, except on the
    ///   final settlement, which releases exactly what is left so no dust
    ///   remains locked.
    pub fn settle(&mut self, position_id: U256, amount: U256, now: u64) -> Result<Settlement> {
        let mut position = self.load_position(position_id)?;
        let state_before = position.lifecycle_state()?;
        match state_before {
            CredisState::Settled | CredisState::Void => {
                return Err(CredisError::PositionClosed.into())
            }
            CredisState::Open | CredisState::Called => {}
        }

        let days = Self::elapsed_days(&position, now);
        let interest = Self::accrued_interest(&position, now)?;
        if amount < interest {
            return Err(CredisError::PaymentBelowAccruedInterest.into());
        }
        let principal_paid = (amount - interest).min(position.outstanding);

        // Floor division favors the protocol on every partial; the final
        // settlement short-circuits to the exact remainder so the sum of
        // releases closes on `collateral` with nothing stranded.
        let gratis_released = if principal_paid == position.outstanding {
            position.collateral_locked
        } else {
            position
                .collateral
                .checked_mul(principal_paid)
                .ok_or(CredisError::ArithmeticOverflow)?
                / position.principal
        };

        position.outstanding = position
            .outstanding
            .checked_sub(principal_paid)
            .ok_or(CredisError::ArithmeticOverflow)?;
        position.collateral_locked = position
            .collateral_locked
            .checked_sub(gratis_released)
            .ok_or(CredisError::ArithmeticOverflow)?;
        // Accrual restarts on the reduced principal; no unpaid interest ever
        // carries between settlements. The anchor advances by the whole days
        // actually charged, never to `now`: settling on a sub-day boundary must
        // not discard the remainder, or repeated dust settlements just under
        // 24h apart would hold `days` at zero and evade the coupon entirely.
        position.last_settled_at = position
            .last_settled_at
            .saturating_add(days.saturating_mul(SECONDS_PER_DAY));

        let closed = position.outstanding.is_zero();
        if closed {
            position.state = CredisState::Settled as u8;
        }
        self.update_position_record(&position)?;
        if closed {
            // Terminal: leave the active index, and release the owner's call
            // block if this settlement resolved a called position.
            self.remove_active(position_id)?;
            if state_before == CredisState::Called {
                self.drop_called_count(position.smart_account)?;
            }
        }

        self.emit(ICredis::SettlementApplied {
            positionId: position_id,
            interestPaid: interest,
            principalPaid: principal_paid,
            gratisReleased: gratis_released,
            outstanding: position.outstanding,
        })?;
        if closed {
            self.emit(ICredis::PositionSettled {
                positionId: position_id,
            })?;
        }

        Ok(Settlement {
            interest,
            principal_paid,
            total_paid: interest
                .checked_add(principal_paid)
                .ok_or(CredisError::ArithmeticOverflow)?,
            gratis_released,
            asset: position.asset,
            smart_account: position.smart_account,
            cca: position.cca,
            closed,
        })
    }

    /// Voids the remainder of a called position whose settlement window has
    /// lapsed. Only the unpaid share is written off: every settlement already
    /// released its proportional share, so whatever the owner settled they have
    /// already reclaimed. The invariant that holds exactly is
    /// `sum released + collateral_locked == G`; because each partial release is
    /// floored, `collateral_locked >= floor(G x P_out / P)`, with the drift
    /// always toward the protocol.
    ///
    /// Returns what the caller must burn and credit; the position itself is
    /// closed here.
    pub fn void_position(&mut self, position_id: U256, now: u64) -> Result<Void> {
        let mut position = self.load_position(position_id)?;
        if position.lifecycle_state()? != CredisState::Called {
            return Err(CredisError::NotCalled.into());
        }
        if now < settlement_deadline(&position) {
            return Err(CredisError::CallWindowOpen.into());
        }
        if position.outstanding.is_zero() {
            return Err(CredisError::NothingOutstanding.into());
        }

        let gratis_burned = position.collateral_locked;
        let principal_written_off = position.outstanding;
        let interest_written_off = Self::accrued_interest(&position, now)?;
        // A dimensionless fraction of the original principal, carried at the
        // protocol's 1e6 fixed-point scale.
        let unpaid_share = principal_written_off
            .checked_mul(SCALE_1E6_U256)
            .ok_or(CredisError::ArithmeticOverflow)?
            / position.principal;

        position.outstanding = U256::ZERO;
        position.collateral_locked = U256::ZERO;
        position.state = CredisState::Void as u8;
        self.update_position_record(&position)?;
        self.remove_active(position_id)?;
        self.drop_called_count(position.smart_account)?;

        self.emit(ICredis::PositionVoided {
            positionId: position_id,
            cca: position.cca,
            gratisBurned: gratis_burned,
            principalWrittenOff: principal_written_off,
            interestWrittenOff: interest_written_off,
        })?;

        Ok(Void {
            gratis_burned,
            principal_written_off,
            interest_written_off,
            smart_account: position.smart_account,
            cca: position.cca,
            unpaid_share,
            eoa_ct: position.eoa_ct,
        })
    }

    // ---------------------------------------------------------------------
    // Reads
    // ---------------------------------------------------------------------

    /// Loads the position record. Reverts on missing.
    pub fn get_position(&self, position_id: U256) -> Result<Position> {
        self.load_position(position_id)
    }

    /// True if any of `account`'s positions is CALLED. Informational only: a
    /// pending call does not gate origination of further positions.
    pub fn has_called_position(&self, account: Address) -> Result<bool> {
        Ok(self.called_position_counts.read(&account)? > 0)
    }

    /// Number of positions still on the price path - those the daily scan visits.
    pub fn active_len(&self) -> Result<u32> {
        self.read_active_len()
    }

    /// Position id at active-index `index`, or `None` past the end.
    pub fn active_at(&self, index: u32) -> Result<Option<U256>> {
        self.read_active_at(index)
    }

    /// Sum of `principal` and of `outstanding` across all positions for
    /// `account`, in one walk of the owner index.
    pub fn principal_and_outstanding_of(&self, account: Address) -> Result<(U256, U256)> {
        let mut principal = U256::ZERO;
        let mut outstanding = U256::ZERO;
        for position in self.get_positions_by_address(account)? {
            principal = principal
                .checked_add(position.principal)
                .ok_or(CredisError::ArithmeticOverflow)?;
            outstanding = outstanding
                .checked_add(position.outstanding)
                .ok_or(CredisError::ArithmeticOverflow)?;
        }
        Ok((principal, outstanding))
    }

    /// How many positions `account` has ever been issued.
    pub fn position_count_of(&self, account: Address) -> Result<u32> {
        self.read_address_position_count(account)
    }

    /// `account`'s `index`-th position, in insertion order.
    pub fn position_of_address_at(&self, account: Address, index: u32) -> Result<Position> {
        if index >= self.read_address_position_count(account)? {
            return Err(CredisError::IndexOutOfBounds.into());
        }
        self.load_position(self.read_address_position_id(account, index)?)
    }

    /// The `index`-th position ever created, in creation order.
    pub fn position_at(&self, index: u64) -> Result<Position> {
        if index >= self.read_total_positions()? {
            return Err(CredisError::IndexOutOfBounds.into());
        }
        self.load_position(self.read_position_id_at(index)?)
    }

    /// All positions for `account`, in insertion order. Unbounded, so it stays
    /// internal: the ABI enumerates through `position_of_address_at` instead.
    pub(crate) fn get_positions_by_address(&self, account: Address) -> Result<Vec<Position>> {
        let count = self.read_address_position_count(account)?;
        let mut out = Vec::with_capacity(count as usize);
        for i in 0..count {
            let position_id = self.read_address_position_id(account, i)?;
            if let Some(position) = self.positions.get(position_id)? {
                out.push(position);
            }
        }
        Ok(out)
    }

    /// Total positions ever created (length of the global dense index). Used by
    /// the block sweeps to bound their cursors.
    pub fn total_positions(&self) -> Result<u64> {
        self.read_total_positions()
    }

    /// Position id at global dense-index `index` (`index < total_positions()`).
    pub fn position_id_at(&self, index: u64) -> Result<U256> {
        self.read_position_id_at(index)
    }
}
