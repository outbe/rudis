use crate::schema::{AgentRewardContract, RewardPool};
use alloy_primitives::{Address, U256};
use outbe_gemfactory::schema::GemTypes;
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::time::WorldwideDay;
use outbe_primitives::units::{checked_protocol_to_native, native_to_protocol_floor};

/// ISO 4217 code both currency axes of an agent reward Gem carry. Agent rewards
/// are denominated in USD by protocol policy, the same as validator Gems.
const AGENT_GEM_CURRENCY: u16 = 840;

impl AgentRewardContract<'_> {
    /// Increments WAA (wallet) tribute count for an address on `day`.
    ///
    /// On the first tribute for this address+day pair, the address is
    /// also appended to the per-day WAA address list so it can be
    /// enumerated during distribution.
    pub fn increment_waa_tribute(&mut self, day: WorldwideDay, address: Address) -> Result<()> {
        let key = AgentRewardContract::tribute_count_key(day, address);
        let count = self.waa_tribute_counts.read(&key)?;
        if count == 0 {
            // First tribute for this address+day - add to address list
            let addr_count = self.waa_address_count.read(&day)?;
            let idx_key = AgentRewardContract::address_index_key(day, addr_count);
            self.waa_addresses.write(&idx_key, address)?;
            self.waa_address_count.write(&day, addr_count + 1)?;
        }
        self.waa_tribute_counts.write(&key, count + 1)
    }

    /// Increments SRA tribute count for an address on `day`.
    ///
    /// On the first tribute for this address+day pair, the address is
    /// also appended to the per-day SRA address list so it can be
    /// enumerated during distribution.
    pub fn increment_sra_tribute(&mut self, day: WorldwideDay, address: Address) -> Result<()> {
        let key = AgentRewardContract::tribute_count_key(day, address);
        let count = self.sra_tribute_counts.read(&key)?;
        if count == 0 {
            // First tribute for this address+day - add to address list
            let addr_count = self.sra_address_count.read(&day)?;
            let idx_key = AgentRewardContract::address_index_key(day, addr_count);
            self.sra_addresses.write(&idx_key, address)?;
            self.sra_address_count.write(&day, addr_count + 1)?;
        }
        self.sra_tribute_counts.write(&key, count + 1)
    }

    /// Gets the total claimable reward balance for an address across both pools.
    pub fn get_claimable_reward(&self, address: Address) -> Result<U256> {
        let waa = self.get_pool_claimable_reward(RewardPool::Waa, address)?;
        let sra = self.get_pool_claimable_reward(RewardPool::Sra, address)?;
        checked_add(waa, sra, "agentreward claimable total overflow")
    }

    /// Gets the claimable reward balance an address holds in one pool.
    pub fn get_pool_claimable_reward(&self, pool: RewardPool, address: Address) -> Result<U256> {
        match pool {
            RewardPool::Waa => self.waa_claimable_rewards.read(&address),
            RewardPool::Sra => self.sra_claimable_rewards.read(&address),
        }
    }

    /// Adds amount to an address's claimable reward in one pool.
    pub fn add_claimable_reward(
        &mut self,
        pool: RewardPool,
        address: Address,
        amount: U256,
    ) -> Result<()> {
        let current = self.get_pool_claimable_reward(pool, address)?;
        let next = checked_add(current, amount, "agentreward claimable_rewards overflow")?;
        self.write_pool_claimable_reward(pool, address, next)
    }

    fn write_pool_claimable_reward(
        &mut self,
        pool: RewardPool,
        address: Address,
        amount: U256,
    ) -> Result<()> {
        match pool {
            RewardPool::Waa => self.waa_claimable_rewards.write(&address, amount),
            RewardPool::Sra => self.sra_claimable_rewards.write(&address, amount),
        }
    }

    /// Claims `amount` of the pool's balance as a Gem, or all of it when `amount`
    /// is zero. Issues the Gem, burns the native COEN that backed it and clears
    /// what was converted. The Gem load is not that COEN - it becomes Promis at
    /// mining time - so leaving the backing in place would let one emission exist
    /// twice.
    ///
    /// The balance is the safe form of the reward and the Gem is not: an unsettled
    /// Gem can be Called and forfeited. Sizing the claim is therefore the agent's
    /// own risk control, and what it leaves behind keeps accruing.
    ///
    /// Any failure reverts the call and leaves the balance for the next day, which
    /// brings a new VWAP with it.
    pub fn claim_reward(
        &mut self,
        pool: RewardPool,
        address: Address,
        amount: U256,
    ) -> Result<U256> {
        let balance = self.get_pool_claimable_reward(pool, address)?;
        if balance.is_zero() {
            return Err(PrecompileError::Revert(
                "no claimable balance in this pool".into(),
            ));
        }
        let requested = if amount.is_zero() { balance } else { amount };
        if requested > balance {
            return Err(PrecompileError::Revert(
                "insufficient claimable balance".into(),
            ));
        }
        // The balance is native COEN; a Gem load is a protocol amount. Only the
        // part that survives the conversion is minted and burned, so a sub-unit
        // remainder keeps accumulating instead of being lost.
        let gem_load = native_to_protocol_floor(requested);
        if gem_load.is_zero() {
            return Err(PrecompileError::Revert(
                "claimed amount is below one protocol unit".into(),
            ));
        }
        let burned = checked_protocol_to_native(gem_load)
            .ok_or_else(|| PrecompileError::Revert("native AgentReward claim overflow".into()))?;
        let entry_price = resolve_gem_entry_price(&self.storage)?.ok_or_else(|| {
            PrecompileError::Revert("agentreward has no usable rudis price yet".into())
        })?;
        let gem_type = match pool {
            RewardPool::Waa => GemTypes::Wallet,
            RewardPool::Sra => GemTypes::Sra,
        };
        let gem_id = outbe_gemfactory::api::issue_gem(
            &self.storage,
            address,
            gem_type,
            gem_load,
            AGENT_GEM_CURRENCY,
            AGENT_GEM_CURRENCY,
            entry_price,
        )?;
        self.storage
            .decrease_balance(outbe_primitives::addresses::AGENT_REWARD_ADDRESS, burned)?;
        self.write_pool_claimable_reward(pool, address, balance - burned)?;

        Ok(gem_id)
    }

    /// Gets all WAA tribute counts for a day as (address, count) pairs.
    pub fn get_all_waa_counts(&self, day: WorldwideDay) -> Result<Vec<(Address, u64)>> {
        let addr_count = self.waa_address_count.read(&day)?;
        let mut result = Vec::with_capacity(addr_count as usize);
        for i in 0..addr_count {
            let idx_key = AgentRewardContract::address_index_key(day, i);
            let addr = self.waa_addresses.read(&idx_key)?;
            if addr.is_zero() {
                continue;
            }
            let count_key = AgentRewardContract::tribute_count_key(day, addr);
            let count = self.waa_tribute_counts.read(&count_key)?;
            if count > 0 {
                result.push((addr, count));
            }
        }
        Ok(result)
    }

    /// Gets all SRA tribute counts for a day as (address, count) pairs.
    pub fn get_all_sra_counts(&self, day: WorldwideDay) -> Result<Vec<(Address, u64)>> {
        let addr_count = self.sra_address_count.read(&day)?;
        let mut result = Vec::with_capacity(addr_count as usize);
        for i in 0..addr_count {
            let idx_key = AgentRewardContract::address_index_key(day, i);
            let addr = self.sra_addresses.read(&idx_key)?;
            if addr.is_zero() {
                continue;
            }
            let count_key = AgentRewardContract::tribute_count_key(day, addr);
            let count = self.sra_tribute_counts.read(&count_key)?;
            if count > 0 {
                result.push((addr, count));
            }
        }
        Ok(result)
    }

    /// Clears WAA tribute counts and address list for a day. Called from
    /// the distribution path once the day's WAA pool has been settled.
    pub fn clear_waa_counts(&mut self, day: WorldwideDay) -> Result<()> {
        let waa_count = self.waa_address_count.read(&day)?;
        for i in 0..waa_count {
            let idx_key = AgentRewardContract::address_index_key(day, i);
            let addr = self.waa_addresses.read(&idx_key)?;
            if !addr.is_zero() {
                let count_key = AgentRewardContract::tribute_count_key(day, addr);
                self.waa_tribute_counts.write(&count_key, 0)?;
                self.waa_addresses.write(&idx_key, Address::ZERO)?;
            }
        }
        self.waa_address_count.write(&day, 0)?;
        Ok(())
    }

    /// Clears SRA tribute counts and address list for a day. Called from
    /// the distribution path once the day's SRA pool has been settled.
    pub fn clear_sra_counts(&mut self, day: WorldwideDay) -> Result<()> {
        let sra_count = self.sra_address_count.read(&day)?;
        for i in 0..sra_count {
            let idx_key = AgentRewardContract::address_index_key(day, i);
            let addr = self.sra_addresses.read(&idx_key)?;
            if !addr.is_zero() {
                let count_key = AgentRewardContract::tribute_count_key(day, addr);
                self.sra_tribute_counts.write(&count_key, 0)?;
                self.sra_addresses.write(&idx_key, Address::ZERO)?;
            }
        }
        self.sra_address_count.write(&day, 0)?;
        Ok(())
    }
}

/// The COEN price an agent reward Gem is issued at: the newest closed UTC day's
/// VWAP, falling back to the live quote. The agent picks the moment it claims,
/// so a price frozen on the day of accrual would be a look-back option.
fn resolve_gem_entry_price(storage: &StorageHandle<'_>) -> Result<Option<U256>> {
    let oracle = outbe_oracle::schema::OracleContract::new(storage.clone());
    let last_finalized_day = oracle.utc_day_vwap_last_finalized.read()?;
    if last_finalized_day != 0 {
        if let Some(index) =
            outbe_oracle::api::coen_pair_index_opt(storage.clone(), AGENT_GEM_CURRENCY)?
        {
            if let Some(vwap) =
                outbe_oracle::api::get_utc_day_vwap(storage.clone(), last_finalized_day, index)?
            {
                return Ok(Some(vwap));
            }
        }
    }

    outbe_oracle::api::fresh_coen_rate_for_opt(storage.clone(), AGENT_GEM_CURRENCY)
}

/// Overflow-checked `U256` addition for reward accounting paths.
fn checked_add(left: U256, right: U256, context: &'static str) -> Result<U256> {
    left.checked_add(right)
        .ok_or_else(|| PrecompileError::Revert(context.into()))
}
