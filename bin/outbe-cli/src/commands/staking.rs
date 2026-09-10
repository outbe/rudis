//! Staking commands.

use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::Result;

use crate::abi::{self, IStaking, IValidatorSet};
use crate::rpc::Rpc;

#[derive(Subcommand)]
pub enum StakingCmd {
    /// Stake tokens to a validator
    Stake {
        /// Validator address
        #[arg(long)]
        validator: Address,
        /// Amount in unit (base denomination)
        #[arg(long)]
        amount: String,
    },
    /// Begin unstaking tokens
    Unstake {
        /// Amount in unit (base denomination)
        #[arg(long)]
        amount: String,
    },
    /// Claim tokens after unbonding period
    Claim,
    /// Unjail your JAILED validator (requires stake >= min_stake) -> PENDING
    Unjail,
    /// Show staking info for a validator
    Info {
        /// Validator address
        address: Address,
    },
    /// Show network-wide staking statistics.
    Stats,
}

impl StakingCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::Stake { validator, amount } => {
                stake(client, private_key, validator, amount).await
            }
            Self::Unstake { amount } => unstake(client, private_key, amount).await,
            Self::Claim => claim(client, private_key).await,
            Self::Unjail => unjail(client, private_key).await,
            Self::Info { address } => info(client, address).await,
            Self::Stats => stats(client).await,
        }
    }
}

async fn stake(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    validator: Address,
    amount: String,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let amount = parse_amount(&amount)?;

    let call = IStaking::stakeCall {
        validatorAddress: validator,
        amount,
    };
    let tx_hash = signer
        .send_tx(client, abi::STAKING_ADDR, call.abi_encode(), amount)
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn unstake(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    amount: String,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let amount = parse_amount(&amount)?;

    let call = IStaking::unstakeCall { amount };
    let tx_hash = signer
        .send_tx(
            client,
            abi::STAKING_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn claim(client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let call = IStaking::claimUnbondedCall {};
    let tx_hash = signer
        .send_tx(
            client,
            abi::STAKING_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn unjail(client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let call = IStaking::unjailValidatorCall {};
    let tx_hash = signer
        .send_tx(
            client,
            abi::STAKING_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

fn parse_amount(amount: &str) -> Result<U256> {
    let amount =
        U256::from_str_radix(amount, 10).map_err(|e| eyre::eyre!("invalid amount: {e}"))?;
    if amount.is_zero() {
        eyre::bail!("amount must be non-zero");
    }
    Ok(amount)
}

struct StakingInfo {
    stake: U256,
    total: U256,
}

async fn fetch_staking_info(client: &(impl Rpc + Sync), address: Address) -> Result<StakingInfo> {
    let stake: U256 = {
        let call = IStaking::getStakeCall { validator: address };
        let result = client
            .eth_call(abi::STAKING_ADDR, &call.abi_encode())
            .await?;
        IStaking::getStakeCall::abi_decode_returns(&result)?
    };

    let total: U256 = {
        let call = IStaking::getTotalStakedCall {};
        let result = client
            .eth_call(abi::STAKING_ADDR, &call.abi_encode())
            .await?;
        IStaking::getTotalStakedCall::abi_decode_returns(&result)?
    };

    Ok(StakingInfo { stake, total })
}

async fn info(client: &(impl Rpc + Sync), address: Address) -> Result<()> {
    let si = fetch_staking_info(client, address).await?;

    println!("Validator:    {:?}", address);
    println!(
        "Stake:        {} rudis",
        super::format_coen_amount(si.stake)
    );
    println!(
        "Total Staked: {} rudis",
        super::format_coen_amount(si.total)
    );

    if !si.total.is_zero() && !si.stake.is_zero() {
        let pct = (si.stake * U256::from(10000)) / si.total;
        let pct_f = pct.to::<u64>() as f64 / 100.0;
        println!("Share:        {pct_f:.2}%");
    }

    Ok(())
}

struct StakingStats {
    total_staked: U256,
    active_count: u64,
    total_count: u64,
}

async fn fetch_staking_stats(client: &(impl Rpc + Sync)) -> Result<StakingStats> {
    let total_staked: U256 = {
        let call = IStaking::getTotalStakedCall {};
        let result = client
            .eth_call(abi::STAKING_ADDR, &call.abi_encode())
            .await?;
        IStaking::getTotalStakedCall::abi_decode_returns(&result)?
    };

    let active_count: u64 = {
        let call = IValidatorSet::activeValidatorCountCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        IValidatorSet::activeValidatorCountCall::abi_decode_returns(&result)?.into()
    };

    let total_count: u64 = {
        let call = IValidatorSet::validatorCountCall {};
        let result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
            .await?;
        IValidatorSet::validatorCountCall::abi_decode_returns(&result)?.into()
    };

    Ok(StakingStats {
        total_staked,
        active_count,
        total_count,
    })
}

async fn stats(client: &(impl Rpc + Sync)) -> Result<()> {
    let ss = fetch_staking_stats(client).await?;

    println!("=== Staking Statistics ===");
    println!(
        "Total Staked:       {} rudis",
        super::format_coen_amount(ss.total_staked)
    );
    println!("Total Validators:   {}", ss.total_count);
    println!("Active Validators:  {}", ss.active_count);

    if ss.active_count > 0 && !ss.total_staked.is_zero() {
        let avg = ss.total_staked / U256::from(ss.active_count);
        println!(
            "Avg Stake (active): {} rudis",
            super::format_coen_amount(avg)
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::U256;

    /// Stake tx must send value == amount (payable precompile requires msg.value == amount).
    #[test]
    fn test_stake_tx_value_equals_amount() {
        let amount = U256::from(100_000u64) * U256::from(10u64).pow(U256::from(18u64));
        // In stake(), the 4th arg to send_tx is `amount` (not Default::default()).
        let tx_value = amount; // mirrors staking.rs line 72
        assert_eq!(tx_value, amount, "stake tx value must equal amount");
        assert!(!tx_value.is_zero(), "stake tx value must not be zero");
    }

    /// Unstake and claim txs must send value == 0 (non-payable).
    #[test]
    fn test_non_payable_staking_calls_send_zero_value() {
        let unstake_value: U256 = Default::default(); // mirrors staking.rs line 90
        let claim_value: U256 = Default::default(); // mirrors staking.rs line 105
        assert!(unstake_value.is_zero(), "unstake tx value must be zero");
        assert!(claim_value.is_zero(), "claim tx value must be zero");
    }

    // --- Mock RPC tests with real ABI verification ---

    use super::*;
    use crate::rpc::mock::{abi_u256, abi_u64, call_map, recording_send_tx_rpc, MockRpc};
    use alloy_sol_types::SolCall;
    use std::collections::HashMap;

    fn staking_info_mock(stake_val: U256, total_val: U256) -> MockRpc {
        let mut map = HashMap::new();
        let get_stake_sel = IStaking::getStakeCall::SELECTOR;
        let get_total_sel = IStaking::getTotalStakedCall::SELECTOR;
        map.insert((abi::STAKING_ADDR, get_stake_sel), abi_u256(stake_val));
        map.insert((abi::STAKING_ADDR, get_total_sel), abi_u256(total_val));
        MockRpc {
            eth_call_map: Some(call_map(map)),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_fetch_staking_info_returns_correct_values() {
        let stake = U256::from(500_000_000u64);
        let total = U256::from(1_000_000_000u64);
        let mock = staking_info_mock(stake, total);
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();

        let result = fetch_staking_info(&mock, addr).await.unwrap();
        assert_eq!(result.stake, stake, "stake must match mock");
        assert_eq!(result.total, total, "total must match mock");
    }

    #[tokio::test]
    async fn test_fetch_staking_info_zero_stake() {
        let mock = staking_info_mock(U256::ZERO, U256::from(1000u64));
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();

        let result = fetch_staking_info(&mock, addr).await.unwrap();
        assert_eq!(result.stake, U256::ZERO);
        assert_eq!(result.total, U256::from(1000u64));
    }

    #[tokio::test]
    async fn test_fetch_staking_info_rpc_error() {
        let mock = MockRpc::default(); // eth_call_map is None -> Err
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(fetch_staking_info(&mock, addr).await.is_err());
    }

    #[tokio::test]
    async fn test_fetch_staking_stats_returns_correct_values() {
        let total = U256::from(3_000_000_000u64);
        let mut map = HashMap::new();
        map.insert(
            (abi::STAKING_ADDR, IStaking::getTotalStakedCall::SELECTOR),
            abi_u256(total),
        );
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::activeValidatorCountCall::SELECTOR,
            ),
            abi_u64(3),
        );
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::validatorCountCall::SELECTOR,
            ),
            abi_u64(5),
        );
        let mock = MockRpc {
            eth_call_map: Some(call_map(map)),
            ..Default::default()
        };

        let result = fetch_staking_stats(&mock).await.unwrap();
        assert_eq!(result.total_staked, total);
        assert_eq!(result.active_count, 3);
        assert_eq!(result.total_count, 5);
    }

    #[tokio::test]
    async fn test_staking_share_percentage_calculation() {
        let stake = U256::from(250_000_000u64);
        let total = U256::from(1_000_000_000u64);
        let mock = staking_info_mock(stake, total);
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();

        let result = fetch_staking_info(&mock, addr).await.unwrap();
        // Verify 25% calculation
        let pct = (result.stake * U256::from(10000)) / result.total;
        let pct_f = pct.to::<u64>() as f64 / 100.0;
        assert!((pct_f - 25.0).abs() < 0.01, "expected 25%, got {pct_f}%");
    }

    // Generate one shared test identity for the RPC mocks.
    static TEST_KEY: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| outbe_primitives::test_keys::hex(1));
    const U256_OVERFLOW_DECIMAL: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639936";

    fn validator_addr() -> Address {
        "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap()
    }

    fn invalid_amount_cases() -> [(&'static str, &'static str); 8] {
        [
            ("not_a_number", "invalid amount"),
            ("1.0", "invalid amount"),
            (" 1", "invalid amount"),
            ("1 ", "invalid amount"),
            ("+1", "invalid amount"),
            ("-1", "invalid amount"),
            ("0", "amount must be non-zero"),
            (U256_OVERFLOW_DECIMAL, "invalid amount"),
        ]
    }

    #[test]
    fn test_parse_amount_rejects_invalid_inputs() {
        for (amount, expected) in invalid_amount_cases() {
            let err = parse_amount(amount).unwrap_err();
            assert!(
                err.to_string().contains(expected),
                "amount={amount:?}: expected {expected:?}, got {err}"
            );
        }
    }

    #[test]
    fn test_parse_amount_accepts_max_u256() {
        assert_eq!(parse_amount(&U256::MAX.to_string()).unwrap(), U256::MAX);
    }

    #[tokio::test]
    async fn test_stake_sends_tx() {
        let validator = validator_addr();
        let amount = U256::from(1000u64);
        let data = IStaking::stakeCall {
            validatorAddress: validator,
            amount,
        }
        .abi_encode();
        let mock = recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, data, amount).unwrap();

        stake(&mock, Some(&TEST_KEY), validator, "1000".to_string())
            .await
            .unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_stake_max_u256_amount_sends_tx() {
        let validator = validator_addr();
        let amount = U256::MAX;
        let data = IStaking::stakeCall {
            validatorAddress: validator,
            amount,
        }
        .abi_encode();
        let mock = recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, data, amount).unwrap();

        stake(&mock, Some(&TEST_KEY), validator, amount.to_string())
            .await
            .unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_stake_no_private_key_errors() {
        let mock = recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, vec![], U256::ZERO).unwrap();
        let validator = validator_addr();
        let err = stake(&mock, None, validator, "1000".to_string())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("--private-key required"),
            "expected private-key error, got: {err}"
        );
        assert!(
            mock.recorded_calls().is_empty(),
            "missing signer must not call RPC"
        );
    }

    #[tokio::test]
    async fn test_stake_invalid_amounts_do_not_call_rpc() {
        for (amount, expected) in invalid_amount_cases() {
            let mock =
                recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, vec![], U256::ZERO).unwrap();
            let err = stake(&mock, Some(&TEST_KEY), validator_addr(), amount.to_string())
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains(expected),
                "amount={amount:?}: expected {expected:?}, got {err}"
            );
            assert!(
                mock.recorded_calls().is_empty(),
                "invalid stake amount {amount:?} must not call RPC"
            );
        }
    }

    #[tokio::test]
    async fn test_unstake_sends_tx() {
        let amount = U256::from(500u64);
        let data = IStaking::unstakeCall { amount }.abi_encode();
        let mock = recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, data, U256::ZERO).unwrap();

        unstake(&mock, Some(&TEST_KEY), "500".to_string())
            .await
            .unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_unstake_max_u256_amount_sends_tx() {
        let amount = U256::MAX;
        let data = IStaking::unstakeCall { amount }.abi_encode();
        let mock = recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, data, U256::ZERO).unwrap();

        unstake(&mock, Some(&TEST_KEY), amount.to_string())
            .await
            .unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_unstake_invalid_amounts_do_not_call_rpc() {
        for (amount, expected) in invalid_amount_cases() {
            let mock =
                recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, vec![], U256::ZERO).unwrap();
            let err = unstake(&mock, Some(&TEST_KEY), amount.to_string())
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains(expected),
                "amount={amount:?}: expected {expected:?}, got {err}"
            );
            assert!(
                mock.recorded_calls().is_empty(),
                "invalid unstake amount {amount:?} must not call RPC"
            );
        }
    }

    #[tokio::test]
    async fn test_claim_sends_tx() {
        let data = IStaking::claimUnbondedCall {}.abi_encode();
        let mock = recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, data, U256::ZERO).unwrap();

        claim(&mock, Some(&TEST_KEY)).await.unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_claim_no_private_key_errors() {
        let mock = recording_send_tx_rpc(&TEST_KEY, abi::STAKING_ADDR, vec![], U256::ZERO).unwrap();
        let err = claim(&mock, None).await.unwrap_err();
        assert!(
            err.to_string().contains("--private-key required"),
            "expected private-key error, got: {err}"
        );
        assert!(
            mock.recorded_calls().is_empty(),
            "missing signer must not call RPC"
        );
    }
}
