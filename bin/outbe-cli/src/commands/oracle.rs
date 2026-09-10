//! Oracle commands.

use alloy_primitives::Address;
use alloy_sol_types::SolCall;
use clap::Subcommand;
use eyre::Result;

use crate::abi::{IOracle, ORACLE_ADDR};
use crate::rpc::Rpc;
use outbe_primitives::asset_type::AssetType;

/// Parses an oracle asset from the operator-facing shorthand.
///
/// `COEN`/`native` is the native asset, a 1-3 digit number is an ISO 4217
/// currency code, and anything else must be a 0x address. Keeps runbooks that
/// say `oracle rate COEN 840` working now that the ABI takes addresses.
fn parse_asset(spec: &str) -> Result<Address> {
    let text = spec.trim();
    if text.eq_ignore_ascii_case("rudis")
        || text.eq_ignore_ascii_case("COEN")
        || text.eq_ignore_ascii_case("native")
    {
        return Ok(Address::ZERO);
    }
    if let Ok(code) = text.parse::<u16>() {
        if (1..=999).contains(&code) {
            return Ok(AssetType::IsoCurrency(code).into());
        }
    }
    text.parse::<Address>()
        .map_err(|e| eyre::eyre!("{spec:?} is not rudis, an ISO 4217 code or a 0x address: {e}"))
}

/// Renders an asset address back into the shorthand `parse_asset` accepts.
fn show_asset(address: Address) -> String {
    match AssetType::from(address) {
        AssetType::Native => outbe_primitives::units::NATIVE_TOKEN_SYMBOL.to_string(),
        AssetType::IsoCurrency(code) => code.to_string(),
        AssetType::ERC20(token) => token.to_string(),
    }
}

fn format_oracle_market_quantity(
    base: Address,
    quote: Address,
    value: alloy_primitives::U256,
) -> String {
    match (AssetType::from(base), AssetType::from(quote)) {
        (AssetType::Native, AssetType::IsoCurrency(_))
        | (AssetType::IsoCurrency(_), AssetType::Native) => super::format_protocol_amount(value),
        _ => super::format_generic_fp18(value),
    }
}

#[derive(Subcommand)]
pub enum OracleCmd {
    /// Show exchange rate for a pair
    Rate {
        /// Base currency (e.g., rudis)
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote as an ISO 4217 numeric code (e.g., 840 for USD)
        #[arg(value_parser = parse_asset)]
        quote: Address,
    },
    /// Show all exchange rates
    Rates,
    /// Show VWAP for a pair
    Vwap {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Lookback period in seconds (default: 86400)
        #[arg(default_value = "86400")]
        seconds: u64,
    },
    /// Show VWAP for a pair over an explicit time range
    VwapRange {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Start timestamp (seconds)
        start_time: u64,
        /// End timestamp (seconds)
        end_time: u64,
    },
    /// Show TWAP for a pair
    Twap {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Lookback period in seconds (default: 86400)
        #[arg(default_value = "86400")]
        seconds: u64,
    },
    /// Show TWAPs for all active vote-target pairs
    Twaps {
        /// Lookback period in seconds (default: 86400)
        #[arg(default_value = "86400")]
        seconds: u64,
    },
    /// Show day VWAP for a pair
    DayVwap {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
    },
    /// Show WorldwideDay-style VWAPs over an explicit time range
    WorldwideDayVwap {
        /// Start timestamp (seconds)
        start_time: u64,
        /// End timestamp (seconds)
        end_time: u64,
    },
    /// Show oracle parameters
    Params,
    /// Show registered pairs and vote targets
    Pairs,
    /// Show whether a pair is an active vote target
    IsVoteTarget {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
    },
    /// Show price snapshot history for a pair
    SnapshotHistory {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Maximum rows to return
        #[arg(long, default_value = "20")]
        count: u32,
    },
    /// Show flattened price snapshot history across all pairs
    AllSnapshotHistory {
        /// Maximum snapshots to return
        #[arg(long, default_value = "20")]
        count: u32,
    },
    /// Show penalty counters for a validator
    Penalty {
        /// Validator address
        validator: Address,
    },
    /// Show feeder delegation for a validator
    Feeder {
        /// Validator address
        validator: Address,
    },
    /// Show pending aggregate vote for a validator
    Vote {
        /// Validator address
        validator: Address,
    },
    /// Show S-curve value for a pair
    Scurve {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Timestamp to evaluate. Defaults to latest block timestamp.
        #[arg(long)]
        timestamp: Option<u64>,
    },
    /// Show active S-curve entries for a pair
    ScurveEntries {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
    },
    /// Show S-curve values for a pair at a timestamp
    ScurveValues {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Timestamp to evaluate
        timestamp: u64,
    },
    /// Show all S-curve data across pairs
    AllScurve,
    /// Show all S-curve data for a pair
    AllScurveForPair {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
    },
    /// Show S-curve adjusted nominal price for a pair
    NominalPrice {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Timestamp to evaluate. Defaults to latest block timestamp.
        #[arg(long)]
        timestamp: Option<u64>,
    },
    /// Show nominal price components for a pair
    NominalComponents {
        /// Base currency
        #[arg(value_parser = parse_asset)]
        base: Address,
        /// Quote currency
        #[arg(value_parser = parse_asset)]
        quote: Address,
        /// Timestamp to evaluate. Defaults to latest block timestamp.
        #[arg(long)]
        timestamp: Option<u64>,
    },
    /// Show vote target pair IDs
    VoteTargets,
    /// Show registered pair count
    PairCount,
    /// Delegate feeder consent to another address
    DelegateFeeder {
        /// Feeder address to delegate to
        feeder: Address,
    },
    /// Show slash window progress for a validator
    SlashProgress {
        /// Validator address
        validator: Address,
    },
}

impl OracleCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::Rate { base, quote } => rate(client, base, quote).await,
            Self::Rates => rates(client).await,
            Self::Vwap {
                base,
                quote,
                seconds,
            } => vwap(client, base, quote, seconds).await,
            Self::VwapRange {
                base,
                quote,
                start_time,
                end_time,
            } => vwap_range(client, base, quote, start_time, end_time).await,
            Self::Twap {
                base,
                quote,
                seconds,
            } => twap(client, base, quote, seconds).await,
            Self::Twaps { seconds } => twaps(client, seconds).await,
            Self::DayVwap { base, quote } => day_vwap(client, base, quote).await,
            Self::WorldwideDayVwap {
                start_time,
                end_time,
            } => worldwide_day_vwap(client, start_time, end_time).await,
            Self::Params => params(client).await,
            Self::Pairs => pairs(client).await,
            Self::IsVoteTarget { base, quote } => is_vote_target(client, base, quote).await,
            Self::SnapshotHistory { base, quote, count } => {
                snapshot_history(client, base, quote, count).await
            }
            Self::AllSnapshotHistory { count } => all_snapshot_history(client, count).await,
            Self::Penalty { validator } => penalty(client, validator).await,
            Self::Feeder { validator } => feeder(client, validator).await,
            Self::Vote { validator } => vote(client, validator).await,
            Self::Scurve {
                base,
                quote,
                timestamp,
            } => scurve(client, base, quote, timestamp).await,
            Self::ScurveEntries { base, quote } => scurve_entries(client, base, quote).await,
            Self::ScurveValues {
                base,
                quote,
                timestamp,
            } => scurve_values(client, base, quote, timestamp).await,
            Self::AllScurve => all_scurve(client).await,
            Self::AllScurveForPair { base, quote } => {
                all_scurve_for_pair(client, base, quote).await
            }
            Self::NominalPrice {
                base,
                quote,
                timestamp,
            } => nominal_price(client, base, quote, timestamp).await,
            Self::NominalComponents {
                base,
                quote,
                timestamp,
            } => nominal_components(client, base, quote, timestamp).await,
            Self::VoteTargets => vote_targets(client).await,
            Self::PairCount => pair_count(client).await,
            Self::DelegateFeeder { feeder } => delegate_feeder(client, private_key, feeder).await,
            Self::SlashProgress { validator } => slash_progress(client, validator).await,
        }
    }
}

async fn rate(client: &(impl Rpc + Sync), base: Address, quote: Address) -> Result<()> {
    let call = IOracle::getExchangeRateDataCall { base, quote };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getExchangeRateDataCall::abi_decode_returns(&result)?;

    println!("=== Exchange Rate: {base}/{quote} ===");
    println!(
        "Rate:      {}",
        format_oracle_market_quantity(base, quote, ret.rate)
    );
    println!("Block:     {}", ret.lastBlock);
    println!("Timestamp: {}", ret.lastTimestamp);
    Ok(())
}

/// The whole rate table, assembled from the registry rather than fetched in one
/// call: the oracle enumerates pairs by index and prices them one at a time.
/// The whole rate table, assembled from the registry rather than fetched in one
/// call: the oracle enumerates pairs by index and prices them one at a time.
async fn rates(client: &(impl Rpc + Sync)) -> Result<()> {
    let count = read_pair_count(client).await?;

    println!(
        "{:<10} {:<10} {:<20} {:<12} {:<12}",
        "Base", "Quote", "Rate", "Block", "Timestamp"
    );
    println!("{}", "-".repeat(66));
    for index in 1..=count {
        let pair = read_pair(client, index).await?;

        let call = IOracle::getExchangeRateDataCall {
            base: pair.base,
            quote: pair.quote,
        };
        let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
        let ret = IOracle::getExchangeRateDataCall::abi_decode_returns(&result)?;

        let (base, quote) = (show_asset(pair.base), show_asset(pair.quote));
        println!(
            "{:<10} {:<10} {:<20} {:<12} {:<12}",
            base,
            quote,
            format_oracle_market_quantity(pair.base, pair.quote, ret.rate),
            ret.lastBlock,
            ret.lastTimestamp
        );
    }
    Ok(())
}

async fn vwap(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    seconds: u64,
) -> Result<()> {
    let call = IOracle::getVwapCall {
        base,
        quote,
        lookbackSeconds: seconds,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getVwapCall::abi_decode_returns(&result)?;
    println!(
        "VWAP {base}/{quote} ({}s lookback): {}",
        seconds,
        format_oracle_market_quantity(base, quote, ret)
    );
    Ok(())
}

async fn vwap_range(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    start_time: u64,
    end_time: u64,
) -> Result<()> {
    let call = IOracle::getVwapForTimeRangeCall {
        base,
        quote,
        startTime: start_time,
        endTime: end_time,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getVwapForTimeRangeCall::abi_decode_returns(&result)?;
    println!(
        "VWAP {base}/{quote} ({start_time}..{end_time}): {}",
        format_oracle_market_quantity(base, quote, ret)
    );
    Ok(())
}

async fn twap(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    seconds: u64,
) -> Result<()> {
    let call = IOracle::getTwapCall {
        base,
        quote,
        lookbackSeconds: seconds,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getTwapCall::abi_decode_returns(&result)?;
    println!(
        "TWAP {base}/{quote} ({}s lookback): {}",
        seconds,
        format_oracle_market_quantity(base, quote, ret)
    );
    Ok(())
}

async fn twaps(client: &(impl Rpc + Sync), seconds: u64) -> Result<()> {
    let call = IOracle::getTwapsCall { lookback: seconds };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getTwapsCall::abi_decode_returns(&result)?;

    println!(
        "{:<10} {:<10} {:<20} {:<12}",
        "Base", "Quote", "TWAP", "Lookback"
    );
    println!("{}", "-".repeat(56));
    for (((base, quote), twap), lookback) in ret
        .bases
        .iter()
        .zip(ret.quotes.iter())
        .zip(ret.twaps.iter())
        .zip(ret.lookbackSeconds.iter())
    {
        println!(
            "{:<10} {:<10} {:<20} {:<12}",
            show_asset(*base),
            show_asset(*quote),
            format_oracle_market_quantity(*base, *quote, *twap),
            lookback
        );
    }
    Ok(())
}

async fn day_vwap(client: &(impl Rpc + Sync), base: Address, quote: Address) -> Result<()> {
    let call = IOracle::getDayVwapCall { base, quote };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getDayVwapCall::abi_decode_returns(&result)?;
    println!(
        "Day VWAP {base}/{quote}: {}",
        format_oracle_market_quantity(base, quote, ret)
    );
    Ok(())
}

async fn worldwide_day_vwap(
    client: &(impl Rpc + Sync),
    start_time: u64,
    end_time: u64,
) -> Result<()> {
    let call = IOracle::getWorldwideDayVwapCall {
        startTime: start_time,
        endTime: end_time,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getWorldwideDayVwapCall::abi_decode_returns(&result)?;

    println!("WorldwideDay VWAP window: {start_time}..{end_time}");
    println!(
        "{:<10} {:<10} {:<20} {:<12}",
        "Base", "Quote", "VWAP", "Lookback"
    );
    println!("{}", "-".repeat(56));
    for (((base, quote), vwap), lookback) in ret
        .bases
        .iter()
        .zip(ret.quotes.iter())
        .zip(ret.vwaps.iter())
        .zip(ret.lookbackSeconds.iter())
    {
        println!(
            "{:<10} {:<10} {:<20} {:<12}",
            show_asset(*base),
            show_asset(*quote),
            format_oracle_market_quantity(*base, *quote, *vwap),
            lookback
        );
    }
    Ok(())
}

async fn params(client: &(impl Rpc + Sync)) -> Result<()> {
    let call = IOracle::getParamsCall {};
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getParamsCall::abi_decode_returns(&result)?;

    println!("=== Oracle Parameters ===");
    println!("Vote Period:        {} blocks", ret.votePeriod);
    println!(
        "Reward Band:        {}",
        super::format_generic_fp18(ret.rewardBand)
    );
    println!("Slash Window:       {} blocks", ret.slashWindow);
    println!(
        "Min Valid/Window:   {}",
        super::format_generic_fp18(ret.minValidPerWindow)
    );
    println!(
        "Slash Fraction:     {}",
        super::format_generic_fp18(ret.slashFraction)
    );
    println!("Lookback Duration:  {}s", ret.lookbackDuration);
    println!("Enabled:            {}", ret.enabled);
    Ok(())
}

async fn pairs(client: &(impl Rpc + Sync)) -> Result<()> {
    let count = read_pair_count(client).await?;
    if count == 0 {
        println!("No oracle pairs registered.");
        return Ok(());
    }

    println!("{:<10} {:<10} {:<8}", "Base", "Quote", "Active");
    println!("{}", "-".repeat(32));
    for index in 1..=count {
        let pair = read_pair(client, index).await?;

        let call = IOracle::isVoteTargetCall {
            base: pair.base,
            quote: pair.quote,
        };
        let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
        let active = IOracle::isVoteTargetCall::abi_decode_returns(&result)?;

        // Rendered back into the shorthand the commands accept, so ISO 840
        // prints as `840` rather than its reserved address.
        let (base, quote) = (show_asset(pair.base), show_asset(pair.quote));
        println!("{base:<10} {quote:<10} {active:<8}");
    }
    Ok(())
}

/// Number of registered pairs - the bound for walking the registry by index.
async fn read_pair_count(client: &(impl Rpc + Sync)) -> Result<u32> {
    let call = IOracle::getPairCountCall {};
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    Ok(IOracle::getPairCountCall::abi_decode_returns(&result)?)
}

async fn read_pair(
    client: &(impl Rpc + Sync),
    index: u32,
) -> Result<IOracle::getPairByIndexReturn> {
    let call = IOracle::getPairByIndexCall { index };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    Ok(IOracle::getPairByIndexCall::abi_decode_returns(&result)?)
}

async fn pair_count(client: &(impl Rpc + Sync)) -> Result<()> {
    let call = IOracle::getPairCountCall {};
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let count = IOracle::getPairCountCall::abi_decode_returns(&result)?;

    println!("Registered pairs: {count}");
    Ok(())
}

async fn vote_targets(client: &(impl Rpc + Sync)) -> Result<()> {
    let call = IOracle::getVoteTargetsCall {};
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let targets = IOracle::getVoteTargetsCall::abi_decode_returns(&result)?;

    println!("Active vote target bases:  {:?}", targets.bases);
    println!("Active vote target quotes: {:?}", targets.quotes);
    Ok(())
}

async fn is_vote_target(client: &(impl Rpc + Sync), base: Address, quote: Address) -> Result<()> {
    let call = IOracle::isVoteTargetCall { base, quote };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let active = IOracle::isVoteTargetCall::abi_decode_returns(&result)?;

    println!("Vote target {base}/{quote}: {active}");
    Ok(())
}

async fn snapshot_history(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    count: u32,
) -> Result<()> {
    let call = IOracle::getPriceSnapshotHistoryCall { base, quote, count };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getPriceSnapshotHistoryCall::abi_decode_returns(&result)?;

    println!("=== Snapshot History: {base}/{quote} ===");
    println!("{:<12} {:<20} {:<20}", "Timestamp", "Rate", "Volume");
    println!("{}", "-".repeat(56));
    for ((timestamp, rate), volume) in ret
        .timestamps
        .iter()
        .zip(ret.rates.iter())
        .zip(ret.volumes.iter())
    {
        println!(
            "{:<12} {:<20} {:<20}",
            timestamp,
            format_oracle_market_quantity(base, quote, *rate),
            format_oracle_market_quantity(base, quote, *volume)
        );
    }
    Ok(())
}

async fn all_snapshot_history(client: &(impl Rpc + Sync), count: u32) -> Result<()> {
    let call = IOracle::getAllPriceSnapshotHistoryCall { count };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getAllPriceSnapshotHistoryCall::abi_decode_returns(&result)?;

    println!(
        "{:<10} {:<12} {:<10} {:<10} {:<20} {:<20}",
        "Snapshot", "Timestamp", "Base", "Quote", "Rate", "Volume"
    );
    println!("{}", "-".repeat(90));
    for (((((snapshot_id, timestamp), base), quote), rate), volume) in ret
        .snapshotIds
        .iter()
        .zip(ret.timestamps.iter())
        .zip(ret.bases.iter())
        .zip(ret.quotes.iter())
        .zip(ret.rates.iter())
        .zip(ret.volumes.iter())
    {
        println!(
            "{:<10} {:<12} {:<10} {:<10} {:<20} {:<20}",
            snapshot_id,
            timestamp,
            show_asset(*base),
            show_asset(*quote),
            format_oracle_market_quantity(*base, *quote, *rate),
            format_oracle_market_quantity(*base, *quote, *volume)
        );
    }
    Ok(())
}

async fn penalty(client: &(impl Rpc + Sync), validator: Address) -> Result<()> {
    let call = IOracle::getVotePenaltyCounterCall { validator };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getVotePenaltyCounterCall::abi_decode_returns(&result)?;

    println!("=== Penalty Counters for {validator} ===");
    println!("Success: {}", ret.success);
    println!("Abstain: {}", ret.abstain);
    println!("Miss:    {}", ret.miss);
    Ok(())
}

async fn feeder(client: &(impl Rpc + Sync), validator: Address) -> Result<()> {
    let call = IOracle::getFeederDelegationCall { validator };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getFeederDelegationCall::abi_decode_returns(&result)?;

    if ret == Address::ZERO {
        println!("Feeder for {validator}: self-delegation (no delegate)");
    } else {
        println!("Feeder for {validator}: {ret}");
    }
    Ok(())
}

async fn vote(client: &(impl Rpc + Sync), validator: Address) -> Result<()> {
    let call = IOracle::getAggregateVoteCall { validator };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getAggregateVoteCall::abi_decode_returns(&result)?;

    if !ret.exists {
        println!("No pending vote for {validator}");
        return Ok(());
    }

    println!("=== Aggregate Vote for {validator} ===");
    println!(
        "{:<10} {:<10} {:<20} {:<20}",
        "Base", "Quote", "Rate", "Volume"
    );
    println!("{}", "-".repeat(62));
    for (((base, quote), rate), vol) in ret
        .bases
        .iter()
        .zip(ret.quotes.iter())
        .zip(ret.rates.iter())
        .zip(ret.volumes.iter())
    {
        println!(
            "{:<10} {:<10} {:<20} {:<20}",
            show_asset(*base),
            show_asset(*quote),
            format_oracle_market_quantity(*base, *quote, *rate),
            format_oracle_market_quantity(*base, *quote, *vol)
        );
    }
    Ok(())
}

async fn scurve(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    timestamp: Option<u64>,
) -> Result<()> {
    let timestamp = resolve_timestamp(client, timestamp).await?;
    let call = IOracle::getScurveValueCall {
        base,
        quote,
        timestamp,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getScurveValueCall::abi_decode_returns(&result)?;
    println!(
        "S-curve value {base}/{quote} at {timestamp}: {}",
        format_oracle_market_quantity(base, quote, ret)
    );
    Ok(())
}

async fn scurve_entries(client: &(impl Rpc + Sync), base: Address, quote: Address) -> Result<()> {
    let call = IOracle::getScurveEntriesCall { base, quote };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getScurveEntriesCall::abi_decode_returns(&result)?;

    println!("=== Active S-curve Entries: {base}/{quote} ===");
    println!(
        "{:<12} {:<20} {:<20}",
        "PeakDay", "PeakPrice", "CurrentValue"
    );
    println!("{}", "-".repeat(58));
    for ((peak_day, peak_price), current_value) in ret
        .peakDays
        .iter()
        .zip(ret.peakPrices.iter())
        .zip(ret.currentValues.iter())
    {
        println!(
            "{:<12} {:<20} {:<20}",
            peak_day,
            format_oracle_market_quantity(base, quote, *peak_price),
            format_oracle_market_quantity(base, quote, *current_value)
        );
    }
    Ok(())
}

async fn scurve_values(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    timestamp: u64,
) -> Result<()> {
    let call = IOracle::getScurveValuesCall {
        base,
        quote,
        timestamp,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getScurveValuesCall::abi_decode_returns(&result)?;

    println!("Target day: {}", ret.targetDay);
    println!("{:<12} {:<20} {:<20}", "PeakDay", "PeakPrice", "Value");
    println!("{}", "-".repeat(58));
    for ((peak_day, peak_price), value) in ret
        .peakDays
        .iter()
        .zip(ret.peakPrices.iter())
        .zip(ret.values.iter())
    {
        println!(
            "{:<12} {:<20} {:<20}",
            peak_day,
            format_oracle_market_quantity(base, quote, *peak_price),
            format_oracle_market_quantity(base, quote, *value)
        );
    }
    Ok(())
}

async fn all_scurve(client: &(impl Rpc + Sync)) -> Result<()> {
    let call = IOracle::getAllScurveDataCall {};
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getAllScurveDataCall::abi_decode_returns(&result)?;

    println!(
        "{:<10} {:<10} {:<12} {:<20}",
        "Base", "Quote", "PeakDay", "PeakPrice"
    );
    println!("{}", "-".repeat(56));
    for (((base, quote), peak_day), peak_price) in ret
        .bases
        .iter()
        .zip(ret.quotes.iter())
        .zip(ret.peakDays.iter())
        .zip(ret.peakPrices.iter())
    {
        println!(
            "{:<10} {:<10} {:<12} {:<20}",
            show_asset(*base),
            show_asset(*quote),
            peak_day,
            format_oracle_market_quantity(*base, *quote, *peak_price)
        );
    }
    Ok(())
}

async fn all_scurve_for_pair(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
) -> Result<()> {
    let call = IOracle::getAllScurveDataForPairCall { base, quote };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getAllScurveDataForPairCall::abi_decode_returns(&result)?;

    println!("=== All S-curve Data: {base}/{quote} ===");
    println!("{:<12} {:<20}", "PeakDay", "PeakPrice");
    println!("{}", "-".repeat(34));
    for (peak_day, peak_price) in ret.peakDays.iter().zip(ret.peakPrices.iter()) {
        println!(
            "{:<12} {:<20}",
            peak_day,
            format_oracle_market_quantity(base, quote, *peak_price)
        );
    }
    Ok(())
}

async fn nominal_price(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    timestamp: Option<u64>,
) -> Result<()> {
    let timestamp = resolve_timestamp(client, timestamp).await?;
    let call = IOracle::getNominalPriceCall {
        base,
        quote,
        timestamp,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getNominalPriceCall::abi_decode_returns(&result)?;
    println!(
        "Nominal price {base}/{quote} at {timestamp}: {}",
        format_oracle_market_quantity(base, quote, ret)
    );
    Ok(())
}

async fn nominal_components(
    client: &(impl Rpc + Sync),
    base: Address,
    quote: Address,
    timestamp: Option<u64>,
) -> Result<()> {
    let timestamp = resolve_timestamp(client, timestamp).await?;
    let call = IOracle::getNominalPriceComponentsCall {
        base,
        quote,
        timestamp,
    };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getNominalPriceComponentsCall::abi_decode_returns(&result)?;

    println!("=== Nominal Price Components: {base}/{quote} at {timestamp} ===");
    println!(
        "Nominal:   {}",
        format_oracle_market_quantity(base, quote, ret.nominalPrice)
    );
    println!(
        "VWAP:      {}",
        format_oracle_market_quantity(base, quote, ret.vwap)
    );
    println!(
        "MaxCurve:  {}",
        format_oracle_market_quantity(base, quote, ret.maxScurve)
    );
    println!("Source:    {}", ret.source);
    Ok(())
}

async fn delegate_feeder(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    feeder: Address,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let call = IOracle::delegateFeederConsentCall { feeder };
    let tx_hash = signer
        .send_tx(client, ORACLE_ADDR, call.abi_encode(), Default::default())
        .await?;
    println!("Feeder delegation tx sent: {tx_hash}");
    Ok(())
}

async fn slash_progress(client: &(impl Rpc + Sync), validator: Address) -> Result<()> {
    let call = IOracle::getSlashWindowProgressCall { validator };
    let result = client.eth_call(ORACLE_ADDR, &call.abi_encode()).await?;
    let ret = IOracle::getSlashWindowProgressCall::abi_decode_returns(&result)?;

    println!("=== Slash Window Progress for {validator} ===");
    println!("Success:      {}", ret.success);
    println!("Abstain:      {}", ret.abstain);
    println!("Miss:         {}", ret.miss);
    println!("Slash Window: {} blocks", ret.slashWindow);

    let total = ret
        .success
        .saturating_add(ret.abstain)
        .saturating_add(ret.miss);
    if total > 0 {
        println!("Valid Rate:   {}", format_percent(ret.success, total));
    }
    Ok(())
}

async fn resolve_timestamp(client: &(impl Rpc + Sync), timestamp: Option<u64>) -> Result<u64> {
    if let Some(timestamp) = timestamp {
        return Ok(timestamp);
    }

    let latest = client.eth_get_latest_block().await?;
    latest
        .get("timestamp")
        .and_then(|value| value.as_str())
        .ok_or_else(|| eyre::eyre!("latest block response is missing timestamp"))
        .and_then(parse_hex_u64)
}

fn parse_hex_u64(value: &str) -> Result<u64> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(value, 16).map_err(|e| eyre::eyre!("failed to parse timestamp: {e}"))
}

fn format_percent(numerator: u64, denominator: u64) -> String {
    if denominator == 0 {
        return "n/a".to_string();
    }

    let basis_points = u128::from(numerator) * 10_000 / u128::from(denominator);
    let whole = basis_points / 100;
    let frac = basis_points % 100;
    format!("{whole}.{frac:02}%")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_aliases_render_as_rudis() {
        for alias in ["rudis", "RUDIS", "COEN", "native"] {
            let asset = parse_asset(alias).unwrap();
            assert_eq!(asset, Address::ZERO);
            assert_eq!(show_asset(asset), "rudis");
        }
    }

    #[test]
    fn test_oracle_cmd_parse() {
        use clap::Parser;

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: OracleCmd,
        }

        let cli = TestCli::try_parse_from(["test", "params"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "rate", "COEN", "840"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "rates"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "vwap", "COEN", "840", "3600"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "vwap-range", "COEN", "840", "100", "200"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "twap", "COEN", "840", "3600"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "twaps", "3600"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "day-vwap", "COEN", "840"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "worldwide-day-vwap", "100", "200"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "pairs"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "pair-count"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "vote-targets"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "is-vote-target", "COEN", "840"]);
        assert!(cli.is_ok());

        let cli =
            TestCli::try_parse_from(["test", "snapshot-history", "COEN", "840", "--count", "5"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "all-snapshot-history", "--count", "5"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from([
            "test",
            "penalty",
            "0x1111111111111111111111111111111111111111",
        ]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "scurve", "COEN", "840"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "scurve", "COEN", "840", "--timestamp", "123"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "scurve-entries", "COEN", "840"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "scurve-values", "COEN", "840", "123"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "all-scurve"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "all-scurve-for-pair", "COEN", "840"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from(["test", "nominal-price", "COEN", "840"]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from([
            "test",
            "nominal-components",
            "COEN",
            "840",
            "--timestamp",
            "123",
        ]);
        assert!(cli.is_ok());

        let cli = TestCli::try_parse_from([
            "test",
            "delegate-feeder",
            "0x1111111111111111111111111111111111111111",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn test_format_percent_uses_integer_math() {
        assert_eq!(format_percent(1, 3), "33.33%");
        assert_eq!(format_percent(0, 0), "n/a");
    }

    #[test]
    fn test_parse_hex_u64_timestamp() {
        assert_eq!(parse_hex_u64("0x7b").unwrap(), 123);
        assert_eq!(parse_hex_u64("7b").unwrap(), 123);
        assert!(parse_hex_u64("0xnot-hex").is_err());
    }
}
