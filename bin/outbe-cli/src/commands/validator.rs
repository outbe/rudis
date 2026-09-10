//! Validator management commands.

use alloy_primitives::{Address, B256};
use alloy_sol_types::SolCall;
use clap::{Subcommand, ValueEnum};
use eyre::{ensure, Result, WrapErr as _};
use outbe_primitives::consensus_p2p::{
    decode_versioned, encode_v1, P2pAddress, P2pIngress, P2P_ADDRESS_VERSION_V1,
};
use std::{net::SocketAddr, path::PathBuf};

use crate::abi::{self, IValidatorSet};
use crate::rpc::Rpc;

#[derive(Subcommand)]
pub enum ValidatorCmd {
    /// List validators
    List {
        /// Show only active validators
        #[arg(long)]
        active_only: bool,
        /// Filter by status: active, inactive, exiting, unbonding
        #[arg(long)]
        status: Option<String>,
        /// Sort by: stake, address, status (default: index)
        #[arg(long)]
        sort: Option<String>,
    },
    /// Show detailed validator info
    Info {
        /// Validator address
        address: Address,
    },
    /// Show participation stats for all active validators.
    Participation,
    /// Register a new validator
    Register {
        /// BLS consensus public key (hex)
        #[arg(long)]
        pubkey: String,
        /// Radicle Ed25519 NodeId as 32-byte hex.
        #[arg(long)]
        radicle_node_id: B256,
        /// BLS registration signature (hex)
        #[arg(long)]
        bls_sig: String,
    },
    /// Deactivate your validator
    Deactivate,
    /// Confirm your PENDING validator has caught up to head and is ready to be
    /// included in the next DKG reshare target (stale-join guard). Send only
    /// after `outbe-cli monitor` / `rudis_syncStatus` shows the node at tip.
    ConfirmReady {
        /// Canonical binary OcompKeyRegistrationV1 produced for this validator.
        #[arg(long, value_name = "PATH")]
        registration: PathBuf,
    },
    /// Assign a role-scoped operational key to this validator.
    Delegate {
        /// Operational role granted to the delegate.
        #[arg(value_enum)]
        role: ValidatorDelegateRoleArg,
        /// Dedicated operational EVM address.
        delegate: Address,
    },
    /// Revoke this validator's operational key for one role.
    RevokeDelegate {
        /// Operational role to revoke.
        #[arg(value_enum)]
        role: ValidatorDelegateRoleArg,
    },
    /// Read a validator's operational key for one role.
    GetDelegate {
        validator: Address,
        #[arg(value_enum)]
        role: ValidatorDelegateRoleArg,
    },
    /// Set a validator Commonware P2P address in the on-chain registry
    SetP2p {
        /// Validator address to update. Defaults to the signer address.
        #[arg(long)]
        validator: Option<Address>,
        /// Symmetric socket address, e.g. 10.0.0.1:30400.
        #[arg(long)]
        symmetric: Option<SocketAddr>,
        /// Asymmetric socket ingress address.
        #[arg(long)]
        ingress_socket: Option<SocketAddr>,
        /// Asymmetric DNS ingress host.
        #[arg(long)]
        ingress_dns_host: Option<String>,
        /// Asymmetric DNS ingress port.
        #[arg(long)]
        ingress_dns_port: Option<u16>,
        /// Asymmetric egress socket address.
        #[arg(long)]
        egress: Option<SocketAddr>,
    },
    /// Read a validator Commonware P2P address registry entry
    GetP2p {
        /// Validator address
        validator: Address,
    },
}

impl ValidatorCmd {
    pub async fn run(self, client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
        match self {
            Self::List {
                active_only,
                status,
                sort,
            } => list(client, active_only, status, sort).await,
            Self::Info { address } => info(client, address).await,
            Self::Participation => participation(client).await,
            Self::Register {
                pubkey,
                radicle_node_id,
                bls_sig,
            } => register(client, private_key, pubkey, radicle_node_id, bls_sig).await,
            Self::Deactivate => deactivate(client, private_key).await,
            Self::ConfirmReady { registration } => {
                confirm_ready(client, private_key, registration).await
            }
            Self::Delegate {
                role,
                delegate: delegate_address,
            } => delegate(client, private_key, role, delegate_address).await,
            Self::RevokeDelegate { role } => revoke_delegate(client, private_key, role).await,
            Self::GetDelegate { validator, role } => get_delegate(client, validator, role).await,
            Self::SetP2p {
                validator,
                symmetric,
                ingress_socket,
                ingress_dns_host,
                ingress_dns_port,
                egress,
            } => {
                let options = SetP2pOptions {
                    validator,
                    symmetric,
                    ingress_socket,
                    ingress_dns_host,
                    ingress_dns_port,
                    egress,
                };
                set_p2p(client, private_key, options).await
            }
            Self::GetP2p { validator } => get_p2p(client, validator).await,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ValidatorDelegateRoleArg {
    Oracle,
    Ocomp,
}

impl ValidatorDelegateRoleArg {
    const fn id(self) -> u8 {
        match self {
            Self::Oracle => 1,
            Self::Ocomp => 2,
        }
    }
}

struct SetP2pOptions {
    validator: Option<Address>,
    symmetric: Option<SocketAddr>,
    ingress_socket: Option<SocketAddr>,
    ingress_dns_host: Option<String>,
    ingress_dns_port: Option<u16>,
    egress: Option<SocketAddr>,
}

async fn list(
    client: &(impl Rpc + Sync),
    active_only: bool,
    status_filter: Option<String>,
    sort_by: Option<String>,
) -> Result<()> {
    // If --status is provided, always fetch all validators to filter
    let fetch_all = status_filter.is_some() && !active_only;
    let call = if active_only && !fetch_all {
        IValidatorSet::getActiveValidatorsCall {}.abi_encode()
    } else {
        IValidatorSet::getValidatorsCall {}.abi_encode()
    };

    let result = client.eth_call(abi::VALIDATOR_SET_ADDR, &call).await?;

    let addrs = if active_only && !fetch_all {
        IValidatorSet::getActiveValidatorsCall::abi_decode_returns(&result)?
    } else {
        IValidatorSet::getValidatorsCall::abi_decode_returns(&result)?
    };

    if addrs.is_empty() {
        println!("No validators found.");
        return Ok(());
    }

    // Parse status filter (codes must match validatorset/logic.rs:42-48).
    let status_code: Option<u8> = status_filter.as_deref().map(parse_status_filter);

    // Fetch details for all validators
    struct Row {
        addr: Address,
        status: u8,
        stake: alloy_primitives::U256,
    }
    let mut rows = Vec::with_capacity(addrs.len());

    for addr in &addrs {
        let detail_call = IValidatorSet::validatorByAddressCall { addr: *addr }.abi_encode();
        let detail_result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &detail_call)
            .await?;
        let detail = IValidatorSet::validatorByAddressCall::abi_decode_returns(&detail_result)?;

        // Apply status filter
        if let Some(code) = status_code {
            if detail.status != code {
                continue;
            }
        }

        rows.push(Row {
            addr: *addr,
            status: detail.status,
            stake: detail.stake,
        });
    }

    // Apply sorting
    if let Some(ref sort) = sort_by {
        match sort.to_lowercase().as_str() {
            "stake" => rows.sort_by_key(|a| std::cmp::Reverse(a.stake)),
            "address" => rows.sort_by_key(|a| a.addr),
            "status" => rows.sort_by_key(|a| a.status),
            _ => {} // keep original order
        }
    }

    if rows.is_empty() {
        println!("No validators match the filter.");
        return Ok(());
    }

    println!(
        "{:<4} {:<44} {:>8} {:>12}",
        "#", "Address", "Status", "Stake"
    );
    println!("{}", "-".repeat(72));

    for (i, row) in rows.iter().enumerate() {
        println!(
            "{:<4} {:?} {:>8} {:>12}",
            i + 1,
            row.addr,
            status_label(row.status),
            super::format_coen_amount(row.stake),
        );
    }

    Ok(())
}

async fn info(client: &(impl Rpc + Sync), address: Address) -> Result<()> {
    let call = IValidatorSet::validatorByAddressCall { addr: address }.abi_encode();
    let result = client.eth_call(abi::VALIDATOR_SET_ADDR, &call).await?;
    let v = IValidatorSet::validatorByAddressCall::abi_decode_returns(&result)?;

    println!("Validator:            {:?}", v.validatorAddress);
    println!(
        "Consensus Pubkey:     0x{}",
        hex::encode(&v.consensusPubkey)
    );
    println!(
        "Status:               {} ({})",
        v.status,
        status_label(v.status)
    );
    println!(
        "Stake:                {} rudis",
        super::format_coen_amount(v.stake)
    );
    println!("Slash Count:          {}", v.slashCount);
    println!("Missed Blocks:        {}", v.missedBlocks);
    println!("Missed Votes:         {}", v.missedVotes);
    println!("Blocks Proposed:      {}", v.blocksProposed);
    println!("Joined At Height:     {}", v.joinedAtHeight);
    println!("Deactivated At:       {}", v.deactivatedAtHeight);
    println!("Unbonding End:        {}", v.unbondingEnd);
    println!("Has BLS Share:        {}", v.hasBLSShare);

    Ok(())
}

async fn register(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    pubkey: String,
    radicle_node_id: B256,
    bls_sig: String,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let pubkey_bytes = hex::decode(pubkey.strip_prefix("0x").unwrap_or(&pubkey))?;
    let sig_bytes = hex::decode(bls_sig.strip_prefix("0x").unwrap_or(&bls_sig))?;

    let call = IValidatorSet::registerValidatorCall {
        validatorAddress: signer.address(),
        consensusPubkey: pubkey_bytes.into(),
        radicleNodeId: radicle_node_id,
        blsRegistrationSignature: sig_bytes.into(),
    };

    let tx_hash = signer
        .send_tx(
            client,
            abi::VALIDATOR_SET_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn deactivate(client: &(impl Rpc + Sync), private_key: Option<&str>) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let call = IValidatorSet::deactivateValidatorCall {
        validatorAddress: signer.address(),
    };

    let tx_hash = signer
        .send_tx(
            client,
            abi::VALIDATOR_SET_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn confirm_ready(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    registration_path: PathBuf,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let registration = std::fs::read(&registration_path).wrap_err_with(|| {
        format!(
            "failed to read canonical OCOMP registration {}",
            registration_path.display()
        )
    })?;
    ensure!(!registration.is_empty(), "OCOMP registration file is empty");
    let call = IValidatorSet::confirmValidatorReadyCall {
        registration: registration.into(),
    };

    let tx_hash = signer
        .send_tx(
            client,
            abi::VALIDATOR_SET_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn delegate(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    role: ValidatorDelegateRoleArg,
    delegate: Address,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let call = IValidatorSet::setDelegateCall {
        role: role.id(),
        delegate,
    };
    let tx_hash = signer
        .send_tx(
            client,
            abi::VALIDATOR_SET_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn revoke_delegate(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    role: ValidatorDelegateRoleArg,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let call = IValidatorSet::revokeDelegateCall { role: role.id() };
    let tx_hash = signer
        .send_tx(
            client,
            abi::VALIDATOR_SET_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn get_delegate(
    client: &(impl Rpc + Sync),
    validator: Address,
    role: ValidatorDelegateRoleArg,
) -> Result<()> {
    let call = IValidatorSet::getDelegateCall {
        validator,
        role: role.id(),
    };
    let result = client
        .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
        .await?;
    let delegate = IValidatorSet::getDelegateCall::abi_decode_returns(&result)?;
    println!("Validator: {validator:?}");
    println!("Role:      {role:?}");
    println!("Delegate:  {delegate:?}");
    Ok(())
}

async fn set_p2p(
    client: &(impl Rpc + Sync),
    private_key: Option<&str>,
    options: SetP2pOptions,
) -> Result<()> {
    let signer = super::require_signer(private_key)?;
    let validator = options.validator.unwrap_or_else(|| signer.address());
    let address = build_p2p_address(
        options.symmetric,
        options.ingress_socket,
        options.ingress_dns_host,
        options.ingress_dns_port,
        options.egress,
    )?;
    let encoded = encode_v1(&address);
    let call = IValidatorSet::setP2pAddressCall {
        validatorAddress: validator,
        version: P2P_ADDRESS_VERSION_V1,
        encoded: encoded.into(),
    };
    let tx_hash = signer
        .send_tx(
            client,
            abi::VALIDATOR_SET_ADDR,
            call.abi_encode(),
            Default::default(),
        )
        .await?;
    println!("Transaction sent: {tx_hash}");
    Ok(())
}

async fn get_p2p(client: &(impl Rpc + Sync), validator: Address) -> Result<()> {
    let call = IValidatorSet::getP2pAddressCall {
        validatorAddress: validator,
    };
    let result = client
        .eth_call(abi::VALIDATOR_SET_ADDR, &call.abi_encode())
        .await?;
    let ret = IValidatorSet::getP2pAddressCall::abi_decode_returns(&result)?;
    println!("Validator:       {validator:?}");
    println!("Version:         {}", ret.version);
    println!("Encoded:         0x{}", hex::encode(&ret.encoded));
    if ret.version != 0 || !ret.encoded.is_empty() {
        let decoded = decode_versioned(ret.version, &ret.encoded)
            .wrap_err("registry payload failed local decode")?;
        println!("Decoded:         {decoded:?}");
    }
    Ok(())
}

fn build_p2p_address(
    symmetric: Option<SocketAddr>,
    ingress_socket: Option<SocketAddr>,
    ingress_dns_host: Option<String>,
    ingress_dns_port: Option<u16>,
    egress: Option<SocketAddr>,
) -> Result<P2pAddress> {
    if let Some(socket) = symmetric {
        ensure!(
            ingress_socket.is_none()
                && ingress_dns_host.is_none()
                && ingress_dns_port.is_none()
                && egress.is_none(),
            "--symmetric cannot be combined with asymmetric ingress/egress options"
        );
        return Ok(P2pAddress::Symmetric(socket));
    }

    let egress = egress.ok_or_else(|| eyre::eyre!("--egress is required for asymmetric p2p"))?;
    let ingress = match (ingress_socket, ingress_dns_host, ingress_dns_port) {
        (Some(socket), None, None) => P2pIngress::Socket(socket),
        (None, Some(host), Some(port)) => P2pIngress::Dns { host, port },
        (None, Some(_), None) => {
            return Err(eyre::eyre!(
                "--ingress-dns-port is required with --ingress-dns-host"
            ));
        }
        (None, None, Some(_)) => {
            return Err(eyre::eyre!(
                "--ingress-dns-host is required with --ingress-dns-port"
            ));
        }
        _ => {
            return Err(eyre::eyre!(
                "set exactly one asymmetric ingress: --ingress-socket or --ingress-dns-host/--ingress-dns-port"
            ));
        }
    };
    Ok(P2pAddress::Asymmetric { ingress, egress })
}

async fn participation(client: &(impl Rpc + Sync)) -> Result<()> {
    let addrs: Vec<Address> = {
        let call = IValidatorSet::getActiveValidatorsCall {}.abi_encode();
        let result = client.eth_call(abi::VALIDATOR_SET_ADDR, &call).await?;
        IValidatorSet::getActiveValidatorsCall::abi_decode_returns(&result)?
    };

    if addrs.is_empty() {
        println!("No active validators.");
        return Ok(());
    }

    println!(
        "{:<4} {:<44} {:>10} {:>10} {:>10} {:>8}",
        "#", "Address", "Proposed", "Miss.Blk", "Miss.Vote", "Uptime%"
    );
    println!("{}", "-".repeat(90));

    for (i, addr) in addrs.iter().enumerate() {
        let detail_call = IValidatorSet::validatorByAddressCall { addr: *addr }.abi_encode();
        let detail_result = client
            .eth_call(abi::VALIDATOR_SET_ADDR, &detail_call)
            .await?;
        let v = IValidatorSet::validatorByAddressCall::abi_decode_returns(&detail_result)?;

        let total_opportunities = v.blocksProposed + v.missedBlocks;
        let uptime = if total_opportunities > 0 {
            v.blocksProposed as f64 / total_opportunities as f64 * 100.0
        } else {
            100.0 // no blocks to miss yet
        };

        println!(
            "{:<4} {:?} {:>10} {:>10} {:>10} {:>7.1}%",
            i + 1,
            addr,
            v.blocksProposed,
            v.missedBlocks,
            v.missedVotes,
            uptime,
        );
    }

    Ok(())
}

fn status_label(status: u8) -> &'static str {
    match status {
        0 => "Registered",
        1 => "Pending",
        2 => "Active",
        3 => "Exiting",
        4 => "Unbonding",
        5 => "Inactive",
        6 => "Jailed",
        _ => "Unknown",
    }
}

/// Parse a string status filter into the numeric code used by ValidatorSet.
/// Returns 255 for unknown strings (matches nothing).
fn parse_status_filter(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "registered" => 0,
        "pending" => 1,
        "active" => 2,
        "exiting" => 3,
        "unbonding" => 4,
        "inactive" => 5,
        "jailed" => 6,
        _ => 255,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_filter_maps_to_correct_codes() {
        // Must match `validator_status` in validatorset/src/runtime.rs.
        assert_eq!(parse_status_filter("registered"), 0);
        assert_eq!(parse_status_filter("pending"), 1);
        assert_eq!(parse_status_filter("active"), 2);
        assert_eq!(parse_status_filter("exiting"), 3);
        assert_eq!(parse_status_filter("unbonding"), 4);
        assert_eq!(parse_status_filter("inactive"), 5);
        assert_eq!(parse_status_filter("jailed"), 6);
        // Case insensitive
        assert_eq!(parse_status_filter("Active"), 2);
        assert_eq!(parse_status_filter("UNBONDING"), 4);
    }

    #[test]
    fn test_unknown_status_filter_returns_255() {
        // 255 is the "matches nothing" sentinel for strings that are not a
        // canonical status name. PENDING (1) is a real lifecycle status, so it
        // IS user-filterable and is covered by the positive test above.
        assert_eq!(parse_status_filter("bogus"), 255);
        assert_eq!(parse_status_filter(""), 255);
        assert_eq!(parse_status_filter("notastatus"), 255);
    }

    // --- Mock RPC tests ---
    use crate::rpc::mock::{call_map, recording_send_tx_rpc, MockRpc};
    use crate::tx::TxSigner;
    use alloy_primitives::U256;
    use alloy_sol_types::{SolCall, SolValue};
    use std::collections::HashMap;

    /// Manually ABI-encode a validatorByAddress return value.
    /// 12 fields: address, bytes(dynamic), uint256, uint8, 7x uint64, bool
    fn mock_validator_detail(addr: Address, status: u8, stake: alloy_primitives::U256) -> Vec<u8> {
        // Use SolValue for the two groups (<=12 elements each) and concatenate.
        // Group1: (addr, offset_to_bytes, stake, status, slashCount,
        //          missedBlocks, missedVotes, blocksProposed, joinedAtHeight,
        //          deactivatedAtHeight, unbondingEnd)
        // Group2: (hasBLSShare,)
        // Dynamic bytes at the end.
        //
        // Simpler: encode as the raw ABI tuple that the decoder expects.
        let mut buf = Vec::new();
        // slot 0: address (left-padded to 32)
        buf.extend_from_slice(
            &alloy_primitives::U256::from_be_slice(addr.as_slice()).to_be_bytes::<32>(),
        );
        // slot 1: offset to dynamic bytes (12 * 32 = 384)
        buf.extend_from_slice(&alloy_primitives::U256::from(12 * 32).to_be_bytes::<32>());
        // slot 2: stake
        buf.extend_from_slice(&stake.to_be_bytes::<32>());
        // slot 3: status (uint8)
        buf.extend_from_slice(&alloy_primitives::U256::from(status).to_be_bytes::<32>());
        // slots 4-10: uint64 fields (all zero except blocksProposed=10, joinedAtHeight=1)
        for val in [0u64, 0, 0, 10, 1, 0, 0] {
            buf.extend_from_slice(&alloy_primitives::U256::from(val).to_be_bytes::<32>());
        }
        // slot 11: hasBLSShare (bool)
        buf.extend_from_slice(&alloy_primitives::U256::from(1u64).to_be_bytes::<32>());
        // dynamic: bytes length + data (48 zero bytes, padded to 64)
        buf.extend_from_slice(&alloy_primitives::U256::from(48u64).to_be_bytes::<32>());
        buf.extend_from_slice(&[0u8; 48]);
        buf.extend_from_slice(&[0u8; 16]); // pad to 64
        buf
    }

    /// Build ABI-encoded address list (dynamic array).
    fn mock_address_list(addrs: &[Address]) -> Vec<u8> {
        addrs.to_vec().abi_encode()
    }

    #[tokio::test]
    async fn test_validator_info_returns_correct_data() {
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let stake = alloy_primitives::U256::from(500u64);
        let mut map = HashMap::new();
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::validatorByAddressCall::SELECTOR,
            ),
            mock_validator_detail(addr, 2, stake),
        );
        let mock = MockRpc {
            eth_call_map: Some(call_map(map)),
            ..Default::default()
        };
        // info() decodes and prints - verify it doesn't error
        info(&mock, addr).await.unwrap();
    }

    #[tokio::test]
    async fn test_validator_info_rpc_error() {
        let mock = MockRpc::default();
        let addr: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        assert!(info(&mock, addr).await.is_err());
    }

    #[tokio::test]
    async fn test_validator_list_empty() {
        let mut map = HashMap::new();
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::getValidatorsCall::SELECTOR,
            ),
            mock_address_list(&[]),
        );
        let mock = MockRpc {
            eth_call_map: Some(call_map(map)),
            ..Default::default()
        };
        list(&mock, false, None, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_validator_list_with_validators() {
        let addr1: Address = "0x1111111111111111111111111111111111111111"
            .parse()
            .unwrap();
        let addr2: Address = "0x2222222222222222222222222222222222222222"
            .parse()
            .unwrap();
        let stake = alloy_primitives::U256::from(1000u64);
        let mut map = HashMap::new();
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::getValidatorsCall::SELECTOR,
            ),
            mock_address_list(&[addr1, addr2]),
        );
        // validatorByAddress returns same data for all (keyed by selector only)
        map.insert(
            (
                abi::VALIDATOR_SET_ADDR,
                IValidatorSet::validatorByAddressCall::SELECTOR,
            ),
            mock_validator_detail(addr1, 2, stake),
        );
        let mock = MockRpc {
            eth_call_map: Some(call_map(map)),
            ..Default::default()
        };
        list(&mock, false, None, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_validator_list_rpc_error() {
        let mock = MockRpc::default();
        assert!(list(&mock, false, None, None).await.is_err());
    }

    const TEST_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[tokio::test]
    async fn test_register_sends_expected_tx() {
        let signer = TxSigner::new(TEST_KEY).unwrap();
        let pubkey = vec![0xaa, 0xbb, 0xcc];
        let bls_sig = vec![0x11, 0x22, 0x33];
        let radicle_node_id = B256::repeat_byte(0x44);
        let data = IValidatorSet::registerValidatorCall {
            validatorAddress: signer.address(),
            consensusPubkey: pubkey.clone().into(),
            radicleNodeId: radicle_node_id,
            blsRegistrationSignature: bls_sig.clone().into(),
        }
        .abi_encode();
        let mock =
            recording_send_tx_rpc(TEST_KEY, abi::VALIDATOR_SET_ADDR, data, U256::ZERO).unwrap();

        register(
            &mock,
            Some(TEST_KEY),
            "0xaabbcc".to_string(),
            radicle_node_id,
            "0x112233".to_string(),
        )
        .await
        .unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_register_invalid_pubkey_does_not_call_rpc() {
        let mock =
            recording_send_tx_rpc(TEST_KEY, abi::VALIDATOR_SET_ADDR, vec![], U256::ZERO).unwrap();
        let err = register(
            &mock,
            Some(TEST_KEY),
            "not_hex".to_string(),
            B256::repeat_byte(0x44),
            "0x112233".to_string(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("Invalid") || err.to_string().contains("Odd"),
            "expected hex decode error, got: {err}"
        );
        assert!(
            mock.recorded_calls().is_empty(),
            "invalid pubkey must not call RPC"
        );
    }

    #[tokio::test]
    async fn test_register_no_private_key_errors_before_rpc() {
        let mock =
            recording_send_tx_rpc(TEST_KEY, abi::VALIDATOR_SET_ADDR, vec![], U256::ZERO).unwrap();
        let err = register(
            &mock,
            None,
            "0xaabbcc".to_string(),
            B256::repeat_byte(0x44),
            "0x112233".to_string(),
        )
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
    async fn test_deactivate_sends_expected_tx() {
        let signer = TxSigner::new(TEST_KEY).unwrap();
        let data = IValidatorSet::deactivateValidatorCall {
            validatorAddress: signer.address(),
        }
        .abi_encode();
        let mock =
            recording_send_tx_rpc(TEST_KEY, abi::VALIDATOR_SET_ADDR, data, U256::ZERO).unwrap();

        deactivate(&mock, Some(TEST_KEY)).await.unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_deactivate_no_private_key_errors_before_rpc() {
        let mock =
            recording_send_tx_rpc(TEST_KEY, abi::VALIDATOR_SET_ADDR, vec![], U256::ZERO).unwrap();
        let err = deactivate(&mock, None).await.unwrap_err();
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
    async fn test_confirm_ready_sends_exact_registration_file_bytes() {
        use std::io::Write as _;

        let registration = vec![0x4f, 0x43, 0x4f, 0x4d, 0x50, 0x01, 0xaa, 0xbb];
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&registration).unwrap();
        let data = IValidatorSet::confirmValidatorReadyCall {
            registration: registration.clone().into(),
        }
        .abi_encode();
        let mock =
            recording_send_tx_rpc(TEST_KEY, abi::VALIDATOR_SET_ADDR, data, U256::ZERO).unwrap();

        confirm_ready(&mock, Some(TEST_KEY), file.path().to_path_buf())
            .await
            .unwrap();
        mock.assert_done();
    }

    #[tokio::test]
    async fn test_delegate_ocomp_sends_role_scoped_transaction() {
        let delegate_address = Address::repeat_byte(0x22);
        let data = IValidatorSet::setDelegateCall {
            role: ValidatorDelegateRoleArg::Ocomp.id(),
            delegate: delegate_address,
        }
        .abi_encode();
        let mock =
            recording_send_tx_rpc(TEST_KEY, abi::VALIDATOR_SET_ADDR, data, U256::ZERO).unwrap();

        delegate(
            &mock,
            Some(TEST_KEY),
            ValidatorDelegateRoleArg::Ocomp,
            delegate_address,
        )
        .await
        .unwrap();
        mock.assert_done();
    }

    #[test]
    fn validator_delegate_role_ids_are_protocol_stable() {
        assert_eq!(ValidatorDelegateRoleArg::Oracle.id(), 1);
        assert_eq!(ValidatorDelegateRoleArg::Ocomp.id(), 2);
    }

    #[test]
    fn test_status_label_all_known() {
        assert_eq!(status_label(0), "Registered");
        assert_eq!(status_label(1), "Pending");
        assert_eq!(status_label(2), "Active");
        assert_eq!(status_label(3), "Exiting");
        assert_eq!(status_label(4), "Unbonding");
        assert_eq!(status_label(5), "Inactive");
    }

    #[test]
    fn test_status_label_unknown() {
        assert_eq!(status_label(7), "Unknown");
        assert_eq!(status_label(255), "Unknown");
    }
}
