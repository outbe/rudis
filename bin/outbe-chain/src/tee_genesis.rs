use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use clap::{Parser, Subcommand, ValueEnum};
use eyre::{ensure, WrapErr as _};
use outbe_primitives::tee_genesis_v1::{
    initial_tee_policy_v1, tee_attestation_v1_genesis_field, InitialTeeProfileV1,
    ProductionSgxMeasurementV1,
};
use reth_ethereum::chainspec::EthChainSpec as _;

const TEE_ATTESTATION_FIELD: &str = "teeAttestationV1";

#[derive(Debug, Parser)]
#[command(name = "outbe-chain-tee")]
pub(crate) struct TeeCli {
    #[command(subcommand)]
    command: TeeCommand,
}

#[derive(Debug, Subcommand)]
enum TeeCommand {
    /// Bind a seeded genesis to one canonical block-1 TEE policy.
    Genesis(TeeGenesisArgs),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum TeeGenesisMode {
    DcapRequired,
    GramineDirectDev,
}

#[derive(Debug, clap::Args)]
struct TeeGenesisArgs {
    /// Seeded genesis JSON without teeAttestationV1.
    #[arg(long)]
    input: PathBuf,

    /// New genesis JSON. The command refuses to overwrite an existing path.
    #[arg(long)]
    output: PathBuf,

    /// Genesis-fixed attestation mode; there is no runtime fallback.
    #[arg(long, value_enum)]
    mode: TeeGenesisMode,

    /// Exact release MRENCLAVE (32-byte hex); required only for DcapRequired.
    #[arg(long)]
    mrenclave: Option<String>,

    /// Exact release MRSIGNER (32-byte hex); required only for DcapRequired.
    #[arg(long)]
    mrsigner: Option<String>,

    /// Exact release ISV product ID; required only for DcapRequired.
    #[arg(long)]
    isv_prod_id: Option<u16>,

    /// Minimum accepted release ISV SVN; required only for DcapRequired.
    #[arg(long)]
    minimum_isv_svn: Option<u16>,

    /// Minimum Intel TCB evaluation data number; required only for DcapRequired.
    #[arg(long)]
    minimum_tcb_evaluation_data_number: Option<u32>,
}

pub(crate) fn run(arguments: &[String]) -> eyre::Result<()> {
    let mut tee_arguments = vec![arguments[0].clone()];
    tee_arguments.extend_from_slice(&arguments[2..]);
    let cli = TeeCli::parse_from(tee_arguments);
    match cli.command {
        TeeCommand::Genesis(args) => generate_genesis(&args),
    }
}

fn generate_genesis(args: &TeeGenesisArgs) -> eyre::Result<()> {
    ensure!(
        args.input != args.output,
        "--input and --output must differ"
    );
    ensure!(
        !args.output.exists(),
        "refusing to overwrite existing genesis output {}",
        args.output.display()
    );
    ensure!(
        args.output.parent().is_some_and(Path::exists),
        "genesis output parent does not exist: {}",
        args.output.display()
    );

    let input_path = utf8_path(&args.input, "input genesis")?;
    let base = reth_ethereum::cli::chainspec::chain_value_parser(input_path)
        .wrap_err_with(|| format!("parse input genesis {}", args.input.display()))?;
    let chain_id = base.chain().id();
    let genesis_hash = base.genesis_hash();

    let profile = match args.mode {
        TeeGenesisMode::DcapRequired => {
            InitialTeeProfileV1::DcapRequired(ProductionSgxMeasurementV1 {
                mrenclave: parse_hex32(required(&args.mrenclave, "--mrenclave")?)?,
                mrsigner: parse_hex32(required(&args.mrsigner, "--mrsigner")?)?,
                isv_prod_id: args
                    .isv_prod_id
                    .ok_or_else(|| eyre::eyre!("DcapRequired requires --isv-prod-id"))?,
                minimum_isv_svn: args
                    .minimum_isv_svn
                    .ok_or_else(|| eyre::eyre!("DcapRequired requires --minimum-isv-svn"))?,
                minimum_tcb_evaluation_data_number: args
                    .minimum_tcb_evaluation_data_number
                    .ok_or_else(|| {
                        eyre::eyre!("DcapRequired requires --minimum-tcb-evaluation-data-number")
                    })?,
            })
        }
        TeeGenesisMode::GramineDirectDev => {
            ensure!(
                args.mrenclave.is_none()
                    && args.mrsigner.is_none()
                    && args.isv_prod_id.is_none()
                    && args.minimum_isv_svn.is_none()
                    && args.minimum_tcb_evaluation_data_number.is_none(),
                "GramineDirectDev uses fixed non-hardware projections; DCAP measurement arguments are forbidden"
            );
            InitialTeeProfileV1::GramineDirectDev
        }
    };
    let policy =
        initial_tee_policy_v1(profile, chain_id, genesis_hash).map_err(eyre::Report::msg)?;
    let field = tee_attestation_v1_genesis_field(&policy).map_err(eyre::Report::msg)?;

    let mut genesis: serde_json::Value = serde_json::from_slice(
        &fs::read(&args.input)
            .wrap_err_with(|| format!("read input genesis {}", args.input.display()))?,
    )
    .wrap_err("decode input genesis JSON")?;
    let config = genesis
        .get_mut("config")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| eyre::eyre!("input genesis config must be a JSON object"))?;
    ensure!(
        !config.contains_key(TEE_ATTESTATION_FIELD),
        "input genesis already contains {TEE_ATTESTATION_FIELD}; refusing an implicit policy replacement"
    );
    config.insert(TEE_ATTESTATION_FIELD.to_owned(), field);

    let mut encoded = serde_json::to_vec_pretty(&genesis).wrap_err("encode output genesis JSON")?;
    encoded.push(b'\n');
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)
        .wrap_err_with(|| format!("create output genesis {}", args.output.display()))?;
    if let Err(error) = output
        .write_all(&encoded)
        .and_then(|()| output.sync_all())
        .wrap_err_with(|| format!("write output genesis {}", args.output.display()))
        .and_then(|()| validate_output(&args.output, chain_id, genesis_hash, profile))
    {
        drop(output);
        let _ = fs::remove_file(&args.output);
        return Err(error);
    }

    println!(
        "wrote {:?} genesis: chain_id={}, genesis_hash={}, output={}",
        profile.attestation_mode(),
        chain_id,
        genesis_hash,
        args.output.display()
    );
    Ok(())
}

fn validate_output(
    output: &Path,
    expected_chain_id: u64,
    expected_genesis_hash: B256,
    expected_profile: InitialTeeProfileV1,
) -> eyre::Result<()> {
    let parsed =
        reth_ethereum::cli::chainspec::chain_value_parser(utf8_path(output, "output genesis")?)
            .wrap_err("parse generated mandatory teeAttestationV1 ChainSpec")?
            .as_ref()
            .clone()
            .map_header(outbe_primitives::OutbeHeader::new);
    ensure!(
        parsed.chain().id() == expected_chain_id,
        "generated genesis changed chain ID"
    );
    ensure!(
        parsed.genesis_hash() == expected_genesis_hash,
        "teeAttestationV1 unexpectedly changed the genesis header hash"
    );
    crate::validate_outbe_chain_spec(&parsed)?;
    let activation =
        outbe_evm::tee_attestation_activation::TeeAttestationChainSpecStateV1::from_chain_spec(
            &parsed,
        );
    let mode = activation
        .activation()
        .map_err(|error| eyre::eyre!(error.to_owned()))?
        .policy_at(1)
        .map_err(eyre::Report::msg)?
        .attestation_mode;
    ensure!(
        mode == expected_profile.attestation_mode(),
        "generated genesis attestation mode mismatch"
    );
    Ok(())
}

fn required<'a>(value: &'a Option<String>, name: &str) -> eyre::Result<&'a str> {
    value
        .as_deref()
        .ok_or_else(|| eyre::eyre!("DcapRequired requires {name}"))
}

fn parse_hex32(value: &str) -> eyre::Result<B256> {
    let encoded = value.strip_prefix("0x").unwrap_or(value);
    ensure!(
        encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "expected exactly 32 hexadecimal bytes"
    );
    let decoded = hex::decode(encoded).wrap_err("decode 32-byte hexadecimal value")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| eyre::eyre!("expected exactly 32 hexadecimal bytes"))?;
    Ok(B256::from(bytes))
}

fn utf8_path<'a>(path: &'a Path, label: &str) -> eyre::Result<&'a str> {
    path.to_str()
        .ok_or_else(|| eyre::eyre!("{label} path is not valid UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbe_metadosis::{
        proof_layout::METADOSIS_STORAGE_LAYOUT_V1_HASH, test_support::ForkInstallScenario,
    };
    use outbe_node::ocomp::fork::{
        METADOSIS_STORAGE_LAYOUT_GENESIS_KEY, OCOMP_FORK_INSTALL_GENESIS_KEY,
    };
    use outbe_ocomp_protocol::profile::poc_schema_limits;
    use outbe_primitives::chain::{DEVNET_CHAIN_ID, MAINNET_CHAIN_ID, TESTNET_CHAIN_ID};
    use reth_cli::chainspec::ChainSpecParser as _;

    fn write_base_genesis(path: &Path, chain_id: u64) {
        let mut genesis = serde_json::json!({
            "config": {
                "chainId": chain_id,
                "epochLengthBlocks": 300,
                "homesteadBlock": 0,
                "eip150Block": 0,
                "eip155Block": 0,
                "eip158Block": 0,
                "byzantiumBlock": 0,
                "constantinopleBlock": 0,
                "petersburgBlock": 0,
                "istanbulBlock": 0,
                "berlinBlock": 0,
                "londonBlock": 0,
                "mergeNetsplitBlock": 0,
                "terminalTotalDifficulty": 0,
                "terminalTotalDifficultyPassed": true,
                "shanghaiTime": 0,
                "cancunTime": 0,
                "pragueTime": 0
            },
            "nonce": "0x0",
            "timestamp": "0x1",
            "extraData": "0x",
            "gasLimit": "0x1dcd6500",
            "difficulty": "0x0",
            "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "coinbase": "0x0000000000000000000000000000000000000000",
            "alloc": {}
        });
        fs::write(path, serde_json::to_vec_pretty(&genesis).unwrap()).unwrap();
        let parsed =
            reth_ethereum::cli::chainspec::chain_value_parser(path.to_str().unwrap()).unwrap();
        let install = ForkInstallScenario::measurement_at(1, chain_id, parsed.genesis_hash())
            .unwrap()
            .into_install();
        let limits = poc_schema_limits();
        let canonical_bytes = install.encode_canonical(&limits).unwrap();
        let install_hash = install.install_hash(&limits).unwrap();
        let config = genesis["config"].as_object_mut().unwrap();
        config.insert(
            OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
            serde_json::json!({
                "canonicalBytes": format!("0x{}", hex::encode(canonical_bytes)),
                "installHash": install_hash,
            }),
        );
        config.insert(
            METADOSIS_STORAGE_LAYOUT_GENESIS_KEY.to_owned(),
            serde_json::json!({ "layoutHash": METADOSIS_STORAGE_LAYOUT_V1_HASH }),
        );
        fs::write(path, serde_json::to_vec_pretty(&genesis).unwrap()).unwrap();
    }

    fn args(input: PathBuf, output: PathBuf, mode: TeeGenesisMode) -> TeeGenesisArgs {
        TeeGenesisArgs {
            input,
            output,
            mode,
            mrenclave: None,
            mrsigner: None,
            isv_prod_id: None,
            minimum_isv_svn: None,
            minimum_tcb_evaluation_data_number: None,
        }
    }

    fn parse_generated(
        path: &Path,
    ) -> reth_ethereum::chainspec::ChainSpec<outbe_primitives::OutbeHeader> {
        reth_ethereum::cli::chainspec::chain_value_parser(path.to_str().unwrap())
            .unwrap()
            .as_ref()
            .clone()
            .map_header(outbe_primitives::OutbeHeader::new)
    }

    #[test]
    fn gramine_direct_dev_genesis_is_valid_and_does_not_change_header_hash() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("base.json");
        let output = root.path().join("dev.json");
        write_base_genesis(&input, DEVNET_CHAIN_ID);
        let before = reth_ethereum::cli::chainspec::chain_value_parser(input.to_str().unwrap())
            .unwrap()
            .genesis_hash();

        generate_genesis(&args(
            input,
            output.clone(),
            TeeGenesisMode::GramineDirectDev,
        ))
        .unwrap();

        let after = parse_generated(&output);
        assert_eq!(after.genesis_hash(), before);
        let json: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert!(json["config"][TEE_ATTESTATION_FIELD].is_object());
    }

    #[test]
    fn dcap_genesis_requires_exact_measurements_and_testnet_chain_id() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("base.json");
        write_base_genesis(&input, TESTNET_CHAIN_ID);
        let before = reth_ethereum::cli::chainspec::chain_value_parser(input.to_str().unwrap())
            .unwrap()
            .genesis_hash();
        let output = root.path().join("testnet.json");
        let mut testnet = args(input, output.clone(), TeeGenesisMode::DcapRequired);
        assert!(generate_genesis(&testnet)
            .unwrap_err()
            .to_string()
            .contains("--mrenclave"));

        testnet.mrenclave = Some("11".repeat(32));
        testnet.mrsigner = Some("22".repeat(32));
        testnet.isv_prod_id = Some(1);
        testnet.minimum_isv_svn = Some(2);
        testnet.minimum_tcb_evaluation_data_number = Some(17);
        generate_genesis(&testnet).unwrap();
        let parsed = parse_generated(&output);
        assert_eq!(parsed.genesis_hash(), before);
    }

    #[test]
    fn dcap_genesis_accepts_mainnet_and_preserves_its_identity() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("mainnet-base.json");
        let output = root.path().join("mainnet.json");
        write_base_genesis(&input, MAINNET_CHAIN_ID);
        let before = reth_ethereum::cli::chainspec::chain_value_parser(input.to_str().unwrap())
            .unwrap()
            .genesis_hash();
        let mut mainnet = args(input, output.clone(), TeeGenesisMode::DcapRequired);
        mainnet.mrenclave = Some("11".repeat(32));
        mainnet.mrsigner = Some("22".repeat(32));
        mainnet.isv_prod_id = Some(1);
        mainnet.minimum_isv_svn = Some(2);
        mainnet.minimum_tcb_evaluation_data_number = Some(17);

        generate_genesis(&mainnet).unwrap();
        let parsed = crate::OutbeChainSpecParser::parse(output.to_str().unwrap()).unwrap();
        assert_eq!(parsed.chain().id(), MAINNET_CHAIN_ID);
        assert_eq!(parsed.genesis_hash(), before);
    }

    #[test]
    fn mode_and_chain_identity_mismatches_are_rejected_without_output() {
        let root = tempfile::tempdir().unwrap();

        let dev_input = root.path().join("dev-base.json");
        let dev_output = root.path().join("dev-output.json");
        write_base_genesis(&dev_input, TESTNET_CHAIN_ID + 1);
        assert!(generate_genesis(&args(
            dev_input,
            dev_output.clone(),
            TeeGenesisMode::GramineDirectDev,
        ))
        .unwrap_err()
        .to_string()
        .contains("devnet or testnet chain ID"));
        assert!(!dev_output.exists());

        let dcap_input = root.path().join("dcap-base.json");
        let dcap_output = root.path().join("dcap-output.json");
        write_base_genesis(&dcap_input, TESTNET_CHAIN_ID + 1);
        let mut dcap = args(
            dcap_input,
            dcap_output.clone(),
            TeeGenesisMode::DcapRequired,
        );
        dcap.mrenclave = Some("11".repeat(32));
        dcap.mrsigner = Some("22".repeat(32));
        dcap.isv_prod_id = Some(1);
        dcap.minimum_isv_svn = Some(2);
        dcap.minimum_tcb_evaluation_data_number = Some(17);
        assert!(generate_genesis(&dcap)
            .unwrap_err()
            .to_string()
            .contains("devnet, testnet, or mainnet"));
        assert!(!dcap_output.exists());
    }

    #[test]
    fn zero_dcap_measurement_is_rejected_without_output() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("base.json");
        let output = root.path().join("testnet.json");
        write_base_genesis(&input, TESTNET_CHAIN_ID);
        let mut testnet = args(input, output.clone(), TeeGenesisMode::DcapRequired);
        testnet.mrenclave = Some("00".repeat(32));
        testnet.mrsigner = Some("22".repeat(32));
        testnet.isv_prod_id = Some(1);
        testnet.minimum_isv_svn = Some(2);
        testnet.minimum_tcb_evaluation_data_number = Some(17);

        assert!(generate_genesis(&testnet)
            .unwrap_err()
            .to_string()
            .contains("must be non-zero"));
        assert!(!output.exists());
    }

    #[test]
    fn development_mode_rejects_dcap_measurement_arguments() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("base.json");
        let output = root.path().join("dev.json");
        write_base_genesis(&input, DEVNET_CHAIN_ID);
        let mut development = args(input, output.clone(), TeeGenesisMode::GramineDirectDev);
        development.mrenclave = Some("11".repeat(32));

        assert!(generate_genesis(&development)
            .unwrap_err()
            .to_string()
            .contains("DCAP measurement arguments are forbidden"));
        assert!(!output.exists());
    }

    #[test]
    fn input_and_output_must_be_distinct() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("base.json");
        write_base_genesis(&input, DEVNET_CHAIN_ID);
        let original = fs::read(&input).unwrap();

        assert!(generate_genesis(&args(
            input.clone(),
            input.clone(),
            TeeGenesisMode::GramineDirectDev,
        ))
        .unwrap_err()
        .to_string()
        .contains("must differ"));
        assert_eq!(fs::read(input).unwrap(), original);
    }

    #[test]
    fn existing_output_is_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("base.json");
        let output = root.path().join("dev.json");
        write_base_genesis(&input, DEVNET_CHAIN_ID);
        fs::write(&output, b"operator-owned\n").unwrap();
        assert!(generate_genesis(&args(
            input,
            output.clone(),
            TeeGenesisMode::GramineDirectDev
        ))
        .unwrap_err()
        .to_string()
        .contains("refusing to overwrite"));
        assert_eq!(fs::read(output).unwrap(), b"operator-owned\n");
    }
}
