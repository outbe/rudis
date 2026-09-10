use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use eyre::Result;
use xtask::{ocomp, protocol_bench, stablecoin};

#[derive(Debug, Parser)]
#[command(about = "Outbe repository development automation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate Stablecoin V1 repository and genesis invariants.
    Stablecoin(StablecoinArgs),
    /// Generate and verify Off-chain Computation PoC development artifacts.
    Ocomp(OcompArgs),
    /// Run deterministic protocol gas and latency benchmarks.
    ProtocolBench(ProtocolBenchArgs),
}

#[derive(Debug, Args)]
struct ProtocolBenchArgs {
    #[command(subcommand)]
    command: ProtocolBenchCommand,
}

#[derive(Debug, Subcommand)]
enum ProtocolBenchCommand {
    /// Run selected Rust protocol scenarios.
    Run(ProtocolBenchOptions),
    /// Fail when deterministic gas output differs from the checked baseline.
    BaselineCheck(ProtocolBenchOptions),
    /// Explicitly replace the deterministic gas baseline after a validated run.
    BaselineUpdate(ProtocolBenchOptions),
}

#[derive(Debug, Args)]
struct ProtocolBenchOptions {
    /// Samples per selected scenario (minimum 3).
    #[arg(long, default_value_t = 300)]
    samples: usize,
    /// Scenario id substring, or `all`.
    #[arg(long, default_value = "all")]
    filter: String,
    /// Optional machine-readable report destination.
    #[arg(long)]
    json: Option<PathBuf>,
    /// Optional deterministic gas baseline path.
    #[arg(long)]
    baseline: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct OcompArgs {
    #[command(subcommand)]
    command: OcompCommand,
}

#[derive(Debug, Subcommand)]
enum OcompCommand {
    /// Emit the frozen OCM-26 budget derived from Rust authorities.
    CapacityBudget {
        /// Destination for the deterministic typed budget JSON.
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate or verify the final chain-bound OCM-26 artifact set.
    FinalArtifacts {
        /// Generated capacity manifest produced from the five cold runs.
        #[arg(long)]
        capacity: PathBuf,
        /// Fresh base genesis without an OCOMP fork-install extension.
        #[arg(long)]
        base_genesis: PathBuf,
        /// Ordered public bootstrap manifest for every genesis validator.
        #[arg(long)]
        validators: PathBuf,
        /// Directory containing validator-N/ocomp-registration-v1.ocb1 founder key material.
        #[arg(long)]
        registrations_dir: Option<PathBuf>,
        /// Frozen release artifact directory whose exact protocol semantics are being deployed.
        #[arg(long)]
        release_artifacts_dir: Option<PathBuf>,
        /// Directory containing the complete generated final artifact set.
        #[arg(long)]
        output_dir: PathBuf,
        /// Fail if the existing output differs from deterministic generation.
        #[arg(long)]
        check: bool,
    },
    /// Print the chain-bound validator identity hashes used by OCOMP registration.
    ValidatorIdentities {
        /// Ordered public bootstrap manifest for every genesis validator.
        #[arg(long)]
        validators: PathBuf,
    },
    /// Generate or check the OCOMP V1 object/domain/list registry.
    Registry {
        /// Fail if checked-in generated files differ from the TSV authority.
        #[arg(long)]
        check: bool,
    },
    /// Generate or verify the measurement-only P0 protocol shape freeze.
    Shape {
        /// Fail if checked-in generated shape artifacts differ from their authorities.
        #[arg(long)]
        check: bool,
    },
}

#[derive(Debug, Args)]
struct StablecoinArgs {
    #[command(subcommand)]
    command: StablecoinCommand,
}

#[derive(Debug, Subcommand)]
enum StablecoinCommand {
    /// Compare every checked-in ABI export with its compiled Solidity interface.
    AbiCheck,
    /// Check fixed addresses, planned classes, predeploys and genesis files.
    NamespaceCheck {
        /// Genesis files to validate. May be repeated.
        #[arg(long)]
        genesis: Vec<PathBuf>,
        /// Allow missing fixed marker accounts when checking a pre-seed genesis.
        #[arg(long)]
        preseed: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = xtask::repository_root()?;
    match cli.command {
        Command::ProtocolBench(arguments) => {
            let (action, options) = match arguments.command {
                ProtocolBenchCommand::Run(options) => (protocol_bench::Action::Run, options),
                ProtocolBenchCommand::BaselineCheck(options) => {
                    (protocol_bench::Action::BaselineCheck, options)
                }
                ProtocolBenchCommand::BaselineUpdate(options) => {
                    (protocol_bench::Action::BaselineUpdate, options)
                }
            };
            protocol_bench::run(
                &repo_root,
                action,
                &protocol_bench::Options {
                    samples: options.samples,
                    filter: &options.filter,
                    json: options.json.as_deref(),
                    baseline: options.baseline.as_deref(),
                },
            )?;
        }
        Command::Ocomp(ocomp_args) => match ocomp_args.command {
            OcompCommand::CapacityBudget { output } => {
                ocomp::capacity::publish_budget(&repo_root, &output)?;
            }
            OcompCommand::FinalArtifacts {
                capacity,
                base_genesis,
                validators,
                registrations_dir,
                release_artifacts_dir,
                output_dir,
                check,
            } => {
                ocomp::finalize::run(
                    &repo_root,
                    &capacity,
                    &base_genesis,
                    &validators,
                    ocomp::finalize::FinalArtifactOverrides {
                        registrations_dir: registrations_dir.as_deref(),
                        release_artifacts_dir: release_artifacts_dir.as_deref(),
                    },
                    &output_dir,
                    check,
                )?;
            }
            OcompCommand::ValidatorIdentities { validators } => {
                for (index, identity) in ocomp::finalize::validator_identities(&validators)?
                    .into_iter()
                    .enumerate()
                {
                    println!("{index}={identity:#x}");
                }
            }
            OcompCommand::Registry { check } => {
                ocomp::registry::run(&repo_root, check)?;
            }
            OcompCommand::Shape { check } => {
                ocomp::shape::run(&repo_root, check)?;
            }
        },
        Command::Stablecoin(stablecoin_args) => match stablecoin_args.command {
            StablecoinCommand::AbiCheck => {
                let report = stablecoin::check_abi_exports(&repo_root)?;
                println!(
                    "stablecoin ABI exports ok: {} complete interfaces",
                    report.interfaces
                );
            }
            StablecoinCommand::NamespaceCheck { genesis, preseed } => {
                let report = stablecoin::check_namespace(&repo_root, &genesis, preseed)?;
                println!(
                    "stablecoin namespace ok: {} declared addresses, {} Ethereum built-ins, {} genesis files, {} seed predeploys, {} planned classes",
                    report.declared_addresses,
                    report.ethereum_builtins,
                    report.genesis_files,
                    report.predeploy_addresses,
                    report.planned_classes,
                );
            }
        },
    }
    Ok(())
}
