use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use eyre::Result;
use xtask::{ocomp, protocol_bench, release::sgx, stablecoin};

#[derive(Debug, Parser)]
#[command(about = "Outbe repository development and release automation")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build, verify and publish release artifacts.
    Release(Box<ReleaseArgs>),
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

#[derive(Debug, Args)]
struct ReleaseArgs {
    #[command(subcommand)]
    command: ReleaseCommand,
}

#[derive(Debug, Subcommand)]
enum ReleaseCommand {
    /// Prepare, authorize and verify a pre-signed Gramine SGX bundle.
    Sgx(SgxArgs),
}

#[derive(Debug, Args)]
struct SgxArgs {
    #[command(subcommand)]
    command: SgxCommand,
}

// This command is parsed once and immediately executed. Keeping the manifest paths as
// strongly typed clap fields is clearer than heap-boxing one arbitrary argument solely to
// equalize enum layout.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum SgxCommand {
    /// Prepare an unsigned deterministic Gramine bundle from a verified ELF build.
    Prepare {
        #[arg(long, value_enum)]
        network: sgx::SgxReleaseNetwork,
        /// Approved seeded ChainSpec. Its chain identity and epoch-0 committee are measured into the enclave.
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        elf_output: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Compare two independently prepared unsigned bundles.
    Compare {
        #[arg(long)]
        first: PathBuf,
        #[arg(long)]
        second: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Authorize an unsigned bundle with the protected network SGX key.
    Sign {
        #[arg(long, value_enum)]
        network: sgx::SgxReleaseNetwork,
        #[arg(long)]
        unsigned: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Materialize the only allowed final-genesis change from a signed bundle.
    FinalizeGenesis {
        #[arg(long, value_enum)]
        network: sgx::SgxReleaseNetwork,
        /// Approved genesis without teeAttestationV1.
        #[arg(long)]
        seeded_genesis: PathBuf,
        /// Signed SGX bundle whose measurements become the block-1 policy.
        #[arg(long)]
        bundle: PathBuf,
        /// New final genesis; an existing path is never overwritten.
        #[arg(long)]
        output: PathBuf,
        /// Canonical evidence for the seeded-to-final transformation.
        #[arg(long)]
        evidence_output: PathBuf,
    },
    /// Verify checksums, SIGSTRUCT and the exact final genesis policy binding.
    Verify {
        #[arg(long, value_enum)]
        network: sgx::SgxReleaseNetwork,
        #[arg(long)]
        bundle: PathBuf,
        /// Final genesis whose block-1 policy must authorize this exact bundle.
        #[arg(long)]
        genesis: PathBuf,
    },
    /// Create a deterministic archive from an already verified signed bundle.
    Archive {
        #[arg(long, value_enum)]
        network: sgx::SgxReleaseNetwork,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build an immutable OCI image from an already verified signed bundle.
    Image {
        #[arg(long, value_enum)]
        network: sgx::SgxReleaseNetwork,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        image: String,
        #[arg(long)]
        output: PathBuf,
        /// Push by digest and emit BuildKit SBOM/provenance attestations.
        #[arg(long)]
        push: bool,
    },
    /// Promote one exact ELF, signed SGX bundle and OCI image to a verified ReleaseManifest.
    Manifest {
        #[arg(long, value_enum)]
        network: sgx::SgxReleaseNetwork,
        #[arg(long)]
        elf_manifest: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        bundle_archive: PathBuf,
        #[arg(long)]
        oci_evidence: PathBuf,
        #[arg(long)]
        cosign_image_verification: PathBuf,
        #[arg(long)]
        cosign_sbom_verification: PathBuf,
        #[arg(long)]
        cosign_provenance_verification: PathBuf,
        #[arg(long)]
        sbom: PathBuf,
        #[arg(long)]
        elf_evidence: PathBuf,
        #[arg(long)]
        sgx_evidence: PathBuf,
        #[arg(long)]
        hardware_evidence: PathBuf,
        #[arg(long)]
        processor_dcap_archive: PathBuf,
        #[arg(long)]
        processor_dcap_evidence: PathBuf,
        /// Approved genesis before the release policy is inserted.
        #[arg(long)]
        seeded_genesis: PathBuf,
        /// Canonical evidence for the seeded-to-final genesis transformation.
        #[arg(long)]
        network_binding_evidence: PathBuf,
        /// Final network genesis whose block-1 policy authorizes this enclave.
        #[arg(long)]
        genesis: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let repo_root = sgx::repository_root()?;
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
        Command::Release(release) => match release.command {
            ReleaseCommand::Sgx(sgx_args) => match sgx_args.command {
                SgxCommand::Prepare {
                    network,
                    genesis,
                    elf_output,
                    output,
                } => {
                    sgx::prepare(&repo_root, network, &genesis, &elf_output, &output)?;
                    println!(
                        "unsigned deterministic {network:?} SGX bundle: {}",
                        output.display()
                    );
                }
                SgxCommand::Compare {
                    first,
                    second,
                    output,
                } => {
                    sgx::compare(&first, &second, &output)?;
                    println!(
                        "unsigned SGX reproducibility evidence: {}",
                        output.display()
                    );
                }
                SgxCommand::Sign {
                    network,
                    unsigned,
                    key_file,
                    output,
                } => {
                    sgx::sign(&repo_root, network, &unsigned, &key_file, &output)?;
                    println!("signed {network:?} SGX bundle: {}", output.display());
                }
                SgxCommand::FinalizeGenesis {
                    network,
                    seeded_genesis,
                    bundle,
                    output,
                    evidence_output,
                } => {
                    sgx::finalize_genesis(
                        &repo_root,
                        network,
                        &seeded_genesis,
                        &bundle,
                        &output,
                        &evidence_output,
                    )?;
                    println!(
                        "final {network:?} genesis: {} (evidence: {})",
                        output.display(),
                        evidence_output.display()
                    );
                }
                SgxCommand::Verify {
                    network,
                    bundle,
                    genesis,
                } => {
                    sgx::verify_with_genesis(&repo_root, network, &bundle, &genesis)?;
                    println!(
                        "verified signed {network:?} SGX bundle: {}",
                        bundle.display()
                    );
                }
                SgxCommand::Archive {
                    network,
                    bundle,
                    output,
                } => {
                    sgx::archive(&repo_root, network, &bundle, &output)?;
                    println!(
                        "deterministic signed {network:?} SGX archive: {}",
                        output.display()
                    );
                }
                SgxCommand::Image {
                    network,
                    bundle,
                    image,
                    output,
                    push,
                } => {
                    sgx::build_image(&repo_root, network, &bundle, &image, &output, push)?;
                    println!("{network:?} SGX OCI evidence: {}", output.display());
                }
                SgxCommand::Manifest {
                    network,
                    elf_manifest,
                    bundle,
                    bundle_archive,
                    oci_evidence,
                    cosign_image_verification,
                    cosign_sbom_verification,
                    cosign_provenance_verification,
                    sbom,
                    elf_evidence,
                    sgx_evidence,
                    hardware_evidence,
                    processor_dcap_archive,
                    processor_dcap_evidence,
                    seeded_genesis,
                    network_binding_evidence,
                    genesis,
                    output,
                } => {
                    sgx::finalize_release_manifest(
                        &repo_root,
                        &sgx::VerifiedReleaseInputs {
                            network,
                            bundle,
                            bundle_archive,
                            cosign_image_verification,
                            cosign_provenance_verification,
                            cosign_sbom_verification,
                            elf_evidence,
                            elf_manifest,
                            hardware_evidence,
                            processor_dcap_archive,
                            processor_dcap_evidence,
                            oci_evidence,
                            sbom,
                            sgx_evidence,
                            seeded_genesis,
                            network_binding_evidence,
                            genesis,
                        },
                        &output,
                    )?;
                    println!("verified {network:?} ReleaseManifest: {}", output.display());
                }
            },
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
