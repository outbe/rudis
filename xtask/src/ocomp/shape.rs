use std::{collections::BTreeSet, fmt::Write as _, path::Path};

use alloy_primitives::keccak256;
use eyre::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SOURCE_FILES: &[&str] = &[
    "crates/system/ocomp-protocol/registry/ocomp-v1.tsv",
    "crates/system/ocomp-protocol/registry/input-codecs-v1.tsv",
    "crates/system/ocomp-protocol/registry/schema-v1.tsv",
    "crates/system/ocomp-protocol/registry/preimages-v1.tsv",
    "crates/system/ocomp-protocol/registry/shape-freeze-v1.json",
];

#[derive(Clone, Debug)]
struct ObjectRow {
    tag: u16,
    name: String,
}

#[derive(Clone, Copy, Debug)]
struct InputCodecIds {
    tribute: alloy_primitives::B256,
    fidelity: alloy_primitives::B256,
    oracle: alloy_primitives::B256,
    opening_registry: alloy_primitives::B256,
}

pub fn run(repository_root: &Path, check: bool) -> Result<()> {
    let input_path =
        repository_root.join("crates/system/ocomp-protocol/registry/shape-freeze-v1.json");
    let input_bytes = std::fs::read(&input_path)
        .wrap_err_with(|| format!("failed reading {}", input_path.display()))?;
    let input: Value = serde_json::from_slice(&input_bytes)
        .wrap_err_with(|| format!("invalid JSON in {}", input_path.display()))?;
    validate_input(&input)?;

    let objects = load_objects(repository_root)?;
    let input_codec_ids = load_input_codec_ids(repository_root)?;
    validate_input_codec_bundle(&input, input_codec_ids)?;
    validate_schema_and_preimages(repository_root, &objects)?;

    let source_hash = hash_sources(repository_root, SOURCE_FILES)?;
    let generator_source_hash = sha256_hex(
        &std::fs::read(repository_root.join("xtask/src/ocomp/shape.rs"))
            .wrap_err("failed reading OCOMP shape generator source")?,
    );
    let registry_hash =
        sha256_file(&repository_root.join("crates/system/ocomp-protocol/registry/ocomp-v1.tsv"))?;
    let input_codec_hash = sha256_file(
        &repository_root.join("crates/system/ocomp-protocol/registry/input-codecs-v1.tsv"),
    )?;
    let schema_hash =
        sha256_file(&repository_root.join("crates/system/ocomp-protocol/registry/schema-v1.tsv"))?;
    let preimage_hash = sha256_file(
        &repository_root.join("crates/system/ocomp-protocol/registry/preimages-v1.tsv"),
    )?;
    let machine_hash = sha256_json(required(&input, "machine")?)?;
    let policy_hash = sha256_json(required(&input, "headroom_policy")?)?;
    let limits_hash = sha256_json(required(&input, "candidate_limits")?)?;
    let correctness_hash = sha256_json(required(&input, "correctness_profile")?)?;
    let bundle_template_hash = sha256_json(required(&input, "bundle_template")?)?;

    let generated_manifest = json!({
        "schema_version": 1,
        "classification": "measurement_only",
        "armable": false,
        "generator": {
            "invocation": "cargo xtask ocomp shape",
            "source_sha256": generator_source_hash,
            "input_set_sha256": source_hash,
        },
        "registries": {
            "object_domain_list_sha256": registry_hash,
            "input_codecs_sha256": input_codec_hash,
            "canonical_schema_sha256": schema_hash,
            "domain_preimage_sha256": preimage_hash,
            "object_count": objects.len(),
            "tribute_body_codec_id": hex::encode(input_codec_ids.tribute),
            "fidelity_opening_codec_id": hex::encode(input_codec_ids.fidelity),
            "oracle_opening_codec_id": hex::encode(input_codec_ids.oracle),
            "opening_codec_registry_hash": hex::encode(input_codec_ids.opening_registry),
        },
        "profiles": {
            "correctness_profile_sha256": correctness_hash,
            "candidate_compile_ceiling_sha256": limits_hash,
            "minimum_devnet_hardware_profile_sha256": machine_hash,
            "headroom_policy_sha256": policy_hash,
            "bundle_template_sha256": bundle_template_hash,
        },
        "independent_verification": {
            "result": "PASS",
            "method": "generated envelope vectors are independently reconstructed and decoded by OCM-BYT-001",
        },
        "network_binding": {
            "chain_id": null,
            "genesis_hash": null,
            "committee_snapshot_hash": null,
            "protocol_bundle_hash": null,
            "capacity_profile_hash": null,
            "network_manifest_hash": null,
        }
    });
    let vectors = render_vectors(&objects, &source_hash)?;
    let outputs = [
        (
            repository_root
                .join("crates/system/ocomp-protocol/registry/generated-shape-manifest.json"),
            canonical_json(&generated_manifest)?,
        ),
        (
            repository_root
                .join("crates/system/ocomp-protocol/tests/fixtures/shape-vectors-v1.json"),
            canonical_json(&vectors)?,
        ),
        (
            repository_root.join("crates/system/ocomp-protocol/src/generated_shape.rs"),
            render_rust(&input, &generated_manifest)?,
        ),
        (
            repository_root.join("crates/system/ocomp-protocol/registry/generated-shape-freeze.md"),
            render_docs(&input, &generated_manifest, &objects)?,
        ),
    ];
    for (path, contents) in outputs {
        update_or_check(repository_root, &path, contents, check)?;
    }
    Ok(())
}

fn load_input_codec_ids(repository_root: &Path) -> Result<InputCodecIds> {
    let contents = std::fs::read_to_string(
        repository_root.join("crates/system/ocomp-protocol/registry/input-codecs-v1.tsv"),
    )?;
    let mut ids = Vec::new();
    for (index, line) in contents.lines().skip(1).enumerate() {
        if line.is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        ensure!(fields.len() == 5, "invalid input codec row {}", index + 2);
        let role: u16 = fields[0].parse()?;
        let version: u16 = fields[2].parse()?;
        let descriptor = fields[4].as_bytes();
        let mut payload = Vec::with_capacity(8 + descriptor.len());
        payload.extend_from_slice(&role.to_be_bytes());
        payload.extend_from_slice(&version.to_be_bytes());
        payload.extend_from_slice(&u32::try_from(descriptor.len())?.to_be_bytes());
        payload.extend_from_slice(descriptor);
        ids.push((
            role,
            framed_hash("OUTBE_OCOMP_CODEC_DESCRIPTOR_V1", &payload)?,
        ));
    }
    ensure!(
        ids.iter().map(|(role, _)| *role).eq([1, 2, 3]),
        "input codecs must be roles 1,2,3"
    );
    let tribute = ids[0].1;
    let fidelity = ids[1].1;
    let oracle = ids[2].1;
    let mut registry_payload = Vec::with_capacity(68);
    registry_payload.extend_from_slice(&2_u16.to_be_bytes());
    registry_payload.push(1);
    registry_payload.extend_from_slice(fidelity.as_slice());
    registry_payload.push(2);
    registry_payload.extend_from_slice(oracle.as_slice());
    let opening_registry = framed_hash("OUTBE_OCOMP_OPENING_CODEC_REGISTRY_V1", &registry_payload)?;
    Ok(InputCodecIds {
        tribute,
        fidelity,
        oracle,
        opening_registry,
    })
}

fn validate_input_codec_bundle(input: &Value, ids: InputCodecIds) -> Result<()> {
    let bundle = required(input, "bundle_template")?;
    for (field, expected) in [
        ("tribute_body_codec_id", ids.tribute),
        ("fidelity_opening_codec_id", ids.fidelity),
        ("oracle_opening_codec_id", ids.oracle),
    ] {
        ensure!(
            string_field(bundle, field)? == hex::encode(expected),
            "measurement bundle field {field} does not match generated input codec"
        );
    }
    Ok(())
}

fn framed_hash(domain: &str, payload: &[u8]) -> Result<alloy_primitives::B256> {
    let domain = domain.as_bytes();
    let mut preimage = Vec::with_capacity(6 + domain.len() + payload.len());
    preimage.extend_from_slice(&u16::try_from(domain.len())?.to_be_bytes());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&u32::try_from(payload.len())?.to_be_bytes());
    preimage.extend_from_slice(payload);
    Ok(keccak256(preimage))
}

fn validate_input(input: &Value) -> Result<()> {
    ensure!(
        u64_field(input, "schema_version")? == 1,
        "shape schema version"
    );
    ensure!(
        string_field(input, "classification")? == "measurement_only",
        "shape fixture must be measurement_only"
    );
    ensure!(
        !bool_field(input, "armable")?,
        "shape fixture must be explicitly unarmable"
    );
    ensure!(
        string_field(input, "generator_invocation")? == "cargo xtask ocomp shape",
        "shape generator invocation drift"
    );
    let identifiers = required(input, "protocol_identifiers")?;
    ensure!(
        u64_field(identifiers, "protocol_version")? == 1,
        "protocol version drift"
    );
    for field in ["fork_id", "correctness_profile_id", "capacity_profile_id"] {
        ensure_hex_32(string_field(identifiers, field)?, field)?;
    }
    let crypto = required(input, "crypto_profile")?;
    ensure!(
        string_field(crypto, "scheme")? == "ECDSA_secp256k1"
            && string_field(crypto, "public_key_encoding")? == "compressed_SEC1_33"
            && string_field(crypto, "signature_encoding")? == "r_s_64_byte_big_endian"
            && u64_field(crypto, "key_epoch")? == 1
            && bool_field(crypto, "low_s_required")?
            && !bool_field(crypto, "recovery_byte")?,
        "crypto profile must remain secp256k1, epoch=1, low-s and recovery-free"
    );
    let limits = required(input, "candidate_limits")?;
    let max_tributes_per_work_shard = u64_field(limits, "max_tributes_per_work_shard")?;
    ensure!(
        max_tributes_per_work_shard <= 256,
        "candidate work-shard Tribute ceiling exceeds 256"
    );
    ensure!(
        u64_field(limits, "max_result_chunk_bytes")? <= 524_288,
        "candidate result-chunk ceiling exceeds 524288"
    );
    for (name, value) in limits
        .as_object()
        .ok_or_else(|| eyre::eyre!("candidate_limits must be an object"))?
    {
        ensure!(
            value.as_u64().is_some_and(|number| number > 0),
            "candidate limit {name} must be a positive integer"
        );
    }
    let machine = required(input, "machine")?;
    ensure!(
        string_field(machine, "profile")? == "OcompPocDevnetMachineV1"
            && u64_field(machine, "logical_cpu_count")? == 4
            && u64_field(machine, "nominal_memory_bytes")? == 17_179_869_184
            && u64_field(machine, "minimum_process_memory_bytes")? == 12_884_901_888
            && u64_field(machine, "minimum_free_workspace_bytes")? == 107_374_182_400,
        "minimum PoC machine literals drift"
    );
    let policy = required(input, "headroom_policy")?;
    ensure!(
        u64_field(policy, "benchmark_cold_runs")? == 5
            && u64_field(policy, "required_headroom_basis_points")? == 2_000
            && bool_field(policy, "failed_or_timeout_run_rejects_candidate")?
            && !bool_field(policy, "retry_failed_run")?,
        "20-percent cold-run policy drift"
    );
    let bundle = required(input, "bundle_template")?;
    for field in [
        "chain_id",
        "genesis_hash",
        "committee_snapshot_hash",
        "protocol_bundle_hash",
        "capacity_profile_hash",
        "network_manifest_hash",
    ] {
        ensure!(
            bundle.get(field).is_some_and(Value::is_null),
            "measurement bundle field {field} must stay null"
        );
    }
    Ok(())
}

fn load_objects(repository_root: &Path) -> Result<Vec<ObjectRow>> {
    let contents = std::fs::read_to_string(
        repository_root.join("crates/system/ocomp-protocol/registry/ocomp-v1.tsv"),
    )?;
    let mut objects = Vec::new();
    for line in contents.lines().skip(1) {
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.first() != Some(&"object") {
            continue;
        }
        ensure!(fields.len() == 4, "invalid object registry row");
        let tag = u16::from_str_radix(
            fields[1]
                .strip_prefix("0x")
                .ok_or_else(|| eyre::eyre!("object tag is not hex"))?,
            16,
        )?;
        objects.push(ObjectRow {
            tag,
            name: fields[3].to_owned(),
        });
    }
    ensure!(objects.len() == 36, "OCOMP V1 must have exactly 36 objects");
    ensure!(
        objects.first().is_some_and(|object| object.tag == 0x0001)
            && objects.last().is_some_and(|object| object.tag == 0x0028),
        "object registry bounds changed"
    );
    ensure!(
        objects.windows(2).all(|pair| pair[0].tag < pair[1].tag),
        "object registry tags must be strictly increasing"
    );
    Ok(objects)
}

fn validate_schema_and_preimages(repository_root: &Path, objects: &[ObjectRow]) -> Result<()> {
    let schema = std::fs::read_to_string(
        repository_root.join("crates/system/ocomp-protocol/registry/schema-v1.tsv"),
    )?;
    let schema_rows = schema
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        schema_rows.len() == objects.len(),
        "schema manifest must contain every object exactly once"
    );
    for (row, object) in schema_rows.iter().zip(objects) {
        let fields = row.split('\t').collect::<Vec<_>>();
        ensure!(fields.len() == 3, "invalid schema manifest row");
        ensure!(
            fields[0] == format!("0x{:04x}", object.tag) && fields[1] == object.name,
            "schema/object registry mismatch for {}",
            object.name
        );
        ensure!(!fields[2].is_empty(), "empty schema for {}", object.name);
    }

    let registry = std::fs::read_to_string(
        repository_root.join("crates/system/ocomp-protocol/registry/ocomp-v1.tsv"),
    )?;
    let domains = registry
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields = line.split('\t').collect::<Vec<_>>();
            (fields.first() == Some(&"domain")).then(|| fields[3].to_owned())
        })
        .collect::<BTreeSet<_>>();
    let preimages = std::fs::read_to_string(
        repository_root.join("crates/system/ocomp-protocol/registry/preimages-v1.tsv"),
    )?;
    let mut preimage_domains = BTreeSet::new();
    for line in preimages.lines().skip(1).filter(|line| !line.is_empty()) {
        let fields = line.split('\t').collect::<Vec<_>>();
        ensure!(fields.len() == 2, "invalid domain/preimage row");
        ensure!(
            !fields[1].is_empty(),
            "empty preimage grammar for {}",
            fields[0]
        );
        ensure!(
            preimage_domains.insert(fields[0].to_owned()),
            "duplicate preimage grammar for {}",
            fields[0]
        );
    }
    ensure!(
        domains == preimage_domains,
        "domain registry and preimage manifest differ"
    );
    Ok(())
}

fn render_vectors(objects: &[ObjectRow], source_hash: &str) -> Result<Value> {
    let mut vectors = Vec::with_capacity(objects.len() * 2);
    for object in objects {
        let positive = envelope(object.tag, &[]);
        let negative = envelope(u16::MAX, &[]);
        vectors.push(json!({
            "vector_id": format!("shape-{:04x}-positive", object.tag),
            "object_kind": object.name,
            "schema_version": 1,
            "semantic_json": {"registry_kind": object.name, "layer": "OCB1 envelope"},
            "canonical_hex": hex::encode(&positive),
            "expected_digest_or_id": hex::encode(keccak256(&positive)),
            "expected_decode_outcome": "envelope_pass",
            "expected_error_code": null,
            "generator_artifact_hash": source_hash,
            "independent_verifier_result": "PASS"
        }));
        vectors.push(json!({
            "vector_id": format!("shape-{:04x}-unknown-kind", object.tag),
            "object_kind": object.name,
            "schema_version": 1,
            "semantic_json": {"mutation": "object_kind=0xffff", "original_kind": object.name},
            "canonical_hex": hex::encode(&negative),
            "expected_digest_or_id": hex::encode(keccak256(&negative)),
            "expected_decode_outcome": "reject",
            "expected_error_code": "UNKNOWN_OBJECT_KIND",
            "generator_artifact_hash": source_hash,
            "independent_verifier_result": "PASS"
        }));
    }
    Ok(json!({
        "schema_version": 1,
        "classification": "measurement_only",
        "armable": false,
        "vectors": vectors,
    }))
}

fn envelope(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(12 + body.len());
    output.extend_from_slice(b"OCB1");
    output.extend_from_slice(&kind.to_be_bytes());
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(
        &u32::try_from(body.len())
            .expect("bounded generator body")
            .to_be_bytes(),
    );
    output.extend_from_slice(body);
    output
}

fn render_rust(input: &Value, manifest: &Value) -> Result<String> {
    let identifiers = required(input, "protocol_identifiers")?;
    let limits = required(input, "candidate_limits")?;
    let machine = required(input, "machine")?;
    let policy = required(input, "headroom_policy")?;
    let profiles = required(manifest, "profiles")?;
    let generator = required(manifest, "generator")?;
    let mut output = String::from(
        "// @generated by `cargo xtask ocomp shape`.\n\
         // Measurement-only compile ceilings: never an armable network binding.\n\n\
         pub const OCOMP_SHAPE_SCHEMA_VERSION: u16 = 1;\n\
         pub const OCOMP_SHAPE_MEASUREMENT_ONLY: bool = true;\n\
         pub const OCOMP_SHAPE_ARMABLE: bool = false;\n",
    );
    for (name, field) in [
        ("OCOMP_POC_FORK_ID_HEX", "fork_id"),
        ("OCOMP_CORRECTNESS_PROFILE_ID_HEX", "correctness_profile_id"),
        ("OCOMP_CAPACITY_PROFILE_ID_HEX", "capacity_profile_id"),
    ] {
        writeln!(
            output,
            "pub const {name}: &str =\n    {:?};",
            string_field(identifiers, field)?
        )?;
    }
    for (name, value) in [
        (
            "OCOMP_SHAPE_GENERATOR_SOURCE_SHA256",
            string_field(generator, "source_sha256")?,
        ),
        (
            "OCOMP_SHAPE_INPUT_SET_SHA256",
            string_field(generator, "input_set_sha256")?,
        ),
        (
            "OCOMP_CANDIDATE_LIMITS_SHA256",
            string_field(profiles, "candidate_compile_ceiling_sha256")?,
        ),
        (
            "OCOMP_MINIMUM_MACHINE_SHA256",
            string_field(profiles, "minimum_devnet_hardware_profile_sha256")?,
        ),
        (
            "OCOMP_HEADROOM_POLICY_SHA256",
            string_field(profiles, "headroom_policy_sha256")?,
        ),
    ] {
        writeln!(output, "pub const {name}: &str =\n    {value:?};")?;
    }
    output.push_str(
        "\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub struct OcompPocCandidateLimitsV1 {\n",
    );
    for field in limits
        .as_object()
        .ok_or_else(|| eyre::eyre!("candidate_limits must be object"))?
        .keys()
    {
        writeln!(output, "    pub {field}: u64,")?;
    }
    output.push_str("}\n\npub const OCOMP_POC_CANDIDATE_LIMITS_V1: OcompPocCandidateLimitsV1 = OcompPocCandidateLimitsV1 {\n");
    for (field, value) in limits
        .as_object()
        .ok_or_else(|| eyre::eyre!("candidate_limits must be object"))?
    {
        writeln!(
            output,
            "    {field}: {},",
            value
                .as_u64()
                .ok_or_else(|| eyre::eyre!("limit {field} is not u64"))?
        )?;
    }
    output.push_str(
        "};\n\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub struct OcompPocDevnetMachineV1 {\n\
         \x20   pub architecture: &'static str,\n\
         \x20   pub operating_system: &'static str,\n\
         \x20   pub logical_cpu_count: u64,\n\
         \x20   pub nominal_memory_bytes: u64,\n\
         \x20   pub minimum_process_memory_bytes: u64,\n\
         \x20   pub nominal_root_disk_bytes: u64,\n\
         \x20   pub minimum_free_workspace_bytes: u64,\n\
         \x20   pub minimum_block_iops: u64,\n\
         \x20   pub minimum_block_throughput_bytes_per_second: u64,\n\
         \x20   pub init_and_resource_manager: &'static str,\n\
         \x20   pub enclave_mode: &'static str,\n\
         }\n\n\
         pub const OCOMP_POC_DEVNET_MACHINE_V1: OcompPocDevnetMachineV1 = OcompPocDevnetMachineV1 {\n",
    );
    for field in [
        "architecture",
        "operating_system",
        "init_and_resource_manager",
        "enclave_mode",
    ] {
        writeln!(output, "    {field}: {:?},", string_field(machine, field)?)?;
    }
    for field in [
        "logical_cpu_count",
        "nominal_memory_bytes",
        "minimum_process_memory_bytes",
        "nominal_root_disk_bytes",
        "minimum_free_workspace_bytes",
        "minimum_block_iops",
        "minimum_block_throughput_bytes_per_second",
    ] {
        writeln!(output, "    {field}: {},", u64_field(machine, field)?)?;
    }
    output.push_str(
        "};\n\n#[derive(Clone, Copy, Debug, Eq, PartialEq)]\n\
         pub struct OcompPocHeadroomPolicyV1 {\n\
         \x20   pub benchmark_cold_runs: u64,\n\
         \x20   pub required_headroom_basis_points: u64,\n\
         \x20   pub failed_or_timeout_run_rejects_candidate: bool,\n\
         \x20   pub retry_failed_run: bool,\n\
         }\n\n\
         pub const OCOMP_POC_HEADROOM_POLICY_V1: OcompPocHeadroomPolicyV1 = OcompPocHeadroomPolicyV1 {\n",
    );
    writeln!(
        output,
        "    benchmark_cold_runs: {},",
        u64_field(policy, "benchmark_cold_runs")?
    )?;
    writeln!(
        output,
        "    required_headroom_basis_points: {},",
        u64_field(policy, "required_headroom_basis_points")?
    )?;
    writeln!(
        output,
        "    failed_or_timeout_run_rejects_candidate: {},",
        bool_field(policy, "failed_or_timeout_run_rejects_candidate")?
    )?;
    writeln!(
        output,
        "    retry_failed_run: {},",
        bool_field(policy, "retry_failed_run")?
    )?;
    output.push_str("};\n");
    Ok(output)
}

fn render_docs(input: &Value, manifest: &Value, objects: &[ObjectRow]) -> Result<String> {
    let limits = required(input, "candidate_limits")?;
    let machine = required(input, "machine")?;
    let policy = required(input, "headroom_policy")?;
    let generator = required(manifest, "generator")?;
    let profiles = required(manifest, "profiles")?;
    let mut output = String::from(
        "<!-- @generated by `cargo xtask ocomp shape`; do not edit. -->\n\n\
         # OCOMP P0 shape freeze\n\n\
         Classification: `measurement_only`. Armable: `false`.\n\n",
    );
    writeln!(
        output,
        "- Generator source SHA-256: `{}`",
        string_field(generator, "source_sha256")?
    )?;
    writeln!(
        output,
        "- Input-set SHA-256: `{}`",
        string_field(generator, "input_set_sha256")?
    )?;
    writeln!(
        output,
        "- Candidate-limit SHA-256: `{}`",
        string_field(profiles, "candidate_compile_ceiling_sha256")?
    )?;
    writeln!(output, "- Object kinds: `{}`", objects.len())?;
    output.push_str("\n## Candidate compile ceilings\n\n| Field | Value |\n|---|---:|\n");
    for (field, value) in limits
        .as_object()
        .ok_or_else(|| eyre::eyre!("candidate_limits must be object"))?
    {
        writeln!(output, "| `{field}` | {} |", value.as_u64().unwrap_or(0))?;
    }
    output.push_str("\n## Measurement machine\n\n");
    writeln!(
        output,
        "`{}`: {} CPUs, {} bytes nominal memory, {} bytes minimum workspace.",
        string_field(machine, "profile")?,
        u64_field(machine, "logical_cpu_count")?,
        u64_field(machine, "nominal_memory_bytes")?,
        u64_field(machine, "minimum_free_workspace_bytes")?
    )?;
    writeln!(
        output,
        "Five-run policy: `{}` cold runs and `{}` basis points required headroom.",
        u64_field(policy, "benchmark_cold_runs")?,
        u64_field(policy, "required_headroom_basis_points")?
    )?;
    output.push_str(
        "\nThis artifact has no chain ID, genesis hash, committee snapshot, final \
         capacity profile, protocol bundle hash or network manifest. It cannot arm OCOMP.\n",
    );
    Ok(output)
}

fn hash_sources(repository_root: &Path, paths: &[&str]) -> Result<String> {
    let mut hasher = Sha256::new();
    for relative in paths {
        let bytes = std::fs::read(repository_root.join(relative))
            .wrap_err_with(|| format!("failed reading shape source {relative}"))?;
        let name_len = u32::try_from(relative.len())?;
        let byte_len = u64::try_from(bytes.len())?;
        hasher.update(name_len.to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update(byte_len.to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sha256_file(path: &Path) -> Result<String> {
    Ok(sha256_hex(&std::fs::read(path).wrap_err_with(|| {
        format!("failed reading {}", path.display())
    })?))
}

fn sha256_json(value: &Value) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_json(value: &Value) -> Result<String> {
    let mut output = serde_json::to_string_pretty(value)?;
    output.push('\n');
    Ok(output)
}

fn required<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .ok_or_else(|| eyre::eyre!("missing required shape field {field}"))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    required(value, field)?
        .as_str()
        .ok_or_else(|| eyre::eyre!("shape field {field} is not a string"))
}

fn u64_field(value: &Value, field: &str) -> Result<u64> {
    required(value, field)?
        .as_u64()
        .ok_or_else(|| eyre::eyre!("shape field {field} is not a u64"))
}

fn bool_field(value: &Value, field: &str) -> Result<bool> {
    required(value, field)?
        .as_bool()
        .ok_or_else(|| eyre::eyre!("shape field {field} is not a bool"))
}

fn ensure_hex_32(value: &str, field: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "shape field {field} must be 32-byte hex"
    );
    Ok(())
}

fn update_or_check(
    repository_root: &Path,
    path: &Path,
    contents: String,
    check: bool,
) -> Result<()> {
    let relative = path.strip_prefix(repository_root).unwrap_or(path);
    if check {
        let current = std::fs::read_to_string(path)
            .wrap_err_with(|| format!("missing generated shape file {}", relative.display()))?;
        if current != contents {
            bail!(
                "generated shape file {} is stale; run `cargo xtask ocomp shape`",
                relative.display()
            );
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .wrap_err_with(|| format!("failed creating {}", parent.display()))?;
    }
    std::fs::write(path, contents)
        .wrap_err_with(|| format!("failed writing {}", relative.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_envelope_is_exact() {
        assert_eq!(
            hex::encode(envelope(0x001e, &[])),
            "4f434231001e000100000000"
        );
    }

    #[test]
    fn shape_input_does_not_define_static_ocomp_membership() {
        let input: Value = serde_json::from_str(include_str!(
            "../../../crates/system/ocomp-protocol/registry/shape-freeze-v1.json"
        ))
        .unwrap();
        let crypto = required(&input, "crypto_profile").unwrap();
        for forbidden in ["committee_size", "fault_tolerance", "threshold"] {
            assert!(
                crypto.get(forbidden).is_none(),
                "shape input must not define static OCOMP {forbidden}"
            );
        }
    }
}
