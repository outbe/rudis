mod support;

use alloy_primitives::B256;
use outbe_ocomp::{
    bundle::PinnedProtocolBundle,
    cas::CasLimits,
    control::{poc_schema_limits, EndpointIdentity},
    embedded_runtime::{
        EmbeddedNodePolicyV1, EmbeddedOcompBundleConfigV1, EmbeddedOcompDomainConfigV1,
        EmbeddedOcompDomainV1,
    },
    inbox::WorkerInboxLimits,
    supervisor_job::{SupervisorJobRunnerConfigV1, SupervisorJobRunnerV1},
    worker_transport::SupervisorWorkerServerV1,
};

fn network_test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn fresh_full_node_domain_creates_its_node_local_storage_parent() {
    let _network = network_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let canonical_bundle = bundle.encode_canonical(&limits).unwrap();
    let bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let worker_address = "127.0.0.1:0".parse().unwrap();
    let domain_root = temporary.path().join("domain-v1");

    let domain = EmbeddedOcompDomainV1::open(EmbeddedOcompDomainConfigV1 {
        domain_root: domain_root.clone(),
        registry_generation: 1,
        bundles: vec![EmbeddedOcompBundleConfigV1 {
            worker_address,
            identity: EndpointIdentity {
                chain_id: 70_860_602,
                genesis_hash: B256::repeat_byte(0x21),
                boot_nonce: B256::repeat_byte(0x22),
                protocol_bundle_hash: bundle_hash,
            },
            protocol_bundle: PinnedProtocolBundle::decode(&canonical_bundle, bundle_hash, &limits)
                .unwrap(),
        }],
        policy: EmbeddedNodePolicyV1::FullNode,
        validator_rpc_url: None,
        limits,
    })
    .unwrap();

    assert!(domain_root.join("node-v1/local-results").is_dir());
    assert!(domain_root.join("supervisor-v1").is_dir());
    assert!(domain_root.join("exporter-v1").is_dir());
    drop(domain);
}

#[test]
fn one_embedded_domain_opens_distinct_worker_lanes_for_two_bundles() {
    let _network = network_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let limits = poc_schema_limits();
    let first = support::protocol_bundle();
    let mut second = first.clone();
    second.protocol_version += 1;
    second.fork_id = B256::repeat_byte(0x41);
    second.request_semantics_version += 1;
    second.lysis_program_semantics_hash = B256::repeat_byte(0x42);
    let first_bytes = first.encode_canonical(&limits).unwrap();
    let second_bytes = second.encode_canonical(&limits).unwrap();
    let first_hash = first.protocol_bundle_hash(&limits).unwrap();
    let second_hash = second.protocol_bundle_hash(&limits).unwrap();
    let first_address = "127.0.0.1:0".parse().unwrap();
    let second_address = "127.0.0.1:0".parse().unwrap();
    let identity = |protocol_bundle_hash| EndpointIdentity {
        chain_id: 70_860_602,
        genesis_hash: B256::repeat_byte(0x51),
        boot_nonce: B256::repeat_byte(0x52),
        protocol_bundle_hash,
    };
    let domain = EmbeddedOcompDomainV1::open(EmbeddedOcompDomainConfigV1 {
        domain_root: temporary.path().join("domain-v1"),
        registry_generation: 1,
        bundles: vec![
            EmbeddedOcompBundleConfigV1 {
                worker_address: first_address,
                identity: identity(first_hash),
                protocol_bundle: PinnedProtocolBundle::decode(&first_bytes, first_hash, &limits)
                    .unwrap(),
            },
            EmbeddedOcompBundleConfigV1 {
                worker_address: second_address,
                identity: identity(second_hash),
                protocol_bundle: PinnedProtocolBundle::decode(&second_bytes, second_hash, &limits)
                    .unwrap(),
            },
        ],
        policy: EmbeddedNodePolicyV1::FullNode,
        validator_rpc_url: None,
        limits,
    })
    .unwrap();

    let mut hashes = domain.installed_bundle_hashes();
    hashes.sort();
    let mut expected = vec![first_hash, second_hash];
    expected.sort();
    assert_eq!(hashes, expected);
}

#[test]
fn node_owned_worker_server_outlives_embedded_runner() {
    let temporary = tempfile::tempdir().unwrap();
    let limits = poc_schema_limits();
    let bundle = support::protocol_bundle();
    let canonical_bundle = bundle.encode_canonical(&limits).unwrap();
    let bundle_hash = bundle.protocol_bundle_hash(&limits).unwrap();
    let identity = EndpointIdentity {
        chain_id: 70_860_602,
        genesis_hash: B256::repeat_byte(0x31),
        boot_nonce: B256::repeat_byte(0x32),
        protocol_bundle_hash: bundle_hash,
    };
    let server =
        SupervisorWorkerServerV1::start("127.0.0.1:0".parse().unwrap(), identity, 1, limits)
            .unwrap();

    let runner = SupervisorJobRunnerV1::open(
        SupervisorJobRunnerConfigV1 {
            cas_root: temporary.path().join("cas"),
            cas_limits: CasLimits {
                max_object_bytes: 1 << 20,
                max_total_bytes: 1 << 24,
            },
            input_ref_root: temporary.path().join("input-refs"),
            job_root: temporary.path().join("jobs"),
            worker_inbox_root: temporary.path().join("worker-inbox"),
            worker_inbox_limits: WorkerInboxLimits {
                max_artifact_bytes: 1 << 20,
                max_total_bytes: 1 << 24,
            },
            protocol_bundle: PinnedProtocolBundle::decode(&canonical_bundle, bundle_hash, &limits)
                .unwrap(),
            limits,
        },
        server.dispatcher(),
    )
    .unwrap();

    drop(runner);
    assert_eq!(server.registered_workers().unwrap(), 0);
}
