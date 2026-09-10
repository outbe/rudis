use outbe_primitives::chain::OutbeNetwork;
use outbe_tee::release_dcap_artifacts::ReleaseDcapArtifactSetV1;

#[test]
fn production_networks_have_exact_disjoint_dcap_artifact_sets() {
    let testnet = ReleaseDcapArtifactSetV1::for_network(OutbeNetwork::Testnet)
        .expect("Testnet release artifact set");
    let mainnet = ReleaseDcapArtifactSetV1::for_network(OutbeNetwork::Mainnet)
        .expect("Mainnet release artifact set");

    assert!(ReleaseDcapArtifactSetV1::for_network(OutbeNetwork::Devnet).is_none());
    assert_eq!(testnet.network(), OutbeNetwork::Testnet);
    assert_eq!(mainnet.network(), OutbeNetwork::Mainnet);
    assert_eq!(testnet.genesis_artifact_path(), "testnet-genesis.json");
    assert_eq!(mainnet.genesis_artifact_path(), "mainnet-genesis.json");
    assert_eq!(testnet.paths().len(), 18);
    assert_eq!(mainnet.paths().len(), 18);

    let common = testnet
        .paths()
        .intersection(&mainnet.paths())
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(common.len(), 17);
    assert!(!testnet.paths().contains(mainnet.genesis_artifact_path()));
    assert!(!mainnet.paths().contains(testnet.genesis_artifact_path()));
}
