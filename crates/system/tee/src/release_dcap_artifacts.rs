//! Canonical non-secret artifact contract for a production DCAP release.

use std::collections::BTreeSet;

use outbe_primitives::chain::OutbeNetwork;

const COMMON_RELEASE_DCAP_ARTIFACT_PATHS: [&str; 17] = [
    "collateral/capture-provenance.json",
    "collateral/pck-certificate-chain.pem0",
    "collateral/pck-crl-issuer-chain.pem",
    "collateral/pck.crl.der",
    "collateral/qe-identity-issuer-chain.pem",
    "collateral/qe-identity.json",
    "collateral/root-ca.crl.der",
    "collateral/tcb-info-issuer-chain.pem",
    "collateral/tcb-info.json",
    "enclave-signature.bin",
    "evidence-v1.bin",
    "intent-v1.bin",
    "node-signature.bin",
    "policy-schedule-v1.bin",
    "policy-v1.bin",
    "quote-v3.bin",
    "verifier-outcome-v1.bin",
];

/// Exact non-secret archive contract for one production release network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseDcapArtifactSetV1 {
    Testnet,
    Mainnet,
}

impl ReleaseDcapArtifactSetV1 {
    #[must_use]
    pub const fn for_network(network: OutbeNetwork) -> Option<Self> {
        match network {
            OutbeNetwork::Testnet => Some(Self::Testnet),
            OutbeNetwork::Mainnet => Some(Self::Mainnet),
            OutbeNetwork::Devnet => None,
        }
    }

    #[must_use]
    pub const fn genesis_artifact_path(self) -> &'static str {
        match self {
            Self::Testnet => "testnet-genesis.json",
            Self::Mainnet => "mainnet-genesis.json",
        }
    }

    #[must_use]
    pub const fn network(self) -> OutbeNetwork {
        match self {
            Self::Testnet => OutbeNetwork::Testnet,
            Self::Mainnet => OutbeNetwork::Mainnet,
        }
    }

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    #[must_use]
    pub const fn bundle_manifest_path(self) -> &'static str {
        match self {
            Self::Testnet => "metadata/testnet-sgx-bundle.json",
            Self::Mainnet => "metadata/mainnet-sgx-bundle.json",
        }
    }

    #[must_use]
    pub fn paths(self) -> BTreeSet<&'static str> {
        COMMON_RELEASE_DCAP_ARTIFACT_PATHS
            .into_iter()
            .chain([self.genesis_artifact_path()])
            .collect()
    }
}
