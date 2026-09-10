//! Finalized OCOMP discovery record shared by the node and snapshot exporter.

use outbe_ocomp_protocol::FinalizedJobSpecV1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryRecord {
    pub generation: u64,
    pub cursor: u64,
    pub spec: FinalizedJobSpecV1,
}
