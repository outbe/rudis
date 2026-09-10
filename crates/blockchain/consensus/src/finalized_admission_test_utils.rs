//! Real cryptographic fixtures for consumers of the public finality wire.
//!
//! This module is compiled only for tests or the explicit `test-utils` feature.

use alloy_primitives::{Bytes, B256};
use commonware_codec::Encode as _;
use commonware_consensus::simplex::types::{Proposal, Subject};
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::{
    bls12381::{self, primitives::variant::MinSig},
    certificate::Scheme as _,
    Signer as _,
};
use commonware_parallel::Sequential;
use commonware_utils::{
    ordered::{Quorum as _, Set},
    N3f1, TryCollect as _,
};
use outbe_primitives::{
    reshare_artifact::{
        encode_outbe_block_artifacts, ConsensusHeaderArtifact, OutbeBlockArtifacts,
    },
    OutbeHeader,
};
use reth_ethereum::{primitives::SealedBlock, Block};

use crate::{
    block::ConsensusBlock,
    bls::ParticipantDkgBootstrapResult,
    digest::Digest,
    hybrid::{HybridScheme, VrfMaterialProvider},
    marshal_types::Finalization,
};

pub struct FinalityCommitteeFixture {
    keys: Vec<bls12381::PrivateKey>,
    participants: Set<bls12381::PublicKey>,
    dkg: ParticipantDkgBootstrapResult,
}

pub struct CertifiedBlockFixture {
    pub finalization: Vec<u8>,
    pub block: Vec<u8>,
    pub block_hash: B256,
}

impl FinalityCommitteeFixture {
    pub fn new(seed_base: u64) -> Self {
        let mut keys = (1..=4)
            .map(|offset| bls12381::PrivateKey::from_seed(seed_base + offset))
            .collect::<Vec<_>>();
        keys.sort_by_key(|key| key.public_key().encode());
        let participants: Set<bls12381::PublicKey> = keys
            .iter()
            .map(|key| key.public_key())
            .try_collect()
            .expect("fixture keys are unique");
        let dkg = crate::bls::bootstrap_dkg_for_participants(participants.clone())
            .expect("fixture DKG succeeds");
        Self {
            keys,
            participants,
            dkg,
        }
    }

    pub fn public_keys_min_pk(&self) -> Vec<[u8; 48]> {
        self.participants
            .iter()
            .map(|key| key.encode().as_ref().try_into().expect("MinPk is 48 bytes"))
            .collect()
    }

    pub fn outcome(&self, epoch: Epoch) -> Vec<u8> {
        crate::dkg_manager::encode_outcome(epoch, &self.dkg.output, false).to_vec()
    }

    pub fn preannounce_extra_data(&self, epoch: Epoch) -> Vec<u8> {
        encode_outbe_block_artifacts(&OutbeBlockArtifacts {
            consensus_header_artifact: Some(ConsensusHeaderArtifact::CommitteePreAnnounce {
                epoch: epoch.get(),
                outcome: Bytes::from(self.outcome(epoch)),
            }),
            ..Default::default()
        })
        .expect("fixture preannounce encodes")
        .to_vec()
    }

    pub fn certify_block(
        &self,
        epoch: Epoch,
        height: u64,
        timestamp: u64,
        state_root: B256,
        extra_data: Vec<u8>,
    ) -> CertifiedBlockFixture {
        let mut block = Block::default();
        block.header.number = height;
        block.header.timestamp = timestamp;
        block.header.state_root = state_root;
        block.header.extra_data = Bytes::from(extra_data);
        let block =
            ConsensusBlock::from_sealed(SealedBlock::seal_slow(block.map_header(OutbeHeader::new)));

        let namespace = crate::config::outbe_app_namespace();
        let verifier = HybridScheme::<MinSig>::verifier_with_vrf_provider(
            &namespace,
            self.participants.clone(),
            VrfMaterialProvider::new(epoch.get(), self.dkg.polynomial.clone(), None),
        )
        .expect("fixture verifier constructs");
        let signers = self
            .keys
            .iter()
            .map(|key| {
                let index = self
                    .participants
                    .index(&key.public_key())
                    .expect("fixture key belongs to committee");
                HybridScheme::<MinSig>::signer_with_vrf_provider(
                    &namespace,
                    self.participants.clone(),
                    key.clone(),
                    VrfMaterialProvider::new(
                        epoch.get(),
                        self.dkg.polynomial.clone(),
                        Some(self.dkg.shares[index.get() as usize].clone()),
                    ),
                )
                .expect("fixture signer constructs")
            })
            .collect::<Vec<_>>();
        let proposal = Proposal::new(
            Round::new(epoch, View::new(2)),
            View::new(1),
            block.digest(),
        );
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let attestations = signers
            .iter()
            .map(|signer| signer.sign::<Digest>(subject).expect("fixture vote signs"))
            .collect::<Vec<_>>();
        let certificate = verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .expect("fixture finalization assembles");
        let finalization: Finalization = Finalization {
            proposal,
            certificate,
        };
        CertifiedBlockFixture {
            finalization: finalization.encode().to_vec(),
            block: block.encode().to_vec(),
            block_hash: block.block_hash(),
        }
    }
}
