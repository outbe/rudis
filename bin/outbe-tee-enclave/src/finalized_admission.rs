//! One-shot finality and Ethereum-state verification for onboarding.

use alloy_consensus::{BlockHeader as _, Sealable as _};
use alloy_primitives::{B256, U256};
use alloy_rlp::Decodable as _;
use commonware_codec::ReadExt as _;
use commonware_consensus::types::Epoch;
use commonware_cryptography::bls12381;
use commonware_utils::ordered::Set;
use outbe_consensus::{
    digest::Digest,
    follow::{decode_public_finalization, CommitteeChain},
};
use outbe_primitives::{
    addresses::TEE_REGISTRY_ADDRESS,
    reshare_artifact::{decode_outbe_block_artifacts, ConsensusHeaderArtifact},
    tee_attestation_v1::TrustedNetworkDescriptorV1,
    OutbeHeader,
};
use outbe_tee::{
    dcap_protocol::DcapOnboardingContextV1,
    finalized_admission::{
        onboarding_registry_slots_v1, CertifiedHeaderV1, FinalizedAdmissionWitnessV1,
        MptAccountProofV1, MptStorageProofV1,
    },
};
use reth_primitives_traits::Account;
use reth_trie::{AccountProof, StorageProof};

const MAX_COMMITTEE_MEMBERS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedAdmissionAnchorV1 {
    pub block_number: u64,
    pub block_hash: B256,
    pub state_root: B256,
    pub consensus_timestamp: u64,
}

pub struct FinalizedAdmissionVerifierV1 {
    chain: CommitteeChain,
    previous_height: u64,
    context: DcapOnboardingContextV1,
}

impl FinalizedAdmissionVerifierV1 {
    pub fn new(
        descriptor: &TrustedNetworkDescriptorV1,
        context: &DcapOnboardingContextV1,
        anchor_outcome: &[u8],
    ) -> Result<Self, String> {
        if context.chain_id != descriptor.network_binding.chain_id
            || context.genesis_hash != descriptor.network_binding.genesis_hash
        {
            return Err("finalized admission network identity is not release-measured".into());
        }

        let participants = descriptor
            .genesis_consensus_keys
            .iter()
            .map(|encoded| {
                let mut input = encoded.as_slice();
                let key = bls12381::PublicKey::read(&mut input)
                    .map_err(|error| format!("invalid measured genesis consensus key: {error}"))?;
                if !input.is_empty() {
                    return Err("measured genesis consensus key has trailing bytes".into());
                }
                Ok(key)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let participants = Set::try_from(participants)
            .map_err(|error| format!("invalid measured genesis committee: {error:?}"))?;
        let measured_chain_id =
            u64::try_from(U256::from_be_bytes(descriptor.network_binding.chain_id))
                .map_err(|_| "measured consensus chain id does not fit u64".to_owned())?;
        outbe_consensus::config::init_consensus_chain_id(measured_chain_id)
            .map_err(|error| format!("consensus verifier chain binding rejected: {error}"))?;
        let mut chain = CommitteeChain::new(Epoch::new(0), participants);
        chain
            .register_epoch_from_outcome(Epoch::new(0), anchor_outcome)
            .map_err(|error| format!("epoch-0 finality anchor rejected: {error}"))?;
        chain.retain_only_highest();
        Ok(Self {
            chain,
            previous_height: 0,
            context: *context,
        })
    }

    pub fn advance_committee(&mut self, encoded: &[u8]) -> Result<(), String> {
        let transition = CertifiedHeaderV1::decode_canonical(encoded)
            .map_err(|error| format!("committee transition codec: {error}"))?;
        let (finalization, header, header_hash) = decode_certified_header(&transition)
            .map_err(|error| format!("committee transition decode failed: {error}"))?;
        if header.number() <= self.previous_height
            || finalization.proposal.payload != Digest(header_hash)
        {
            return Err("committee transition envelope or order is invalid".into());
        }
        let epoch = finalization.proposal.round.epoch();
        let expected = self
            .chain
            .highest_registered()
            .ok_or_else(|| "epoch-0 committee was not registered".to_owned())?;
        if epoch != expected {
            return Err("committee transition was not finalized by the current committee".into());
        }
        self.chain
            .verify_finalization(epoch, &finalization)
            .map_err(|error| format!("committee transition finalization rejected: {error}"))?;
        let artifacts = decode_outbe_block_artifacts(header.extra_data().as_ref())
            .map_err(|error| format!("committee transition artifacts rejected: {error:?}"))?;
        let Some(ConsensusHeaderArtifact::CommitteePreAnnounce {
            epoch: next,
            outcome,
        }) = artifacts.consensus_header_artifact
        else {
            return Err("committee transition lacks a pre-announce".into());
        };
        if next != epoch.get().saturating_add(1) {
            return Err("committee transition does not announce the immediate successor".into());
        }
        self.chain
            .register_epoch_from_outcome(Epoch::new(next), &outcome)
            .map_err(|error| format!("successor committee rejected: {error}"))?;
        self.chain.retain_only_highest();
        self.previous_height = header.number();
        Ok(())
    }

    pub fn verify_admission(&self, encoded: &[u8]) -> Result<VerifiedAdmissionAnchorV1, String> {
        let proof = FinalizedAdmissionWitnessV1::decode_canonical(encoded)
            .map_err(|error| format!("finalized admission witness codec: {error}"))?;
        let (finalization, header, header_hash) = decode_certified_header(&proof.admission)
            .map_err(|error| format!("admission finalization decode failed: {error}"))?;
        if header.number() <= self.previous_height
            || finalization.proposal.payload != Digest(header_hash)
        {
            return Err("admission finalization envelope or order is invalid".into());
        }
        let epoch = finalization.proposal.round.epoch();
        if self.chain.highest_registered() != Some(epoch) {
            return Err("admission certificate skips an unauthenticated committee".into());
        }
        self.chain
            .verify_finalization(epoch, &finalization)
            .map_err(|error| format!("admission finalization rejected: {error}"))?;

        let state_root = header.state_root();
        verify_registry_account(state_root, &proof.registry_account)?;
        let expected =
            expected_registry_claims(&self.context, header.timestamp(), &proof.registry_storage)?;
        if proof.registry_storage.len() != expected.len() {
            return Err("finalized admission Registry proof has an unexpected slot count".into());
        }
        for (slot, value) in expected {
            let opening = proof
                .registry_storage
                .iter()
                .find(|opening| opening.key == slot)
                .ok_or_else(|| {
                    "finalized admission Registry proof is missing a required slot".to_owned()
                })?;
            if opening.value != value {
                return Err(
                    "finalized admission Registry value differs from onboarding context".into(),
                );
            }
            verify_storage(proof.registry_account.storage_root, opening)?;
        }
        Ok(VerifiedAdmissionAnchorV1 {
            block_number: header.number(),
            block_hash: header_hash,
            state_root,
            consensus_timestamp: header.timestamp(),
        })
    }
}

fn decode_certified_header(
    proof: &CertifiedHeaderV1,
) -> Result<
    (
        outbe_consensus::marshal_types::Finalization,
        OutbeHeader,
        B256,
    ),
    String,
> {
    let finalization = decode_public_finalization(&proof.finalization, MAX_COMMITTEE_MEMBERS)
        .map_err(|error| error.to_string())?;
    let mut header_bytes = proof.header.as_slice();
    let header = OutbeHeader::decode(&mut header_bytes)
        .map_err(|error| format!("invalid canonical Outbe header RLP: {error}"))?;
    if !header_bytes.is_empty() {
        return Err("trailing bytes after canonical Outbe header".into());
    }
    let hash = header.hash_slow();
    Ok((finalization, header, hash))
}

fn verify_registry_account(state_root: B256, witness: &MptAccountProofV1) -> Result<(), String> {
    AccountProof {
        address: TEE_REGISTRY_ADDRESS,
        info: Some(Account {
            nonce: witness.nonce,
            balance: witness.balance,
            bytecode_hash: Some(witness.code_hash),
        }),
        proof: witness.nodes.iter().cloned().map(Into::into).collect(),
        storage_root: witness.storage_root,
        storage_proofs: Vec::new(),
    }
    .verify(state_root)
    .map_err(|error| format!("finalized admission Registry account proof rejected: {error}"))
}

fn verify_storage(root: B256, witness: &MptStorageProofV1) -> Result<(), String> {
    StorageProof {
        key: witness.key,
        value: witness.value,
        ..StorageProof::new(witness.key)
    }
    .with_proof(witness.nodes.iter().cloned().map(Into::into).collect())
    .verify(root)
    .map_err(|error| format!("finalized admission Registry storage proof rejected: {error}"))
}

fn expected_registry_claims(
    context: &DcapOnboardingContextV1,
    block_timestamp: u64,
    openings: &[MptStorageProofV1],
) -> Result<Vec<(B256, U256)>, String> {
    let slots = onboarding_registry_slots_v1(context);
    let valid_until_slot = slots[7];
    let valid_until = openings
        .iter()
        .find(|opening| opening.key == valid_until_slot)
        .map(|opening| opening.value)
        .ok_or_else(|| "finalized admission Registry proof lacks lease expiry".to_owned())?;
    if valid_until <= U256::from(block_timestamp) {
        return Err("finalized admission Registry lease is not live at the proved block".into());
    }
    Ok(vec![
        (slots[0], U256::from_be_bytes(context.tribute_offer_public)),
        (slots[1], U256::from(context.key_epoch)),
        (slots[2], U256::from(context.tribute_offer_epoch)),
        (slots[3], U256::from_be_bytes(context.enclave_id.0)),
        (slots[4], U256::from_be_bytes(context.binding_id.0)),
        (slots[5], U256::from_be_bytes(context.intent_hash.0)),
        (slots[6], U256::from_be_bytes(context.policy_hash.0)),
        (valid_until_slot, valid_until),
        (slots[8], U256::from_be_bytes(context.recipient_x25519)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compact_certified_header(finalization: &[u8], block: &[u8]) -> CertifiedHeaderV1 {
        let certified = outbe_consensus::follow::decode_public_finalized_block(
            finalization,
            block,
            MAX_COMMITTEE_MEMBERS,
        )
        .unwrap();
        CertifiedHeaderV1 {
            finalization: finalization.to_vec(),
            header: alloy_rlp::encode(certified.block.header()).to_vec(),
        }
    }

    fn context() -> DcapOnboardingContextV1 {
        DcapOnboardingContextV1 {
            chain_id: U256::from(676_u64).to_be_bytes(),
            genesis_hash: B256::repeat_byte(0x11),
            intent_hash: B256::repeat_byte(0x12),
            node_id_hash: B256::repeat_byte(0x13),
            enclave_id: B256::repeat_byte(0x14),
            binding_id: B256::repeat_byte(0x1a),
            policy_hash: B256::repeat_byte(0x1b),
            recipient_x25519: [0x15; 32],
            tribute_offer_public: [0x16; 32],
            key_epoch: 17,
            tribute_offer_epoch: 18,
        }
    }

    fn opening(key: B256, value: U256) -> MptStorageProofV1 {
        MptStorageProofV1 {
            key,
            value,
            nodes: Vec::new(),
        }
    }

    #[test]
    fn exact_registry_claims_are_bound_to_context_and_physical_slots() {
        let context = context();
        let slots = onboarding_registry_slots_v1(&context);
        let claims =
            expected_registry_claims(&context, 1_000, &[opening(slots[7], U256::from(1_001_u64))])
                .unwrap();

        assert_eq!(claims.len(), 9);
        assert_eq!(claims[0], (slots[0], U256::from_be_bytes([0x16; 32])));
        assert_eq!(claims[1], (slots[1], U256::from(17_u64)));
        assert_eq!(claims[2], (slots[2], U256::from(18_u64)));
        assert_eq!(claims[3], (slots[3], U256::from_be_bytes([0x14; 32])));
        assert_eq!(claims[4], (slots[4], U256::from_be_bytes([0x1a; 32])));
        assert_eq!(claims[5], (slots[5], U256::from_be_bytes([0x12; 32])));
        assert_eq!(claims[6], (slots[6], U256::from_be_bytes([0x1b; 32])));
        assert_eq!(claims[7], (slots[7], U256::from(1_001_u64)));
        assert_eq!(claims[8], (slots[8], U256::from_be_bytes([0x15; 32])));
    }

    #[test]
    fn registry_claims_reject_missing_or_expired_lease() {
        let context = context();
        let valid_until = onboarding_registry_slots_v1(&context)[7];
        assert!(expected_registry_claims(&context, 1_000, &[])
            .unwrap_err()
            .contains("lacks lease expiry"));
        assert!(expected_registry_claims(
            &context,
            1_000,
            &[opening(valid_until, U256::from(1_000_u64))],
        )
        .unwrap_err()
        .contains("lease is not live"));
    }

    #[test]
    fn compact_header_decoder_binds_exact_canonical_header_and_finalization() {
        use outbe_consensus::finalized_admission_test_utils::FinalityCommitteeFixture;

        let committee = FinalityCommitteeFixture::new(80);
        let certified =
            committee.certify_block(Epoch::new(0), 7, 1_000, B256::repeat_byte(0x81), Vec::new());
        let compact = compact_certified_header(&certified.finalization, &certified.block);
        let (_, header, hash) = decode_certified_header(&compact).unwrap();
        assert_eq!(header.number(), 7);
        assert_eq!(hash, certified.block_hash);

        let mut trailing_finalization = compact.clone();
        trailing_finalization.finalization.push(0);
        assert!(decode_certified_header(&trailing_finalization)
            .unwrap_err()
            .contains("trailing bytes after Commonware finalization"));

        let mut trailing_header = compact;
        trailing_header.header.push(0);
        assert!(decode_certified_header(&trailing_header)
            .unwrap_err()
            .contains("trailing bytes after canonical Outbe header"));
    }

    #[test]
    fn streaming_verifier_crosses_256_committee_transitions() {
        use outbe_consensus::finalized_admission_test_utils::FinalityCommitteeFixture;
        use outbe_primitives::tee_attestation_v1::NetworkBindingV1;

        const LAST_EPOCH: u64 = 300;
        let context = DcapOnboardingContextV1 {
            chain_id: U256::ZERO.to_be_bytes(),
            ..context()
        };
        let committee = FinalityCommitteeFixture::new(90);
        let descriptor = TrustedNetworkDescriptorV1 {
            network_binding: NetworkBindingV1 {
                chain_id: context.chain_id,
                genesis_hash: context.genesis_hash,
                attestation_mode:
                    outbe_primitives::tee_attestation_v1::AttestationMode::DcapRequired,
            },
            genesis_consensus_keys: committee.public_keys_min_pk(),
        };
        let mut verifier = FinalizedAdmissionVerifierV1::new(
            &descriptor,
            &context,
            &committee.outcome(Epoch::new(0)),
        )
        .unwrap();

        for epoch in 0..LAST_EPOCH {
            let certified = committee.certify_block(
                Epoch::new(epoch),
                epoch + 1,
                1_000 + epoch,
                B256::repeat_byte(0x91),
                committee.preannounce_extra_data(Epoch::new(epoch + 1)),
            );
            verifier
                .advance_committee(
                    &compact_certified_header(&certified.finalization, &certified.block)
                        .encode_canonical()
                        .unwrap(),
                )
                .unwrap();
        }

        assert_eq!(
            verifier.chain.highest_registered(),
            Some(Epoch::new(LAST_EPOCH))
        );
        assert_eq!(verifier.previous_height, LAST_EPOCH);
    }

    #[test]
    fn real_e0_to_e1_finalization_chain_and_registry_mpt_verify_end_to_end() {
        use std::collections::BTreeMap;

        use alloy_primitives::{keccak256, Bytes};
        use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount};
        use outbe_consensus::finalized_admission_test_utils::FinalityCommitteeFixture;
        use outbe_primitives::tee_attestation_v1::NetworkBindingV1;

        fn storage_trie(slots: &[(U256, U256)]) -> (B256, Vec<Vec<Bytes>>) {
            let targets = slots
                .iter()
                .map(|(slot, _)| Nibbles::unpack(keccak256(slot.to_be_bytes::<32>())))
                .collect::<Vec<_>>();
            let mut leaves = BTreeMap::new();
            for ((_, value), target) in slots.iter().zip(&targets) {
                if !value.is_zero() {
                    leaves.insert(*target, alloy_rlp::encode_fixed_size(value).to_vec());
                }
            }
            let mut builder = HashBuilder::default()
                .with_proof_retainer(ProofRetainer::from_iter(targets.clone()));
            for (path, value) in leaves {
                builder.add_leaf(path, &value);
            }
            let root = builder.root();
            let retained = builder.take_proof_nodes();
            let proofs = targets
                .iter()
                .map(|target| {
                    retained
                        .matching_nodes_sorted(target)
                        .into_iter()
                        .map(|(_, node)| node)
                        .collect()
                })
                .collect();
            (root, proofs)
        }

        fn account_trie(account: TrieAccount) -> (B256, Vec<Bytes>) {
            let target = Nibbles::unpack(keccak256(TEE_REGISTRY_ADDRESS));
            let mut builder =
                HashBuilder::default().with_proof_retainer(ProofRetainer::from_iter([target]));
            builder.add_leaf(target, &alloy_rlp::encode(account));
            let root = builder.root();
            let proof = builder
                .take_proof_nodes()
                .matching_nodes_sorted(&target)
                .into_iter()
                .map(|(_, node)| node)
                .collect();
            (root, proof)
        }

        let context = DcapOnboardingContextV1 {
            chain_id: U256::ZERO.to_be_bytes(),
            ..context()
        };
        let epoch0 = FinalityCommitteeFixture::new(10);
        let epoch1 = FinalityCommitteeFixture::new(50);
        let descriptor = TrustedNetworkDescriptorV1 {
            network_binding: NetworkBindingV1 {
                chain_id: context.chain_id,
                genesis_hash: context.genesis_hash,
                attestation_mode:
                    outbe_primitives::tee_attestation_v1::AttestationMode::DcapRequired,
            },
            genesis_consensus_keys: epoch0.public_keys_min_pk(),
        };
        let slots = onboarding_registry_slots_v1(&context);
        let values = [
            U256::from_be_bytes(context.tribute_offer_public),
            U256::from(context.key_epoch),
            U256::from(context.tribute_offer_epoch),
            U256::from_be_bytes(context.enclave_id.0),
            U256::from_be_bytes(context.binding_id.0),
            U256::from_be_bytes(context.intent_hash.0),
            U256::from_be_bytes(context.policy_hash.0),
            U256::from(2_000_u64),
            U256::from_be_bytes(context.recipient_x25519),
        ];
        let storage_leaves = slots
            .iter()
            .zip(values)
            .map(|(slot, value)| (U256::from_be_bytes(slot.0), value))
            .collect::<Vec<_>>();
        let (storage_root, storage_proofs) = storage_trie(&storage_leaves);
        let code_hash = B256::repeat_byte(0x91);
        let account = TrieAccount {
            nonce: 1,
            balance: U256::from(2_u64),
            storage_root,
            code_hash,
        };
        let (state_root, account_proof) = account_trie(account);

        let transition = epoch0.certify_block(
            Epoch::new(0),
            1,
            900,
            B256::repeat_byte(0x81),
            epoch1.preannounce_extra_data(Epoch::new(1)),
        );
        let admission = epoch1.certify_block(Epoch::new(1), 2, 1_000, state_root, Vec::new());

        let transition_record =
            compact_certified_header(&transition.finalization, &transition.block)
                .encode_canonical()
                .unwrap();
        let proof = FinalizedAdmissionWitnessV1 {
            admission: compact_certified_header(&admission.finalization, &admission.block),
            registry_account: MptAccountProofV1 {
                nonce: account.nonce,
                balance: account.balance,
                code_hash,
                storage_root,
                nodes: account_proof
                    .into_iter()
                    .map(|node| node.to_vec())
                    .collect(),
            },
            registry_storage: slots
                .iter()
                .zip(values)
                .zip(storage_proofs)
                .map(|((key, value), nodes)| MptStorageProofV1 {
                    key: *key,
                    value,
                    nodes: nodes.into_iter().map(|node| node.to_vec()).collect(),
                })
                .collect(),
        };
        let mut verifier = FinalizedAdmissionVerifierV1::new(
            &descriptor,
            &context,
            &epoch0.outcome(Epoch::new(0)),
        )
        .unwrap();
        verifier.advance_committee(&transition_record).unwrap();
        let verified = verifier
            .verify_admission(&proof.encode_canonical().unwrap())
            .unwrap();
        assert_eq!(verified.block_number, 2);
        assert_eq!(verified.block_hash, admission.block_hash);
        assert_eq!(verified.state_root, state_root);
        assert_eq!(verified.consensus_timestamp, 1_000);
    }
}
