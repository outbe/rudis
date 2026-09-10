mod support;

use alloy_primitives::{Address, B256};
use commonware_codec::Encode;
use commonware_cryptography::Signer;
use outbe_radicle::endpoint::{
    sign_response, verify_response, AuthorityRecord, PeerId, VerificationContext, VerifyError,
};

#[test]
fn verify_matrix() {
    let signer = support::key(7);
    let other = support::key(8);
    let validator = Address::repeat_byte(0x33);
    let node_id = [0x44; 32];
    let snapshot = support::snapshot(validator, node_id, &signer);
    let response = support::signed([1; 32], validator, node_id, &signer);
    let context = VerificationContext {
        chain: support::chain(),
        current_height: 100,
    };

    let verified = verify_response(support::peer(&signer), &response, &snapshot, context).unwrap();
    assert_eq!(verified.validator, validator);
    assert_eq!(verified.node_id, node_id);

    assert_eq!(
        verify_response(support::peer(&other), &response, &snapshot, context),
        Err(VerifyError::TransportPeer)
    );

    let mut wrong_genesis = support::body([1; 32], validator, node_id);
    wrong_genesis.genesis_hash = B256::repeat_byte(0x99);
    let wrong_genesis = sign_response(wrong_genesis, &signer).unwrap();
    assert_eq!(
        verify_response(support::peer(&signer), &wrong_genesis, &snapshot, context,),
        Err(VerifyError::Chain)
    );

    let mut wrong_chain = support::body([1; 32], validator, node_id);
    wrong_chain.chain_id += 1;
    let wrong_chain = sign_response(wrong_chain, &signer).unwrap();
    assert_eq!(
        verify_response(support::peer(&signer), &wrong_chain, &snapshot, context),
        Err(VerifyError::Chain)
    );

    let mut wrong_node = support::body([1; 32], validator, [9; 32]);
    wrong_node.node_id = [9; 32];
    let wrong_node = sign_response(wrong_node, &signer).unwrap();
    assert_eq!(
        verify_response(support::peer(&signer), &wrong_node, &snapshot, context),
        Err(VerifyError::NodeId)
    );

    let inactive =
        outbe_radicle::endpoint::AnchorSnapshot::new(100, support::ANCHOR_HASH, vec![]).unwrap();
    assert_eq!(
        verify_response(support::peer(&signer), &response, &inactive, context),
        Err(VerifyError::Inactive)
    );
}

#[test]
fn anchor_and_signature_matrix() {
    let signer = support::key(9);
    let validator = Address::repeat_byte(0x55);
    let node_id = [0x66; 32];
    let snapshot = support::snapshot(validator, node_id, &signer);
    let context = VerificationContext {
        chain: support::chain(),
        current_height: 100,
    };

    let mut expired = support::body([2; 32], validator, node_id);
    expired.valid_until = 100;
    assert_eq!(
        verify_response(
            support::peer(&signer),
            &sign_response(expired, &signer).unwrap(),
            &snapshot,
            context,
        ),
        Err(VerifyError::Expired)
    );

    let mut ttl = support::body([2; 32], validator, node_id);
    ttl.valid_until = ttl.anchor_number + 257;
    assert_eq!(
        verify_response(
            support::peer(&signer),
            &sign_response(ttl, &signer).unwrap(),
            &snapshot,
            context,
        ),
        Err(VerifyError::Ttl)
    );

    let mut wrong_anchor = support::body([2; 32], validator, node_id);
    wrong_anchor.anchor_hash = B256::repeat_byte(0x77);
    assert_eq!(
        verify_response(
            support::peer(&signer),
            &sign_response(wrong_anchor, &signer).unwrap(),
            &snapshot,
            context,
        ),
        Err(VerifyError::Anchor)
    );

    let wrong_signer = support::key(999);
    let wrong_signature =
        sign_response(support::body([3; 32], validator, node_id), &wrong_signer).unwrap();
    assert_eq!(
        verify_response(support::peer(&signer), &wrong_signature, &snapshot, context,),
        Err(VerifyError::Signature)
    );

    let wrong_domain = support::signed([4; 32], validator, node_id, &signer);
    let frame =
        outbe_radicle::endpoint::EndpointFrame::Response(Box::new(wrong_domain.clone())).encode();
    let message = &frame[5..frame.len() - 96];
    let signature = signer.sign(b"WRONG_RADICLE_DOMAIN", message).encode();
    let mut signature_bytes = [0; 96];
    signature_bytes.copy_from_slice(signature.as_ref());
    let wrong_domain = outbe_radicle::endpoint::SignedEndpointResponse::new(
        wrong_domain.body().clone(),
        signature_bytes,
    )
    .unwrap();
    assert_eq!(
        verify_response(support::peer(&signer), &wrong_domain, &snapshot, context,),
        Err(VerifyError::Signature)
    );
}

#[test]
fn authority_snapshot_rejects_duplicates() {
    let signer = support::key(10);
    let validator = Address::repeat_byte(0x77);
    let record = AuthorityRecord {
        validator,
        peer: PeerId::from_public_key(&signer.public_key()),
        node_id: [1; 32],
    };
    assert!(outbe_radicle::endpoint::AnchorSnapshot::new(
        1,
        B256::ZERO,
        vec![record.clone(), record],
    )
    .is_err());
}
