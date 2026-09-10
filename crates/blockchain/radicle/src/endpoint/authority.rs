use super::{
    wire::{EndpointResponseBody, SignedEndpointResponse, WireError},
    ChainIdentity, ENDPOINT_SIGNATURE_NAMESPACE, MAX_ENDPOINT_TTL_BLOCKS,
};
use alloy_primitives::{Address, B256};
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{bls12381, Signer, Verifier};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 48]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityRecord {
    pub validator: Address,
    pub peer: PeerId,
    pub node_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSnapshot {
    pub number: u64,
    pub hash: B256,
    authorities: BTreeMap<Address, AuthorityRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationContext {
    pub chain: ChainIdentity,
    pub current_height: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEndpoint {
    pub validator: Address,
    pub peer: PeerId,
    pub node_id: [u8; 32],
    pub addresses: Vec<super::EndpointAddress>,
    pub anchor_number: u64,
    pub anchor_hash: B256,
    pub valid_until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AnchorError {
    #[error("duplicate validator authority")]
    DuplicateValidator,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("response belongs to another chain")]
    Chain,
    #[error("response anchor does not match the exact snapshot")]
    Anchor,
    #[error("validator is not active at the exact anchor")]
    Inactive,
    #[error("transport peer does not match validator BLS identity")]
    TransportPeer,
    #[error("response NodeId does not match the on-chain binding")]
    NodeId,
    #[error("endpoint response is expired")]
    Expired,
    #[error("endpoint response TTL exceeds the protocol maximum")]
    Ttl,
    #[error("BLS public key encoding is invalid")]
    PublicKeyEncoding,
    #[error("BLS signature encoding is invalid")]
    SignatureEncoding,
    #[error("BLS signature verification failed")]
    Signature,
}

impl PeerId {
    pub fn from_public_key(key: &bls12381::PublicKey) -> Self {
        let mut bytes = [0; 48];
        bytes.copy_from_slice(key.as_ref());
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    pub fn to_public_key(self) -> Result<bls12381::PublicKey, VerifyError> {
        <bls12381::PublicKey as DecodeExt<()>>::decode(Bytes::copy_from_slice(&self.0))
            .map_err(|_| VerifyError::PublicKeyEncoding)
    }
}

impl AnchorSnapshot {
    pub fn new(
        number: u64,
        hash: B256,
        authorities: Vec<AuthorityRecord>,
    ) -> Result<Self, AnchorError> {
        let mut indexed = BTreeMap::new();
        for authority in authorities {
            let validator = authority.validator;
            if indexed.insert(validator, authority).is_some() {
                return Err(AnchorError::DuplicateValidator);
            }
        }
        Ok(Self {
            number,
            hash,
            authorities: indexed,
        })
    }

    pub fn authority(&self, validator: Address) -> Option<&AuthorityRecord> {
        self.authorities.get(&validator)
    }
}

pub fn sign_response(
    body: EndpointResponseBody,
    signer: &bls12381::PrivateKey,
) -> Result<SignedEndpointResponse, WireError> {
    super::wire::validate_body(&body)?;
    let message = body.signing_bytes();
    let signature = signer.sign(ENDPOINT_SIGNATURE_NAMESPACE, &message).encode();
    let mut bytes = [0; 96];
    bytes.copy_from_slice(signature.as_ref());
    SignedEndpointResponse::new(body, bytes)
}

pub fn verify_response(
    sender: PeerId,
    response: &SignedEndpointResponse,
    snapshot: &AnchorSnapshot,
    context: VerificationContext,
) -> Result<VerifiedEndpoint, VerifyError> {
    let body = response.body();
    verify_chain_and_time(body, context)?;
    if body.anchor_number != snapshot.number || body.anchor_hash != snapshot.hash {
        return Err(VerifyError::Anchor);
    }
    let authority = snapshot
        .authority(body.validator)
        .ok_or(VerifyError::Inactive)?;
    if sender != authority.peer {
        return Err(VerifyError::TransportPeer);
    }
    if body.node_id != authority.node_id {
        return Err(VerifyError::NodeId);
    }

    verify_signature(authority.peer, response)?;
    Ok(VerifiedEndpoint {
        validator: body.validator,
        peer: sender,
        node_id: body.node_id,
        addresses: body.addresses.clone(),
        anchor_number: body.anchor_number,
        anchor_hash: body.anchor_hash,
        valid_until: body.valid_until,
    })
}

pub(crate) fn verify_future_response(
    sender: PeerId,
    response: &SignedEndpointResponse,
    context: VerificationContext,
) -> Result<(), VerifyError> {
    verify_chain_and_time(response.body(), context)?;
    verify_signature(sender, response)
}

fn verify_chain_and_time(
    body: &EndpointResponseBody,
    context: VerificationContext,
) -> Result<(), VerifyError> {
    if body.chain_id != context.chain.chain_id || body.genesis_hash != context.chain.genesis_hash {
        return Err(VerifyError::Chain);
    }
    if body.valid_until <= context.current_height || body.valid_until <= body.anchor_number {
        return Err(VerifyError::Expired);
    }
    if body.valid_until - body.anchor_number > MAX_ENDPOINT_TTL_BLOCKS {
        return Err(VerifyError::Ttl);
    }
    Ok(())
}

fn verify_signature(peer: PeerId, response: &SignedEndpointResponse) -> Result<(), VerifyError> {
    let public_key = peer.to_public_key()?;
    let signature = <bls12381::Signature as DecodeExt<()>>::decode(Bytes::copy_from_slice(
        response.signature(),
    ))
    .map_err(|_| VerifyError::SignatureEncoding)?;
    if signature.encode().as_ref() != response.signature() {
        return Err(VerifyError::SignatureEncoding);
    }
    if !public_key.verify(
        ENDPOINT_SIGNATURE_NAMESPACE,
        &response.signing_bytes(),
        &signature,
    ) {
        return Err(VerifyError::Signature);
    }
    Ok(())
}
