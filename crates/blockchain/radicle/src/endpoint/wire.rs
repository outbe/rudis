use super::{
    address::{AddressError, EndpointAddress},
    MAX_ADDRESSES, MAX_ENDPOINT_FRAME_BYTES, RADICLE_ENDPOINT_MAGIC, RADICLE_ENDPOINT_REQUEST_TAG,
    RADICLE_ENDPOINT_RESPONSE_TAG, RADICLE_ENDPOINT_WIRE_VERSION,
};
use alloy_primitives::{Address, B256};
use bytes::Bytes;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381;

const REQUEST_SIZE: usize = 38;
const RESPONSE_FIXED_SIZE: usize = 275;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointRequest {
    request_id: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointResponseBody {
    pub request_id: [u8; 32],
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub validator: Address,
    pub node_id: [u8; 32],
    pub addresses: Vec<EndpointAddress>,
    pub anchor_number: u64,
    pub anchor_hash: B256,
    pub valid_until: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedEndpointResponse {
    body: EndpointResponseBody,
    signature: [u8; 96],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointFrame {
    Request(EndpointRequest),
    Response(Box<SignedEndpointResponse>),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("endpoint frame exceeds the protocol cap")]
    Oversized,
    #[error("endpoint frame is truncated")]
    Truncated,
    #[error("invalid endpoint frame magic")]
    Magic,
    #[error("unknown endpoint frame tag {0}")]
    Tag(u8),
    #[error("unsupported endpoint wire version {0}")]
    Version(u8),
    #[error("request id must be non-zero")]
    ZeroRequestId,
    #[error("too many endpoint addresses")]
    TooManyAddresses,
    #[error("endpoint addresses are duplicate or unsorted")]
    AddressOrder,
    #[error("endpoint signature is not canonical BLS MinPk bytes")]
    SignatureEncoding,
    #[error("endpoint frame has trailing bytes")]
    TrailingBytes,
    #[error(transparent)]
    Address(#[from] AddressError),
}

impl EndpointRequest {
    pub fn new(request_id: [u8; 32]) -> Result<Self, WireError> {
        require_request_id(request_id)?;
        Ok(Self { request_id })
    }

    pub fn request_id(&self) -> [u8; 32] {
        self.request_id
    }
}

impl SignedEndpointResponse {
    pub fn new(body: EndpointResponseBody, signature: [u8; 96]) -> Result<Self, WireError> {
        validate_body(&body)?;
        validate_signature(&signature)?;
        Ok(Self { body, signature })
    }

    pub fn body(&self) -> &EndpointResponseBody {
        &self.body
    }

    pub fn signature(&self) -> &[u8; 96] {
        &self.signature
    }

    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        self.body.signing_bytes()
    }
}

impl EndpointResponseBody {
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        let address_bytes = self
            .addresses
            .iter()
            .map(EndpointAddress::encoded_len)
            .sum::<usize>();
        let mut output = Vec::with_capacity(RESPONSE_FIXED_SIZE - 5 - 96 + address_bytes);
        output.push(RADICLE_ENDPOINT_WIRE_VERSION);
        output.extend_from_slice(&self.request_id);
        output.extend_from_slice(&self.chain_id.to_be_bytes());
        output.extend_from_slice(self.genesis_hash.as_slice());
        output.extend_from_slice(self.validator.as_slice());
        output.extend_from_slice(&self.node_id);
        output.push(self.addresses.len() as u8);
        for address in &self.addresses {
            address.write_to(&mut output);
        }
        output.extend_from_slice(&self.anchor_number.to_be_bytes());
        output.extend_from_slice(self.anchor_hash.as_slice());
        output.extend_from_slice(&self.valid_until.to_be_bytes());
        output
    }
}

impl EndpointFrame {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Request(request) => {
                let mut output = Vec::with_capacity(REQUEST_SIZE);
                output.extend_from_slice(&RADICLE_ENDPOINT_MAGIC);
                output.push(RADICLE_ENDPOINT_REQUEST_TAG);
                output.push(RADICLE_ENDPOINT_WIRE_VERSION);
                output.extend_from_slice(&request.request_id);
                output
            }
            Self::Response(response) => {
                let body = response.signing_bytes();
                let mut output = Vec::with_capacity(5 + body.len() + response.signature.len());
                output.extend_from_slice(&RADICLE_ENDPOINT_MAGIC);
                output.push(RADICLE_ENDPOINT_RESPONSE_TAG);
                output.extend_from_slice(&body);
                output.extend_from_slice(&response.signature);
                output
            }
        }
    }

    pub fn decode(input: &[u8]) -> Result<Self, WireError> {
        if input.len() > MAX_ENDPOINT_FRAME_BYTES {
            return Err(WireError::Oversized);
        }
        if input.len() < 6 {
            return Err(WireError::Truncated);
        }
        if input[..4] != RADICLE_ENDPOINT_MAGIC {
            return Err(WireError::Magic);
        }
        let tag = input[4];
        let version = input[5];
        if version != RADICLE_ENDPOINT_WIRE_VERSION {
            return Err(WireError::Version(version));
        }
        match tag {
            RADICLE_ENDPOINT_REQUEST_TAG => decode_request(input),
            RADICLE_ENDPOINT_RESPONSE_TAG => decode_response(input),
            other => Err(WireError::Tag(other)),
        }
    }
}

fn decode_request(input: &[u8]) -> Result<EndpointFrame, WireError> {
    if input.len() < REQUEST_SIZE {
        return Err(WireError::Truncated);
    }
    if input.len() > REQUEST_SIZE {
        return Err(WireError::TrailingBytes);
    }
    let request_id = array_at::<32>(input, 6)?;
    Ok(EndpointFrame::Request(EndpointRequest::new(request_id)?))
}

fn decode_response(input: &[u8]) -> Result<EndpointFrame, WireError> {
    if input.len() < RESPONSE_FIXED_SIZE {
        return Err(WireError::Truncated);
    }
    let mut offset = 6;
    let request_id = take_array::<32>(input, &mut offset)?;
    let chain_id = u64::from_be_bytes(take_array::<8>(input, &mut offset)?);
    let genesis_hash = B256::from(take_array::<32>(input, &mut offset)?);
    let validator = Address::from(take_array::<20>(input, &mut offset)?);
    let node_id = take_array::<32>(input, &mut offset)?;
    let address_count = take_byte(input, &mut offset)? as usize;
    if address_count > MAX_ADDRESSES {
        return Err(WireError::TooManyAddresses);
    }
    let mut addresses = Vec::with_capacity(address_count);
    for _ in 0..address_count {
        addresses.push(EndpointAddress::read_from(input, &mut offset)?);
    }
    let anchor_number = u64::from_be_bytes(take_array::<8>(input, &mut offset)?);
    let anchor_hash = B256::from(take_array::<32>(input, &mut offset)?);
    let valid_until = u64::from_be_bytes(take_array::<8>(input, &mut offset)?);
    let signature = take_array::<96>(input, &mut offset)?;
    if offset != input.len() {
        return Err(WireError::TrailingBytes);
    }
    let body = EndpointResponseBody {
        request_id,
        chain_id,
        genesis_hash,
        validator,
        node_id,
        addresses,
        anchor_number,
        anchor_hash,
        valid_until,
    };
    Ok(EndpointFrame::Response(Box::new(
        SignedEndpointResponse::new(body, signature)?,
    )))
}

pub(crate) fn validate_body(body: &EndpointResponseBody) -> Result<(), WireError> {
    require_request_id(body.request_id)?;
    if body.addresses.len() > MAX_ADDRESSES {
        return Err(WireError::TooManyAddresses);
    }
    if body
        .addresses
        .windows(2)
        .any(|window| window[0].encode() >= window[1].encode())
    {
        return Err(WireError::AddressOrder);
    }
    Ok(())
}

fn validate_signature(bytes: &[u8; 96]) -> Result<(), WireError> {
    let signature = <bls12381::Signature as DecodeExt<()>>::decode(Bytes::copy_from_slice(bytes))
        .map_err(|_| WireError::SignatureEncoding)?;
    let encoded = signature.encode();
    if encoded.as_ref() != bytes {
        return Err(WireError::SignatureEncoding);
    }
    Ok(())
}

fn require_request_id(request_id: [u8; 32]) -> Result<(), WireError> {
    if request_id == [0; 32] {
        Err(WireError::ZeroRequestId)
    } else {
        Ok(())
    }
}

fn array_at<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], WireError> {
    let mut cursor = offset;
    take_array(input, &mut cursor)
}

fn take_byte(input: &[u8], offset: &mut usize) -> Result<u8, WireError> {
    let byte = *input.get(*offset).ok_or(WireError::Truncated)?;
    *offset += 1;
    Ok(byte)
}

fn take_array<const N: usize>(input: &[u8], offset: &mut usize) -> Result<[u8; N], WireError> {
    let end = offset.checked_add(N).ok_or(WireError::Truncated)?;
    let slice = input.get(*offset..end).ok_or(WireError::Truncated)?;
    let mut output = [0; N];
    output.copy_from_slice(slice);
    *offset = end;
    Ok(output)
}
