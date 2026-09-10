use super::MAX_DNS_LENGTH;
use std::net::IpAddr;

const IPV4_TAG: u8 = 0;
const IPV6_TAG: u8 = 1;
const DNS_TAG: u8 = 2;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EndpointAddress {
    Ipv4(Ipv4Endpoint),
    Ipv6(Ipv6Endpoint),
    Dns(DnsEndpoint),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4Endpoint {
    octets: [u8; 4],
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv6Endpoint {
    octets: [u8; 16],
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DnsEndpoint {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AddressError {
    #[error("endpoint port must be non-zero")]
    ZeroPort,
    #[error("DNS endpoint must not have a trailing dot")]
    TrailingDot,
    #[error("DNS endpoint contains an empty label")]
    EmptyLabel,
    #[error("DNS endpoint label exceeds 63 ASCII bytes")]
    LabelTooLong,
    #[error("DNS endpoint exceeds 253 ASCII bytes")]
    NameTooLong,
    #[error("DNS endpoint is an IP literal")]
    IpLiteral,
    #[error("DNS endpoint is not valid UTS #46 STD3 input")]
    InvalidDns,
    #[error("DNS wire form is not canonical")]
    NonCanonicalDns,
    #[error("unknown endpoint address tag {0}")]
    Tag(u8),
    #[error("truncated endpoint address")]
    Truncated,
    #[error("trailing endpoint address bytes")]
    TrailingBytes,
}

impl EndpointAddress {
    pub fn ipv4(octets: [u8; 4], port: u16) -> Result<Self, AddressError> {
        require_port(port)?;
        Ok(Self::Ipv4(Ipv4Endpoint { octets, port }))
    }

    pub fn ipv6(octets: [u8; 16], port: u16) -> Result<Self, AddressError> {
        require_port(port)?;
        Ok(Self::Ipv6(Ipv6Endpoint { octets, port }))
    }

    pub fn dns(host: &str, port: u16) -> Result<Self, AddressError> {
        require_port(port)?;
        if host.ends_with('.') {
            return Err(AddressError::TrailingDot);
        }
        if host.split('.').any(str::is_empty) {
            return Err(AddressError::EmptyLabel);
        }
        if host.parse::<IpAddr>().is_ok() {
            return Err(AddressError::IpLiteral);
        }
        if host.is_ascii() {
            validate_ascii_dns(&host.to_ascii_lowercase())?;
        }
        let host = idna::domain_to_ascii_strict(host).map_err(|_| AddressError::InvalidDns)?;
        let host = host.to_ascii_lowercase();
        validate_ascii_dns(&host)?;
        Ok(Self::Dns(DnsEndpoint { host, port }))
    }

    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Dns(endpoint) => Some(&endpoint.host),
            _ => None,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ipv4(endpoint) => endpoint.port,
            Self::Ipv6(endpoint) => endpoint.port,
            Self::Dns(endpoint) => endpoint.port,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.encoded_len());
        self.write_to(&mut output);
        output
    }

    pub fn decode(input: &[u8]) -> Result<Self, AddressError> {
        let mut offset = 0;
        let address = Self::read_from(input, &mut offset)?;
        if offset != input.len() {
            return Err(AddressError::TrailingBytes);
        }
        Ok(address)
    }

    pub(crate) fn encoded_len(&self) -> usize {
        match self {
            Self::Ipv4(_) => 7,
            Self::Ipv6(_) => 19,
            Self::Dns(endpoint) => 4 + endpoint.host.len(),
        }
    }

    pub(crate) fn write_to(&self, output: &mut Vec<u8>) {
        match self {
            Self::Ipv4(endpoint) => {
                output.push(IPV4_TAG);
                output.extend_from_slice(&endpoint.octets);
                output.extend_from_slice(&endpoint.port.to_be_bytes());
            }
            Self::Ipv6(endpoint) => {
                output.push(IPV6_TAG);
                output.extend_from_slice(&endpoint.octets);
                output.extend_from_slice(&endpoint.port.to_be_bytes());
            }
            Self::Dns(endpoint) => {
                output.push(DNS_TAG);
                output.push(endpoint.host.len() as u8);
                output.extend_from_slice(endpoint.host.as_bytes());
                output.extend_from_slice(&endpoint.port.to_be_bytes());
            }
        }
    }

    pub(crate) fn read_from(input: &[u8], offset: &mut usize) -> Result<Self, AddressError> {
        let tag = take_byte(input, offset)?;
        match tag {
            IPV4_TAG => {
                let octets = take_array::<4>(input, offset)?;
                let port = u16::from_be_bytes(take_array::<2>(input, offset)?);
                Self::ipv4(octets, port)
            }
            IPV6_TAG => {
                let octets = take_array::<16>(input, offset)?;
                let port = u16::from_be_bytes(take_array::<2>(input, offset)?);
                Self::ipv6(octets, port)
            }
            DNS_TAG => {
                let length = take_byte(input, offset)? as usize;
                let bytes = take_slice(input, offset, length)?;
                if !bytes.is_ascii() {
                    return Err(AddressError::NonCanonicalDns);
                }
                let host = std::str::from_utf8(bytes).map_err(|_| AddressError::NonCanonicalDns)?;
                let port = u16::from_be_bytes(take_array::<2>(input, offset)?);
                let decoded = Self::dns(host, port)?;
                if decoded.host() != Some(host) {
                    return Err(AddressError::NonCanonicalDns);
                }
                Ok(decoded)
            }
            other => Err(AddressError::Tag(other)),
        }
    }
}

fn require_port(port: u16) -> Result<(), AddressError> {
    if port == 0 {
        Err(AddressError::ZeroPort)
    } else {
        Ok(())
    }
}

fn validate_ascii_dns(host: &str) -> Result<(), AddressError> {
    if !host.is_ascii() {
        return Err(AddressError::InvalidDns);
    }
    if host.len() > MAX_DNS_LENGTH {
        return Err(AddressError::NameTooLong);
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(AddressError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(AddressError::LabelTooLong);
        }
    }
    Ok(())
}

fn take_byte(input: &[u8], offset: &mut usize) -> Result<u8, AddressError> {
    let byte = *input.get(*offset).ok_or(AddressError::Truncated)?;
    *offset += 1;
    Ok(byte)
}

fn take_array<const N: usize>(input: &[u8], offset: &mut usize) -> Result<[u8; N], AddressError> {
    let slice = take_slice(input, offset, N)?;
    let mut output = [0; N];
    output.copy_from_slice(slice);
    Ok(output)
}

fn take_slice<'a>(
    input: &'a [u8],
    offset: &mut usize,
    length: usize,
) -> Result<&'a [u8], AddressError> {
    let end = offset.checked_add(length).ok_or(AddressError::Truncated)?;
    let slice = input.get(*offset..end).ok_or(AddressError::Truncated)?;
    *offset = end;
    Ok(slice)
}
