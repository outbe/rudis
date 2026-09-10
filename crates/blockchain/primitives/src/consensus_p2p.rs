use alloc::{string::String, vec::Vec};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const P2P_ADDRESS_VERSION_V1: u8 = 1;
pub const MAX_P2P_ADDRESS_ENCODED_LEN: usize = 512;

const ADDR_SYMMETRIC: u8 = 0;
const ADDR_ASYMMETRIC: u8 = 1;
const INGRESS_SOCKET: u8 = 0;
const INGRESS_DNS: u8 = 1;
const IP_V4: u8 = 4;
const IP_V6: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pAddress {
    Symmetric(SocketAddr),
    Asymmetric {
        ingress: P2pIngress,
        egress: SocketAddr,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum P2pIngress {
    Socket(SocketAddr),
    Dns { host: String, port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum P2pAddressError {
    #[error("unsupported p2p address version {0}")]
    UnsupportedVersion(u8),
    #[error("p2p address payload exceeds max length {actual}>{max}")]
    TooLarge { actual: usize, max: usize },
    #[error("p2p address payload is truncated")]
    Truncated,
    #[error("p2p address payload has trailing bytes")]
    TrailingBytes,
    #[error("invalid p2p address kind {0}")]
    InvalidAddressKind(u8),
    #[error("invalid p2p ingress kind {0}")]
    InvalidIngressKind(u8),
    #[error("invalid p2p ip kind {0}")]
    InvalidIpKind(u8),
    #[error("p2p socket port must be non-zero")]
    ZeroPort,
    #[error("p2p hostname is invalid")]
    InvalidHostname,
}

pub fn encode_v1(address: &P2pAddress) -> Vec<u8> {
    let mut out = Vec::new();
    match address {
        P2pAddress::Symmetric(socket) => {
            out.push(ADDR_SYMMETRIC);
            encode_socket(*socket, &mut out);
        }
        P2pAddress::Asymmetric { ingress, egress } => {
            out.push(ADDR_ASYMMETRIC);
            encode_ingress(ingress, &mut out);
            encode_socket(*egress, &mut out);
        }
    }
    out
}

pub fn decode_versioned(version: u8, payload: &[u8]) -> Result<P2pAddress, P2pAddressError> {
    if version != P2P_ADDRESS_VERSION_V1 {
        return Err(P2pAddressError::UnsupportedVersion(version));
    }
    decode_v1(payload)
}

pub fn decode_v1(payload: &[u8]) -> Result<P2pAddress, P2pAddressError> {
    validate_len(payload)?;
    let mut cursor = Cursor::new(payload);
    let kind = cursor.read_u8()?;
    let address = match kind {
        ADDR_SYMMETRIC => P2pAddress::Symmetric(cursor.read_socket()?),
        ADDR_ASYMMETRIC => P2pAddress::Asymmetric {
            ingress: cursor.read_ingress()?,
            egress: cursor.read_socket()?,
        },
        other => return Err(P2pAddressError::InvalidAddressKind(other)),
    };
    if !cursor.is_finished() {
        return Err(P2pAddressError::TrailingBytes);
    }
    Ok(address)
}

pub fn validate_versioned(version: u8, payload: &[u8]) -> Result<(), P2pAddressError> {
    decode_versioned(version, payload).map(|_| ())
}

fn validate_len(payload: &[u8]) -> Result<(), P2pAddressError> {
    if payload.len() > MAX_P2P_ADDRESS_ENCODED_LEN {
        return Err(P2pAddressError::TooLarge {
            actual: payload.len(),
            max: MAX_P2P_ADDRESS_ENCODED_LEN,
        });
    }
    Ok(())
}

fn encode_ingress(ingress: &P2pIngress, out: &mut Vec<u8>) {
    match ingress {
        P2pIngress::Socket(socket) => {
            out.push(INGRESS_SOCKET);
            encode_socket(*socket, out);
        }
        P2pIngress::Dns { host, port } => {
            out.push(INGRESS_DNS);
            out.extend_from_slice(&(host.len() as u16).to_be_bytes());
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

fn encode_socket(socket: SocketAddr, out: &mut Vec<u8>) {
    match socket.ip() {
        IpAddr::V4(ip) => {
            out.push(IP_V4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(IP_V6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&socket.port().to_be_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_u8(&mut self) -> Result<u8, P2pAddressError> {
        let Some(value) = self.bytes.get(self.offset) else {
            return Err(P2pAddressError::Truncated);
        };
        self.offset += 1;
        Ok(*value)
    }

    fn read_u16(&mut self) -> Result<u16, P2pAddressError> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], P2pAddressError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(P2pAddressError::Truncated)?;
        let Some(bytes) = self.bytes.get(self.offset..end) else {
            return Err(P2pAddressError::Truncated);
        };
        self.offset = end;
        Ok(bytes)
    }

    fn read_socket(&mut self) -> Result<SocketAddr, P2pAddressError> {
        let ip_kind = self.read_u8()?;
        let ip = match ip_kind {
            IP_V4 => {
                let bytes = self.read_exact(4)?;
                IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
            }
            IP_V6 => {
                let bytes = self.read_exact(16)?;
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            other => return Err(P2pAddressError::InvalidIpKind(other)),
        };
        let port = self.read_u16()?;
        if port == 0 {
            return Err(P2pAddressError::ZeroPort);
        }
        Ok(SocketAddr::new(ip, port))
    }

    fn read_ingress(&mut self) -> Result<P2pIngress, P2pAddressError> {
        match self.read_u8()? {
            INGRESS_SOCKET => Ok(P2pIngress::Socket(self.read_socket()?)),
            INGRESS_DNS => {
                let host_len = self.read_u16()? as usize;
                let host_bytes = self.read_exact(host_len)?;
                let host = core::str::from_utf8(host_bytes)
                    .map_err(|_| P2pAddressError::InvalidHostname)?
                    .to_owned();
                validate_hostname(&host)?;
                let port = self.read_u16()?;
                if port == 0 {
                    return Err(P2pAddressError::ZeroPort);
                }
                Ok(P2pIngress::Dns { host, port })
            }
            other => Err(P2pAddressError::InvalidIngressKind(other)),
        }
    }
}

fn validate_hostname(host: &str) -> Result<(), P2pAddressError> {
    if host.is_empty() || host.len() > 253 {
        return Err(P2pAddressError::InvalidHostname);
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(P2pAddressError::InvalidHostname);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(P2pAddressError::InvalidHostname);
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(P2pAddressError::InvalidHostname);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{IpAddr, Ipv4Addr};

    #[test]
    fn symmetric_v1_round_trip() {
        let address = P2pAddress::Symmetric(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            30400,
        ));
        let encoded = encode_v1(&address);
        assert_eq!(decode_v1(&encoded).unwrap(), address);
        assert_eq!(
            decode_versioned(P2P_ADDRESS_VERSION_V1, &encoded).unwrap(),
            address
        );
    }

    #[test]
    fn asymmetric_dns_v1_round_trip() {
        let address = P2pAddress::Asymmetric {
            ingress: P2pIngress::Dns {
                host: "validator-1.example.com".to_owned(),
                port: 30400,
            },
            egress: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30401),
        };
        let encoded = encode_v1(&address);
        assert_eq!(decode_v1(&encoded).unwrap(), address);
    }

    #[test]
    fn rejects_unknown_version_and_trailing_bytes() {
        let address = P2pAddress::Symmetric(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            30400,
        ));
        let mut encoded = encode_v1(&address);
        assert!(matches!(
            decode_versioned(2, &encoded),
            Err(P2pAddressError::UnsupportedVersion(2))
        ));
        encoded.push(0);
        assert!(matches!(
            decode_v1(&encoded),
            Err(P2pAddressError::TrailingBytes)
        ));
    }

    #[test]
    fn rejects_zero_port_and_invalid_dns() {
        assert!(matches!(
            decode_v1(&[ADDR_SYMMETRIC, IP_V4, 127, 0, 0, 1, 0, 0]),
            Err(P2pAddressError::ZeroPort)
        ));

        let address = P2pAddress::Asymmetric {
            ingress: P2pIngress::Dns {
                host: "-bad.example".to_owned(),
                port: 30400,
            },
            egress: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 30401),
        };
        let encoded = encode_v1(&address);
        assert!(matches!(
            decode_v1(&encoded),
            Err(P2pAddressError::InvalidHostname)
        ));
    }
}
