use crate::endpoint::{EndpointAddress, MAX_ADDRESSES};
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Write},
    net::{IpAddr, SocketAddr},
    os::unix::net::UnixStream,
    path::Path,
    str::FromStr,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarInfo {
    pub node_id: [u8; 32],
    pub addresses: Vec<EndpointAddress>,
}

#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("Heartwood control command failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Heartwood control command exceeded its deadline")]
    Deadline,
    #[error("Heartwood control response is malformed: {0}")]
    Malformed(String),
    #[error("Heartwood NodeId is invalid")]
    NodeId,
    #[error("Heartwood externalAddresses must contain 1..={MAX_ADDRESSES} unique addresses")]
    Addresses,
}

pub async fn query_sidecar(
    socket: impl AsRef<Path>,
    deadline: Duration,
) -> Result<SidecarInfo, SidecarError> {
    let socket = socket.as_ref().to_path_buf();
    let task = tokio::task::spawn_blocking(move || query_sidecar_blocking(&socket, deadline));
    tokio::time::timeout(deadline, task)
        .await
        .map_err(|_| SidecarError::Deadline)?
        .map_err(|error| SidecarError::Malformed(error.to_string()))?
}

fn query_sidecar_blocking(socket: &Path, deadline: Duration) -> Result<SidecarInfo, SidecarError> {
    let deadline = Instant::now()
        .checked_add(deadline)
        .ok_or(SidecarError::Deadline)?;
    let node_id = command(socket, "nodeId", deadline)?;
    let config = command(socket, "config", deadline)?;
    let encoded = node_id.as_str().ok_or(SidecarError::NodeId)?;
    let (_, bytes) = multibase::decode(encoded).map_err(|_| SidecarError::NodeId)?;
    let node_id: [u8; 32] = bytes
        .strip_prefix(&[0xed, 0x01])
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(SidecarError::NodeId)?;
    let advertised = config
        .get("externalAddresses")
        .and_then(Value::as_array)
        .ok_or_else(|| SidecarError::Malformed("missing externalAddresses".to_owned()))?;
    if advertised.is_empty() || advertised.len() > MAX_ADDRESSES {
        return Err(SidecarError::Addresses);
    }
    let mut addresses = advertised
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| SidecarError::Malformed("non-string external address".to_owned()))
                .and_then(parse_address)
        })
        .collect::<Result<Vec<_>, _>>()?;
    addresses.sort();
    if addresses.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(SidecarError::Addresses);
    }
    Ok(SidecarInfo { node_id, addresses })
}

fn command(socket: &Path, command: &str, deadline: Instant) -> Result<Value, SidecarError> {
    let mut stream = UnixStream::connect(socket)?;
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(SidecarError::Deadline)?;
    stream.set_read_timeout(Some(remaining))?;
    stream.set_write_timeout(Some(remaining))?;
    serde_json::to_writer(&mut stream, &serde_json::json!({ "command": command }))
        .map_err(|error| SidecarError::Malformed(error.to_string()))?;
    stream.write_all(b"\n")?;
    let mut response = String::new();
    BufReader::new(stream).read_line(&mut response)?;
    serde_json::from_str(&response).map_err(|error| SidecarError::Malformed(error.to_string()))
}

fn parse_address(value: &str) -> Result<EndpointAddress, SidecarError> {
    if let Ok(socket) = SocketAddr::from_str(value) {
        return match socket.ip() {
            IpAddr::V4(ip) => EndpointAddress::ipv4(ip.octets(), socket.port()),
            IpAddr::V6(ip) => EndpointAddress::ipv6(ip.octets(), socket.port()),
        }
        .map_err(|error| SidecarError::Malformed(error.to_string()));
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| SidecarError::Malformed(format!("invalid external address {value}")))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| SidecarError::Malformed(format!("invalid external address {value}")))?;
    EndpointAddress::dns(host, port).map_err(|error| SidecarError::Malformed(error.to_string()))
}
