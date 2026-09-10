use super::types::{
    BoxFuture, ControlSession, DisconnectDisposition, HeartwoodControl, ManagerError,
    RepositoryStatus, SessionDirection,
};
use crate::endpoint::EndpointAddress;
use outbe_radicleregistry::RepoId;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    io::{BufRead, BufReader, Write},
    net::SocketAddr,
    os::unix::net::UnixStream,
    path::PathBuf,
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct NativeHeartwoodControl {
    socket: PathBuf,
    deadline: Duration,
}

impl NativeHeartwoodControl {
    #[must_use]
    pub fn new(socket: PathBuf, deadline: Duration) -> Self {
        Self { socket, deadline }
    }

    async fn command<C, R>(&self, command: C) -> Result<R, ManagerError>
    where
        C: Serialize + Send + 'static,
        R: DeserializeOwned + Send + 'static,
    {
        let socket = self.socket.clone();
        let deadline = self.deadline;
        tokio::time::timeout(
            deadline,
            blocking(move || native_call(&socket, deadline, &command)),
        )
        .await
        .map_err(|_| ManagerError::Control("Heartwood control deadline exceeded".into()))?
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "command")]
enum NativeCommand {
    NodeId,
    Sessions,
    Connect {
        addr: String,
        opts: NativeConnectOptions,
    },
    DisconnectBounded {
        nid: String,
        expected_address: String,
        timeout: Duration,
    },
    Seed {
        rid: String,
        scope: &'static str,
    },
}

#[derive(Serialize)]
struct NativeConnectOptions {
    persistent: bool,
    timeout: Duration,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeSession {
    nid: String,
    link: NativeLink,
    addr: String,
    state: NativeState,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum NativeLink {
    Outbound,
    Inbound,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum NativeState {
    Initial,
    Attempted,
    Connected {},
    Disconnected {},
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "status")]
enum NativeConnectResult {
    Connected,
    Disconnected { reason: String },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum NativeDisconnectDisposition {
    Disconnected,
    AlreadyAbsent,
    NotConnected,
    Inbound,
    AddressChanged,
}

#[derive(Deserialize)]
struct NativeSuccess {
    #[allow(dead_code)]
    #[serde(default)]
    updated: bool,
}

impl HeartwoodControl for NativeHeartwoodControl {
    fn node_id(&self) -> BoxFuture<'_, Result<[u8; 32], ManagerError>> {
        Box::pin(async move {
            let encoded: String = self.command(NativeCommand::NodeId).await?;
            decode_node_id(&encoded)
        })
    }

    fn sessions(&self) -> BoxFuture<'_, Result<Vec<ControlSession>, ManagerError>> {
        Box::pin(async move {
            let sessions: Vec<NativeSession> = self.command(NativeCommand::Sessions).await?;
            sessions
                .into_iter()
                .map(|session| {
                    Ok(ControlSession {
                        node_id: decode_node_id(&session.nid)?,
                        address: parse_endpoint(&session.addr)?,
                        direction: match session.link {
                            NativeLink::Inbound => SessionDirection::Inbound,
                            NativeLink::Outbound => SessionDirection::Outbound,
                        },
                        connected: matches!(session.state, NativeState::Connected { .. }),
                    })
                })
                .collect()
        })
    }

    fn connect<'a>(
        &'a self,
        node_id: [u8; 32],
        addresses: &'a [EndpointAddress],
    ) -> BoxFuture<'a, Result<EndpointAddress, ManagerError>> {
        Box::pin(async move {
            let nid = encode_node_id(node_id);
            let mut last_error = None;
            for endpoint in addresses {
                let result: NativeConnectResult = self
                    .command(NativeCommand::Connect {
                        addr: format!("{nid}@{}", format_endpoint(endpoint)?),
                        opts: NativeConnectOptions {
                            persistent: false,
                            timeout: self.deadline,
                        },
                    })
                    .await?;
                match result {
                    NativeConnectResult::Connected => return Ok(endpoint.clone()),
                    NativeConnectResult::Disconnected { reason } => last_error = Some(reason),
                }
            }
            Err(ManagerError::Control(
                last_error.unwrap_or_else(|| "peer has no signed endpoint".into()),
            ))
        })
    }

    fn disconnect<'a>(
        &'a self,
        node_id: [u8; 32],
        expected: &'a EndpointAddress,
    ) -> BoxFuture<'a, Result<DisconnectDisposition, ManagerError>> {
        Box::pin(async move {
            let disposition: NativeDisconnectDisposition = self
                .command(NativeCommand::DisconnectBounded {
                    nid: encode_node_id(node_id),
                    expected_address: format_endpoint(expected)?,
                    timeout: self.deadline,
                })
                .await?;
            Ok(match disposition {
                NativeDisconnectDisposition::Disconnected => DisconnectDisposition::Disconnected,
                NativeDisconnectDisposition::AlreadyAbsent => DisconnectDisposition::AlreadyAbsent,
                NativeDisconnectDisposition::NotConnected => DisconnectDisposition::NotConnected,
                NativeDisconnectDisposition::Inbound => DisconnectDisposition::Inbound,
                NativeDisconnectDisposition::AddressChanged => {
                    DisconnectDisposition::AddressChanged
                }
            })
        })
    }

    fn seed(&self, repo: RepoId) -> BoxFuture<'_, Result<(), ManagerError>> {
        Box::pin(async move {
            let _: NativeSuccess = self
                .command(NativeCommand::Seed {
                    rid: encode_repo_id(repo),
                    scope: "all",
                })
                .await?;
            Ok(())
        })
    }
}

fn native_call<C: Serialize, R: DeserializeOwned>(
    socket: &std::path::Path,
    deadline: Duration,
    command: &C,
) -> Result<R, ManagerError> {
    let mut stream = UnixStream::connect(socket).map_err(control_error)?;
    stream
        .set_read_timeout(Some(deadline))
        .map_err(control_error)?;
    stream
        .set_write_timeout(Some(deadline))
        .map_err(control_error)?;
    serde_json::to_writer(&mut stream, command).map_err(control_error)?;
    stream.write_all(b"\n").map_err(control_error)?;
    stream.flush().map_err(control_error)?;
    let mut response = String::new();
    BufReader::new(stream)
        .read_line(&mut response)
        .map_err(control_error)?;
    if response.is_empty() {
        return Err(ManagerError::Control("empty control response".into()));
    }
    let value: serde_json::Value = serde_json::from_str(&response).map_err(control_error)?;
    if let Some(reason) = value.get("error").and_then(serde_json::Value::as_str) {
        return Err(ManagerError::Control(reason.into()));
    }
    serde_json::from_value(value).map_err(control_error)
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ManagerError> + Send + 'static,
) -> Result<T, ManagerError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| ManagerError::Control(error.to_string()))?
}

fn encode_node_id(node_id: [u8; 32]) -> String {
    let mut bytes = [0; 34];
    bytes[..2].copy_from_slice(&[0xed, 0x01]);
    bytes[2..].copy_from_slice(&node_id);
    multibase::encode(multibase::Base::Base58Btc, bytes)
}

fn decode_node_id(encoded: &str) -> Result<[u8; 32], ManagerError> {
    let (base, bytes) = multibase::decode(encoded).map_err(control_error)?;
    if base != multibase::Base::Base58Btc || bytes.len() != 34 || bytes[..2] != [0xed, 0x01] {
        return Err(ManagerError::Control("invalid Heartwood NodeId".into()));
    }
    bytes[2..]
        .try_into()
        .map_err(|_| ManagerError::Control("invalid Heartwood NodeId".into()))
}

fn encode_repo_id(repo: RepoId) -> String {
    format!(
        "rad:{}",
        multibase::encode(multibase::Base::Base58Btc, repo.as_slice())
    )
}

fn parse_endpoint(encoded: &str) -> Result<EndpointAddress, ManagerError> {
    if let Ok(socket) = encoded.parse::<SocketAddr>() {
        return match socket.ip() {
            std::net::IpAddr::V4(ip) => EndpointAddress::ipv4(ip.octets(), socket.port()),
            std::net::IpAddr::V6(ip) => EndpointAddress::ipv6(ip.octets(), socket.port()),
        }
        .map_err(control_error);
    }
    let (host, port) = encoded
        .rsplit_once(':')
        .ok_or_else(|| ManagerError::Control("invalid Heartwood address".into()))?;
    let port = port.parse::<u16>().map_err(control_error)?;
    EndpointAddress::dns(host, port).map_err(control_error)
}

fn format_endpoint(endpoint: &EndpointAddress) -> Result<String, ManagerError> {
    let encoded = endpoint.encode();
    match encoded.as_slice() {
        [0, a, b, c, d, port_hi, port_lo] => Ok(format!(
            "{}.{}.{}.{}:{}",
            a,
            b,
            c,
            d,
            u16::from_be_bytes([*port_hi, *port_lo])
        )),
        [1, octets @ .., port_hi, port_lo] if octets.len() == 16 => {
            let octets: [u8; 16] = octets
                .try_into()
                .map_err(|_| ManagerError::Control("invalid IPv6 endpoint".into()))?;
            Ok(format!(
                "[{}]:{}",
                std::net::Ipv6Addr::from(octets),
                u16::from_be_bytes([*port_hi, *port_lo])
            ))
        }
        [2, length, rest @ ..] if rest.len() == usize::from(*length) + 2 => {
            let host = endpoint
                .host()
                .ok_or_else(|| ManagerError::Control("invalid DNS endpoint".into()))?;
            Ok(format!("{host}:{}", endpoint.port()))
        }
        _ => Err(ManagerError::Control(
            "invalid canonical endpoint encoding".into(),
        )),
    }
}

fn control_error(error: impl std::fmt::Display) -> ManagerError {
    ManagerError::Control(error.to_string())
}

#[derive(Clone, Debug)]
pub struct HttpRepositoryStatus {
    base: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct RepositoryResponse {
    version: u8,
    repo_id: String,
    available: bool,
}

impl HttpRepositoryStatus {
    pub fn new(address: SocketAddr, deadline: Duration) -> Result<Self, ManagerError> {
        if !address.ip().is_loopback() {
            return Err(ManagerError::Status(
                "repository status endpoint must be loopback".into(),
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(deadline)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(status_error)?;
        Ok(Self {
            base: format!("http://{address}"),
            client,
        })
    }
}

impl RepositoryStatus for HttpRepositoryStatus {
    fn available(&self, repo: RepoId) -> BoxFuture<'_, Result<bool, ManagerError>> {
        Box::pin(async move {
            let encoded = hex::encode(repo);
            let response = self
                .client
                .get(format!("{}/v1/repositories/{encoded}", self.base))
                .send()
                .await
                .map_err(status_error)?
                .error_for_status()
                .map_err(status_error)?
                .json::<RepositoryResponse>()
                .await
                .map_err(status_error)?;
            if response.version != 1 || response.repo_id != encoded {
                return Err(ManagerError::Status(
                    "repository status identity mismatch".into(),
                ));
            }
            Ok(response.available)
        })
    }
}

fn status_error(error: impl std::fmt::Display) -> ManagerError {
    ManagerError::Status(error.to_string())
}
