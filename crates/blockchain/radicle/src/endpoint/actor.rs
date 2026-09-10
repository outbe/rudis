use super::{
    authority::{AnchorSnapshot, PeerId},
    pending::{
        EndpointProtocol, ProtocolError, ProtocolStats, ReceiveOutcome, RequestIdSource,
        ResolvedResponse,
    },
    wire::{EndpointFrame, SignedEndpointResponse},
    ACTOR_MAILBOX_CAPACITY, HANDLE_DEADLINE,
};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug)]
pub struct EndpointActor<S> {
    protocol: EndpointProtocol<S>,
    receiver: mpsc::Receiver<Command>,
}

#[derive(Clone, Debug)]
pub struct EndpointHandle {
    sender: mpsc::Sender<Command>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HandleError {
    #[error("endpoint actor mailbox is full")]
    MailboxFull,
    #[error("endpoint actor is closed")]
    Closed,
    #[error("endpoint actor response deadline exceeded")]
    Deadline,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[derive(Debug)]
enum Command {
    Request {
        peer: PeerId,
        now_ms: u64,
        response: oneshot::Sender<Result<Vec<u8>, ProtocolError>>,
    },
    Response {
        peer: PeerId,
        message: Box<SignedEndpointResponse>,
        latest_height: u64,
        snapshot: Option<AnchorSnapshot>,
        now_ms: u64,
        response: oneshot::Sender<Result<ReceiveOutcome, ProtocolError>>,
    },
    SendFailed {
        peer: PeerId,
        request_id: [u8; 32],
        response: oneshot::Sender<()>,
    },
    Resolve {
        snapshot: AnchorSnapshot,
        latest_height: u64,
        now_ms: u64,
        response: oneshot::Sender<Vec<ResolvedResponse>>,
    },
    Stats {
        response: oneshot::Sender<ProtocolStats>,
    },
    Shutdown {
        response: oneshot::Sender<()>,
    },
}

impl<S: RequestIdSource> EndpointActor<S> {
    pub fn new(protocol: EndpointProtocol<S>) -> (Self, EndpointHandle) {
        let (sender, receiver) = mpsc::channel(ACTOR_MAILBOX_CAPACITY);
        (Self { protocol, receiver }, EndpointHandle { sender })
    }

    pub async fn run(mut self) {
        while let Some(command) = self.receiver.recv().await {
            match command {
                Command::Request {
                    peer,
                    now_ms,
                    response,
                } => {
                    let result = self
                        .protocol
                        .request(peer, now_ms)
                        .map(|request| EndpointFrame::Request(request).encode());
                    let _ = response.send(result);
                }
                Command::Response {
                    peer,
                    message,
                    latest_height,
                    snapshot,
                    now_ms,
                    response,
                } => {
                    let result = self.protocol.receive(
                        peer,
                        *message,
                        latest_height,
                        snapshot.as_ref(),
                        now_ms,
                    );
                    let _ = response.send(result);
                }
                Command::SendFailed {
                    peer,
                    request_id,
                    response,
                } => {
                    self.protocol.send_failed(peer, request_id);
                    let _ = response.send(());
                }
                Command::Resolve {
                    snapshot,
                    latest_height,
                    now_ms,
                    response,
                } => {
                    let _ = response.send(self.protocol.resolve(&snapshot, latest_height, now_ms));
                }
                Command::Stats { response } => {
                    let _ = response.send(self.protocol.stats());
                }
                Command::Shutdown { response } => {
                    let _ = response.send(());
                    break;
                }
            }
        }
    }
}

impl EndpointHandle {
    pub async fn request(&self, peer: PeerId, now_ms: u64) -> Result<Vec<u8>, HandleError> {
        let (response, receiver) = oneshot::channel();
        self.enqueue(Command::Request {
            peer,
            now_ms,
            response,
        })?;
        receive_deadline(receiver).await?.map_err(HandleError::from)
    }

    pub async fn response(
        &self,
        peer: PeerId,
        message: SignedEndpointResponse,
        latest_height: u64,
        snapshot: Option<AnchorSnapshot>,
        now_ms: u64,
    ) -> Result<ReceiveOutcome, HandleError> {
        let (response, receiver) = oneshot::channel();
        self.enqueue(Command::Response {
            peer,
            message: Box::new(message),
            latest_height,
            snapshot,
            now_ms,
            response,
        })?;
        receive_deadline(receiver).await?.map_err(HandleError::from)
    }

    pub async fn send_failed(&self, peer: PeerId, request_id: [u8; 32]) -> Result<(), HandleError> {
        let (response, receiver) = oneshot::channel();
        self.enqueue(Command::SendFailed {
            peer,
            request_id,
            response,
        })?;
        receive_deadline(receiver).await
    }

    pub async fn resolve(
        &self,
        snapshot: AnchorSnapshot,
        latest_height: u64,
        now_ms: u64,
    ) -> Result<Vec<ResolvedResponse>, HandleError> {
        let (response, receiver) = oneshot::channel();
        self.enqueue(Command::Resolve {
            snapshot,
            latest_height,
            now_ms,
            response,
        })?;
        receive_deadline(receiver).await
    }

    pub async fn stats(&self) -> Result<ProtocolStats, HandleError> {
        let (response, receiver) = oneshot::channel();
        self.enqueue(Command::Stats { response })?;
        receive_deadline(receiver).await
    }

    pub async fn shutdown(&self) -> Result<(), HandleError> {
        let (response, receiver) = oneshot::channel();
        self.enqueue(Command::Shutdown { response })?;
        receive_deadline(receiver).await
    }

    fn enqueue(&self, command: Command) -> Result<(), HandleError> {
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => HandleError::MailboxFull,
            mpsc::error::TrySendError::Closed(_) => HandleError::Closed,
        })
    }
}

async fn receive_deadline<T>(receiver: oneshot::Receiver<T>) -> Result<T, HandleError> {
    match tokio::time::timeout(HANDLE_DEADLINE, receiver).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(HandleError::Closed),
        Err(_) => Err(HandleError::Deadline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{ChainIdentity, OsRequestIds};
    use alloy_primitives::B256;

    #[test]
    fn mailbox_bound() {
        let protocol = EndpointProtocol::new(
            ChainIdentity {
                chain_id: 1,
                genesis_hash: B256::ZERO,
            },
            OsRequestIds,
        );
        let (_actor, handle) = EndpointActor::new(protocol);
        let mut receivers = Vec::with_capacity(ACTOR_MAILBOX_CAPACITY);
        for _ in 0..ACTOR_MAILBOX_CAPACITY {
            let (response, receiver) = oneshot::channel();
            handle.enqueue(Command::Stats { response }).unwrap();
            receivers.push(receiver);
        }
        let (response, _receiver) = oneshot::channel();
        assert_eq!(
            handle.enqueue(Command::Stats { response }),
            Err(HandleError::MailboxFull)
        );
        drop(receivers);
    }

    #[tokio::test(start_paused = true)]
    async fn handle_deadline() {
        let (_sender, receiver) = oneshot::channel::<()>();
        let waiting = tokio::spawn(receive_deadline(receiver));
        tokio::task::yield_now().await;
        tokio::time::advance(HANDLE_DEADLINE).await;
        assert_eq!(waiting.await.unwrap(), Err(HandleError::Deadline));
    }
}
