use super::{
    authority::{
        verify_future_response, verify_response, AnchorSnapshot, PeerId, VerificationContext,
        VerifiedEndpoint, VerifyError,
    },
    wire::{EndpointFrame, EndpointRequest, SignedEndpointResponse},
    ChainIdentity, MAX_FUTURE_ANCHOR_DISTANCE, MAX_PENDING_REQUESTS, MAX_UNKNOWN_ANCHORS,
    MAX_UNKNOWN_ANCHOR_BYTES, REQUEST_ID_GENERATION_ATTEMPTS, REQUEST_TIMEOUT_MS,
    UNKNOWN_ANCHOR_TIMEOUT_MS,
};
use rand_core::{OsRng, RngCore};
use std::collections::{HashMap, HashSet};

pub trait RequestIdSource: Send + 'static {
    fn next_id(&mut self) -> Result<[u8; 32], IdError>;
}

#[derive(Debug, Default)]
pub struct OsRequestIds;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    #[error("request id source is unavailable")]
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Verified(VerifiedEndpoint),
    Queued { anchor_number: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedResponse {
    pub peer: PeerId,
    pub result: Result<VerifiedEndpoint, ProtocolError>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProtocolStats {
    pub pending: usize,
    pub queued: usize,
    pub queued_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("peer already has a pending or queued request")]
    AlreadyPending,
    #[error("endpoint protocol capacity is full")]
    Capacity,
    #[error("request id generation failed")]
    IdSource,
    #[error("request id collision attempts are exhausted")]
    RequestIdExhausted,
    #[error("response is unsolicited or replayed")]
    Unsolicited,
    #[error("pending request timed out")]
    TimedOut,
    #[error("response anchor is stale")]
    Stale,
    #[error("response anchor is too far in the future")]
    FutureDistance,
    #[error("exact anchor snapshot is unavailable")]
    AnchorUnavailable,
    #[error(transparent)]
    Verification(#[from] VerifyError),
}

#[derive(Debug)]
pub struct EndpointProtocol<S> {
    chain: ChainIdentity,
    ids: S,
    pending: HashMap<PeerId, PendingRequest>,
    queued: HashMap<PeerId, QueuedResponse>,
    queued_bytes: usize,
}

#[derive(Clone, Debug)]
struct PendingRequest {
    request_id: [u8; 32],
    deadline_ms: u64,
}

#[derive(Clone, Debug)]
struct QueuedResponse {
    response: SignedEndpointResponse,
    deadline_ms: u64,
    bytes: usize,
}

impl RequestIdSource for OsRequestIds {
    fn next_id(&mut self) -> Result<[u8; 32], IdError> {
        let mut id = [0; 32];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| IdError::Unavailable)?;
        Ok(id)
    }
}

impl<S: RequestIdSource> EndpointProtocol<S> {
    pub fn new(chain: ChainIdentity, ids: S) -> Self {
        Self {
            chain,
            ids,
            pending: HashMap::new(),
            queued: HashMap::new(),
            queued_bytes: 0,
        }
    }

    pub fn request(&mut self, peer: PeerId, now_ms: u64) -> Result<EndpointRequest, ProtocolError> {
        self.expire(now_ms);
        if self.pending.contains_key(&peer) || self.queued.contains_key(&peer) {
            return Err(ProtocolError::AlreadyPending);
        }
        if self.pending.len() >= MAX_PENDING_REQUESTS {
            return Err(ProtocolError::Capacity);
        }
        let live_ids = self.live_ids();
        let mut selected = None;
        for _ in 0..REQUEST_ID_GENERATION_ATTEMPTS {
            let id = self.ids.next_id().map_err(|_| ProtocolError::IdSource)?;
            if id != [0; 32] && !live_ids.contains(&id) {
                selected = Some(id);
                break;
            }
        }
        let request_id = selected.ok_or(ProtocolError::RequestIdExhausted)?;
        self.pending.insert(
            peer,
            PendingRequest {
                request_id,
                deadline_ms: now_ms.saturating_add(REQUEST_TIMEOUT_MS),
            },
        );
        EndpointRequest::new(request_id).map_err(|_| ProtocolError::RequestIdExhausted)
    }

    pub fn send_failed(&mut self, peer: PeerId, request_id: [u8; 32]) {
        if self
            .pending
            .get(&peer)
            .is_some_and(|pending| pending.request_id == request_id)
        {
            self.pending.remove(&peer);
        }
    }

    pub fn receive(
        &mut self,
        peer: PeerId,
        response: SignedEndpointResponse,
        latest_height: u64,
        snapshot: Option<&AnchorSnapshot>,
        now_ms: u64,
    ) -> Result<ReceiveOutcome, ProtocolError> {
        self.expire(now_ms);
        let Some(pending) = self.pending.get(&peer) else {
            return Err(ProtocolError::Unsolicited);
        };
        if pending.request_id != response.body().request_id {
            return Err(ProtocolError::Unsolicited);
        }
        if now_ms >= pending.deadline_ms {
            self.pending.remove(&peer);
            return Err(ProtocolError::TimedOut);
        }
        if response.body().anchor_number < latest_height {
            self.pending.remove(&peer);
            return Err(ProtocolError::Stale);
        }
        if response.body().anchor_number > latest_height {
            return self.queue_future(peer, response, latest_height, now_ms);
        }

        self.pending.remove(&peer);
        let snapshot = snapshot.ok_or(ProtocolError::AnchorUnavailable)?;
        let verified = verify_response(
            peer,
            &response,
            snapshot,
            VerificationContext {
                chain: self.chain,
                current_height: latest_height,
            },
        )?;
        Ok(ReceiveOutcome::Verified(verified))
    }

    pub fn resolve(
        &mut self,
        snapshot: &AnchorSnapshot,
        latest_height: u64,
        now_ms: u64,
    ) -> Vec<ResolvedResponse> {
        self.expire(now_ms);
        let peers: Vec<_> = self
            .queued
            .iter()
            .filter_map(|(peer, queued)| {
                let anchor = queued.response.body().anchor_number;
                (anchor < latest_height || (anchor == latest_height && snapshot.number == anchor))
                    .then_some(*peer)
            })
            .collect();
        let mut resolved = Vec::with_capacity(peers.len());
        for peer in peers {
            let Some(queued) = self.remove_queued(peer) else {
                continue;
            };
            let result = if queued.response.body().anchor_number < latest_height {
                Err(ProtocolError::Stale)
            } else {
                verify_response(
                    peer,
                    &queued.response,
                    snapshot,
                    VerificationContext {
                        chain: self.chain,
                        current_height: latest_height,
                    },
                )
                .map_err(ProtocolError::from)
            };
            resolved.push(ResolvedResponse { peer, result });
        }
        resolved
    }

    pub fn expire(&mut self, now_ms: u64) {
        self.pending
            .retain(|_, pending| pending.deadline_ms > now_ms);
        let expired: Vec<_> = self
            .queued
            .iter()
            .filter_map(|(peer, queued)| (queued.deadline_ms <= now_ms).then_some(*peer))
            .collect();
        for peer in expired {
            self.remove_queued(peer);
        }
    }

    pub fn stats(&self) -> ProtocolStats {
        ProtocolStats {
            pending: self.pending.len(),
            queued: self.queued.len(),
            queued_bytes: self.queued_bytes,
        }
    }

    fn queue_future(
        &mut self,
        peer: PeerId,
        response: SignedEndpointResponse,
        latest_height: u64,
        now_ms: u64,
    ) -> Result<ReceiveOutcome, ProtocolError> {
        self.pending.remove(&peer);
        let distance = response.body().anchor_number - latest_height;
        if distance > MAX_FUTURE_ANCHOR_DISTANCE {
            return Err(ProtocolError::FutureDistance);
        }
        verify_future_response(
            peer,
            &response,
            VerificationContext {
                chain: self.chain,
                current_height: latest_height,
            },
        )?;
        let bytes = EndpointFrame::Response(Box::new(response.clone()))
            .encode()
            .len();
        if self.queued.len() >= MAX_UNKNOWN_ANCHORS
            || self.queued.contains_key(&peer)
            || self.queued_bytes.saturating_add(bytes) > MAX_UNKNOWN_ANCHOR_BYTES
        {
            return Err(ProtocolError::Capacity);
        }
        let anchor_number = response.body().anchor_number;
        self.queued.insert(
            peer,
            QueuedResponse {
                response,
                deadline_ms: now_ms.saturating_add(UNKNOWN_ANCHOR_TIMEOUT_MS),
                bytes,
            },
        );
        self.queued_bytes += bytes;
        Ok(ReceiveOutcome::Queued { anchor_number })
    }

    fn live_ids(&self) -> HashSet<[u8; 32]> {
        self.pending
            .values()
            .map(|pending| pending.request_id)
            .chain(
                self.queued
                    .values()
                    .map(|queued| queued.response.body().request_id),
            )
            .collect()
    }

    fn remove_queued(&mut self, peer: PeerId) -> Option<QueuedResponse> {
        let queued = self.queued.remove(&peer)?;
        self.queued_bytes = self.queued_bytes.saturating_sub(queued.bytes);
        Some(queued)
    }
}
