use serde::{Deserialize, Serialize};

/// Declares the operational role a node may hold in the v0 mesh contract.
/// These roles describe policy and intent, not authority over the Rust core.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    MobileNode,
    StablePcNode,
    Relay,
    Observer,
}

/// Tracks the local lifecycle state of a node installation.
/// The values mirror the documentation contract and remain local-first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeLifecycleState {
    New,
    Active,
    Restored,
    Reinstalled,
    Invalid,
}

/// Classifies the kind of mesh event flow being evaluated by policy.
/// This stays intentionally small until runtime integration is defined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshEventKind {
    LiveIngress,
    SyncItem,
    RelayPullReplay,
    LocalReplay,
}

/// Describes the local outcome of applying the mesh acceptance contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshAcceptance {
    Accepted,
    Duplicate,
    RejectedInvalid,
    RejectedLoop,
}

/// Declares the conservative ordering mode used by a node or relay.
/// v0 stays intentionally simple and does not claim global causal ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderingMode {
    TimestampAscLocalTieBreak,
    TimestampAscRelayRowTieBreak,
}

/// Minimal sync cursor used to resume pull or replay from a conservative timestamp boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncCursor {
    pub since_ts_ms: u64,
}

impl SyncCursor {
    pub const fn new(since_ts_ms: u64) -> Self {
        Self { since_ts_ms }
    }
}

/// Lightweight reference to an event that has already been accepted locally.
/// This is a reference shape only; it does not replace the current message or relay formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedEventRef {
    pub event_hash: String,
    pub sender_id: String,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
    pub kind: MeshEventKind,
}
