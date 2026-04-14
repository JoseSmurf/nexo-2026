use crate::mesh::types::{NodeLifecycleState, NodeRole};

/// Narrow error surface for early mesh contract validation.
/// These errors are about contract violations, not transport or database failures.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshContractError {
    InvalidLifecycleTransition {
        from: NodeLifecycleState,
        to: NodeLifecycleState,
    },
    RoleNotPermittedAsRelay(NodeRole),
    InvalidSyncCursor {
        since_ts_ms: u64,
    },
    InvalidAcceptedEventHash {
        event_hash: String,
    },
}
