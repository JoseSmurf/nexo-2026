use crate::mesh::errors::MeshContractError;
use crate::mesh::types::{NodeLifecycleState, NodeRole, OrderingMode, SyncCursor};

/// Conservative v0 ordering contract for accepted local history.
pub const DEFAULT_NODE_ORDERING: OrderingMode = OrderingMode::TimestampAscLocalTieBreak;

/// Conservative v0 ordering contract for relay pull results.
pub const DEFAULT_RELAY_ORDERING: OrderingMode = OrderingMode::TimestampAscRelayRowTieBreak;

/// `u64::MAX` is reserved as an invalid cursor sentinel in v0.
/// A valid cursor must be either `0` for bootstrap or a concrete observed timestamp boundary.
pub const INVALID_SYNC_CURSOR_TS_MS: u64 = u64::MAX;

/// Returns whether a lifecycle transition is valid under the current documentation contract.
pub fn is_valid_lifecycle_transition(from: NodeLifecycleState, to: NodeLifecycleState) -> bool {
    match (from, to) {
        (NodeLifecycleState::New, NodeLifecycleState::Active)
        | (NodeLifecycleState::Active, NodeLifecycleState::Restored)
        | (NodeLifecycleState::Restored, NodeLifecycleState::Active)
        | (NodeLifecycleState::Active, NodeLifecycleState::Invalid)
        | (NodeLifecycleState::Restored, NodeLifecycleState::Invalid)
        | (NodeLifecycleState::Reinstalled, NodeLifecycleState::New)
        | (NodeLifecycleState::Invalid, NodeLifecycleState::New) => true,
        _ if from == to => true,
        _ => false,
    }
}

/// Validates a lifecycle transition and returns a precise contract error when it is not allowed.
pub fn validate_lifecycle_transition(
    from: NodeLifecycleState,
    to: NodeLifecycleState,
) -> Result<(), MeshContractError> {
    if is_valid_lifecycle_transition(from, to) {
        Ok(())
    } else {
        Err(MeshContractError::InvalidLifecycleTransition { from, to })
    }
}

/// Returns whether a node role may behave as a passive relay in the v0 contract.
pub const fn role_can_act_as_relay(role: NodeRole) -> bool {
    matches!(role, NodeRole::StablePcNode | NodeRole::Relay)
}

/// Validates passive relay eligibility without implying semantic authority.
pub fn validate_relay_role(role: NodeRole) -> Result<(), MeshContractError> {
    if role_can_act_as_relay(role) {
        Ok(())
    } else {
        Err(MeshContractError::RoleNotPermittedAsRelay(role))
    }
}

/// v0 cursors are timestamp based and reserve `u64::MAX` as an invalid sentinel.
pub const fn is_valid_sync_cursor(cursor: SyncCursor) -> bool {
    cursor.since_ts_ms != INVALID_SYNC_CURSOR_TS_MS
}

/// Validates the current v0 sync cursor shape using the smallest concrete rule already assumed by the contract.
pub fn validate_sync_cursor(cursor: SyncCursor) -> Result<(), MeshContractError> {
    if is_valid_sync_cursor(cursor) {
        Ok(())
    } else {
        Err(MeshContractError::InvalidSyncCursor {
            since_ts_ms: cursor.since_ts_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_allows_documented_transitions() {
        assert!(is_valid_lifecycle_transition(
            NodeLifecycleState::New,
            NodeLifecycleState::Active
        ));
        assert!(is_valid_lifecycle_transition(
            NodeLifecycleState::Active,
            NodeLifecycleState::Restored
        ));
        assert!(is_valid_lifecycle_transition(
            NodeLifecycleState::Restored,
            NodeLifecycleState::Active
        ));
        assert!(is_valid_lifecycle_transition(
            NodeLifecycleState::Active,
            NodeLifecycleState::Invalid
        ));
        assert!(is_valid_lifecycle_transition(
            NodeLifecycleState::Reinstalled,
            NodeLifecycleState::New
        ));
    }

    #[test]
    fn lifecycle_rejects_invalid_shortcuts() {
        assert_eq!(
            validate_lifecycle_transition(
                NodeLifecycleState::Reinstalled,
                NodeLifecycleState::Active
            ),
            Err(MeshContractError::InvalidLifecycleTransition {
                from: NodeLifecycleState::Reinstalled,
                to: NodeLifecycleState::Active,
            })
        );
        assert_eq!(
            validate_lifecycle_transition(NodeLifecycleState::New, NodeLifecycleState::Restored),
            Err(MeshContractError::InvalidLifecycleTransition {
                from: NodeLifecycleState::New,
                to: NodeLifecycleState::Restored,
            })
        );
    }

    #[test]
    fn relay_role_is_restricted_to_passive_roles() {
        assert!(role_can_act_as_relay(NodeRole::StablePcNode));
        assert!(role_can_act_as_relay(NodeRole::Relay));
        assert_eq!(
            validate_relay_role(NodeRole::MobileNode),
            Err(MeshContractError::RoleNotPermittedAsRelay(
                NodeRole::MobileNode
            ))
        );
        assert_eq!(
            validate_relay_role(NodeRole::Observer),
            Err(MeshContractError::RoleNotPermittedAsRelay(
                NodeRole::Observer
            ))
        );
    }

    #[test]
    fn default_ordering_modes_remain_conservative() {
        assert_eq!(
            DEFAULT_NODE_ORDERING,
            OrderingMode::TimestampAscLocalTieBreak
        );
        assert_eq!(
            DEFAULT_RELAY_ORDERING,
            OrderingMode::TimestampAscRelayRowTieBreak
        );
    }

    #[test]
    fn timestamp_cursor_is_accepted_as_v0_shape() {
        assert!(is_valid_sync_cursor(SyncCursor::new(0)));
        assert!(is_valid_sync_cursor(SyncCursor::new(1_736_986_900_000)));
        assert_eq!(validate_sync_cursor(SyncCursor::new(42)), Ok(()));
        assert!(!is_valid_sync_cursor(SyncCursor::new(
            INVALID_SYNC_CURSOR_TS_MS
        )));
        assert_eq!(
            validate_sync_cursor(SyncCursor::new(INVALID_SYNC_CURSOR_TS_MS)),
            Err(MeshContractError::InvalidSyncCursor {
                since_ts_ms: INVALID_SYNC_CURSOR_TS_MS,
            })
        );
    }
}
