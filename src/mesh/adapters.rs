use crate::message::{event_hash, CanonicalMessage};

#[cfg(feature = "network")]
use super::policy::validate_sync_cursor;
use super::policy::{DEFAULT_NODE_ORDERING, DEFAULT_RELAY_ORDERING};
#[cfg(feature = "network")]
use super::types::MeshAcceptance;
#[cfg(feature = "network")]
use super::types::SyncCursor;
use super::types::{AcceptedEventRef, MeshEventKind, OrderingMode};

#[cfg(feature = "network")]
use crate::offline_store::{StoreInsertStatus, StoredMessage};

/// Returns the conservative ordering mode for accepted local node history in v0.
#[allow(dead_code)]
pub(crate) const fn local_node_ordering_mode() -> OrderingMode {
    DEFAULT_NODE_ORDERING
}

/// Returns the conservative ordering mode for relay pull results in v0.
#[allow(dead_code)]
pub(crate) const fn relay_pull_ordering_mode() -> OrderingMode {
    DEFAULT_RELAY_ORDERING
}

/// Builds a lightweight accepted-event reference from an already validated canonical message.
#[allow(dead_code)]
pub(crate) fn accepted_event_ref_from_canonical_message(
    message: &CanonicalMessage,
    kind: MeshEventKind,
) -> AcceptedEventRef {
    AcceptedEventRef {
        event_hash: event_hash(message),
        sender_id: message.sender_id.clone(),
        timestamp_utc_ms: message.timestamp_utc_ms,
        nonce: message.nonce,
        kind,
    }
}

/// Projects a locally accepted canonical message into the conservative mesh v0 shape.
#[allow(dead_code)]
pub(crate) fn project_live_ingress_message(
    message: &CanonicalMessage,
) -> (OrderingMode, AcceptedEventRef) {
    (
        local_node_ordering_mode(),
        accepted_event_ref_from_canonical_message(message, MeshEventKind::LiveIngress),
    )
}

/// Maps the current persistent store insertion status into the minimal mesh acceptance vocabulary.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) const fn mesh_acceptance_from_store_insert_status(
    status: StoreInsertStatus,
) -> MeshAcceptance {
    match status {
        StoreInsertStatus::Inserted => MeshAcceptance::Accepted,
        StoreInsertStatus::Duplicate => MeshAcceptance::Duplicate,
    }
}

/// Builds a lightweight accepted-event reference from an already stored local message.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) fn accepted_event_ref_from_stored_message(
    message: &StoredMessage,
    kind: MeshEventKind,
) -> AcceptedEventRef {
    AcceptedEventRef {
        event_hash: message.event_hash.clone(),
        sender_id: message.sender_id.clone(),
        timestamp_utc_ms: message.timestamp_utc_ms,
        nonce: message.nonce,
        kind,
    }
}

/// Projects a stored sync item into the conservative mesh v0 shape after cursor validation.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) fn project_stored_message_for_sync(
    message: &StoredMessage,
    since_ts_ms: u64,
) -> Option<(OrderingMode, AcceptedEventRef)> {
    validate_sync_cursor(SyncCursor::new(since_ts_ms)).ok()?;
    Some((
        relay_pull_ordering_mode(),
        accepted_event_ref_from_stored_message(message, MeshEventKind::SyncItem),
    ))
}

/// Projects an already materialized slice of accepted local messages into the conservative mesh
/// v0 history shape. This helper is read-only: it preserves caller order, applies only the
/// documented timestamp boundary, and does not mutate store state, dedup state, or sync state.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) fn project_local_accepted_history(
    messages: &[StoredMessage],
    since_ts_ms: u64,
) -> Option<(OrderingMode, Vec<AcceptedEventRef>)> {
    validate_sync_cursor(SyncCursor::new(since_ts_ms)).ok()?;
    Some((
        local_node_ordering_mode(),
        messages
            .iter()
            .filter(|message| message.timestamp_utc_ms >= since_ts_ms)
            .map(|message| {
                accepted_event_ref_from_stored_message(message, MeshEventKind::LocalReplay)
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_adapter_matches_contract_defaults() {
        let message = CanonicalMessage::new_with_nonce("node_a", 1_736_986_900_000, 7, b"hello")
            .expect("msg");

        let (ordering, accepted) = project_live_ingress_message(&message);

        assert_eq!(accepted.event_hash, event_hash(&message));
        assert_eq!(accepted.sender_id, "node_a");
        assert_eq!(accepted.timestamp_utc_ms, 1_736_986_900_000);
        assert_eq!(accepted.nonce, 7);
        assert_eq!(accepted.kind, MeshEventKind::LiveIngress);
        assert_eq!(ordering, DEFAULT_NODE_ORDERING);
        assert_eq!(relay_pull_ordering_mode(), DEFAULT_RELAY_ORDERING);
    }

    #[cfg(feature = "network")]
    #[test]
    fn network_adapters_preserve_existing_runtime_shapes() {
        let message = StoredMessage {
            event_hash: "ehash".to_string(),
            sender_id: "node_b".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 42,
            nonce: 9,
            content: b"payload".to_vec(),
        };

        let (ordering, accepted) =
            project_stored_message_for_sync(&message, 0).expect("valid sync projection");

        assert_eq!(accepted.event_hash, "ehash");
        assert_eq!(accepted.sender_id, "node_b");
        assert_eq!(accepted.timestamp_utc_ms, 42);
        assert_eq!(accepted.nonce, 9);
        assert_eq!(accepted.kind, MeshEventKind::SyncItem);
        assert_eq!(ordering, DEFAULT_RELAY_ORDERING);
        assert_eq!(
            mesh_acceptance_from_store_insert_status(StoreInsertStatus::Inserted),
            MeshAcceptance::Accepted
        );
        assert_eq!(
            mesh_acceptance_from_store_insert_status(StoreInsertStatus::Duplicate),
            MeshAcceptance::Duplicate
        );
        assert!(project_stored_message_for_sync(&message, u64::MAX).is_none());
    }

    #[cfg(feature = "network")]
    #[test]
    fn local_accepted_history_projection_is_stable_and_read_only() {
        let messages = vec![
            StoredMessage {
                event_hash: "ehash-2".to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
            StoredMessage {
                event_hash: "ehash-3".to_string(),
                sender_id: "node_c".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 30,
                nonce: 3,
                content: b"three".to_vec(),
            },
        ];
        let original = messages.clone();

        let (ordering, projected) =
            project_local_accepted_history(&messages, 20).expect("valid local projection");

        assert_eq!(ordering, DEFAULT_NODE_ORDERING);
        assert_eq!(projected.len(), 2);
        assert_eq!(projected[0].event_hash, "ehash-2");
        assert_eq!(projected[0].sender_id, "node_b");
        assert_eq!(projected[0].timestamp_utc_ms, 20);
        assert_eq!(projected[0].nonce, 2);
        assert_eq!(projected[0].kind, MeshEventKind::LocalReplay);
        assert_eq!(projected[1].event_hash, "ehash-3");
        assert_eq!(projected[1].sender_id, "node_c");
        assert_eq!(projected[1].timestamp_utc_ms, 30);
        assert_eq!(projected[1].nonce, 3);
        assert_eq!(projected[1].kind, MeshEventKind::LocalReplay);
        assert_eq!(messages, original);
        assert!(project_local_accepted_history(&messages, u64::MAX).is_none());
    }

    #[cfg(feature = "network")]
    #[test]
    fn local_accepted_history_projection_applies_timestamp_boundary_only() {
        let messages = vec![
            StoredMessage {
                event_hash: "ehash-1".to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "ehash-2".to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
        ];

        let (_, projected) =
            project_local_accepted_history(&messages, 15).expect("valid local projection");

        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].event_hash, "ehash-2");
        assert_eq!(projected[0].sender_id, "node_b");
        assert_eq!(projected[0].timestamp_utc_ms, 20);
        assert_eq!(projected[0].nonce, 2);
        assert_eq!(projected[0].kind, MeshEventKind::LocalReplay);
    }
}
