use crate::message::{event_hash, CanonicalMessage};

#[cfg(feature = "network")]
use super::errors::MeshContractError;
#[cfg(feature = "network")]
use super::policy::validate_sync_cursor;
use super::policy::{DEFAULT_NODE_ORDERING, DEFAULT_RELAY_ORDERING};
use super::types::BandwidthDigestComparison;
#[cfg(feature = "network")]
use super::types::MeshAcceptance;
use super::types::OperationalTruthKind;
use super::types::OperationalTruthSurface;
#[cfg(feature = "network")]
use super::types::RecoveryClassification;
#[cfg(feature = "network")]
use super::types::SyncCursor;
use super::types::{
    AcceptedEventRef, AcceptedStateWitness, BandwidthMinimalSyncDigest, MeshEventKind,
    OrderingMode, RecoveryWitness, SyncConvergenceHarnessReport, SyncConvergenceOutcome,
    SyncConvergenceScenario, SyncSliceComparability,
};

#[cfg(feature = "network")]
use crate::offline_store::{OfflineStore, StoreInsertStatus, StoredMessage};

#[cfg(feature = "network")]
const RECOVERY_WITNESS_RELAY_SINCE_KEY: &str = "last_relay_pull_since_ms";

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
) -> Result<(OrderingMode, Vec<AcceptedEventRef>), MeshContractError> {
    validate_sync_cursor(SyncCursor::new(since_ts_ms))?;
    Ok((
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

#[cfg(feature = "network")]
fn witness_hash_field(hasher: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    hasher.update(&(tag.len() as u32).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(data.len() as u32).to_le_bytes());
    hasher.update(data);
}

#[cfg(feature = "network")]
fn ordering_mode_tag(ordering: OrderingMode) -> &'static [u8] {
    match ordering {
        OrderingMode::TimestampAscLocalTieBreak => b"timestamp_asc_local_tiebreak",
        OrderingMode::TimestampAscRelayRowTieBreak => b"timestamp_asc_relay_row_tiebreak",
    }
}

#[cfg(feature = "network")]
fn mesh_event_kind_tag(kind: MeshEventKind) -> u8 {
    match kind {
        MeshEventKind::LiveIngress => 0,
        MeshEventKind::SyncItem => 1,
        MeshEventKind::RelayPullReplay => 2,
        MeshEventKind::LocalReplay => 3,
    }
}

#[cfg(feature = "network")]
fn parse_event_hash_hex(hash: &str) -> Result<[u8; 32], MeshContractError> {
    if hash.len() != 64 {
        return Err(MeshContractError::InvalidAcceptedEventHash {
            event_hash: hash.to_string(),
        });
    }

    let mut out = [0u8; 32];
    for (index, chunk) in hash.as_bytes().chunks_exact(2).enumerate() {
        let raw = std::str::from_utf8(chunk).map_err(|_| {
            MeshContractError::InvalidAcceptedEventHash {
                event_hash: hash.to_string(),
            }
        })?;
        out[index] = u8::from_str_radix(raw, 16).map_err(|_| {
            MeshContractError::InvalidAcceptedEventHash {
                event_hash: hash.to_string(),
            }
        })?;
    }
    Ok(out)
}

#[cfg(feature = "network")]
fn accepted_state_digest(
    ordering: OrderingMode,
    since_ts_ms: u64,
    events: &[AcceptedEventRef],
    event_hashes: &[[u8; 32]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    witness_hash_field(&mut hasher, b"schema", b"mesh_accepted_state_witness_v1");
    witness_hash_field(&mut hasher, b"ordering", ordering_mode_tag(ordering));
    witness_hash_field(&mut hasher, b"since_ts_ms", &since_ts_ms.to_le_bytes());
    witness_hash_field(
        &mut hasher,
        b"event_count",
        &(events.len() as u64).to_le_bytes(),
    );

    for (event, event_hash) in events.iter().zip(event_hashes.iter()) {
        witness_hash_field(&mut hasher, b"event_hash", event_hash);
        witness_hash_field(&mut hasher, b"sender_id", event.sender_id.as_bytes());
        witness_hash_field(
            &mut hasher,
            b"timestamp_utc_ms",
            &event.timestamp_utc_ms.to_le_bytes(),
        );
        witness_hash_field(&mut hasher, b"nonce", &event.nonce.to_le_bytes());
        witness_hash_field(&mut hasher, b"kind", &[mesh_event_kind_tag(event.kind)]);
    }

    *hasher.finalize().as_bytes()
}

#[cfg(feature = "network")]
fn recovery_classification_tag(classification: RecoveryClassification) -> u8 {
    match classification {
        RecoveryClassification::NewNode => 0,
        RecoveryClassification::Intact => 1,
        RecoveryClassification::RestoredValid => 2,
        RecoveryClassification::Ambiguous => 3,
        RecoveryClassification::Invalid => 4,
    }
}

#[cfg(feature = "network")]
fn identity_fingerprint(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    witness_hash_field(&mut hasher, b"schema", b"mesh_identity_fingerprint_v1");
    witness_hash_field(&mut hasher, b"node_identity_pubkey", pubkey);
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "network")]
fn recovery_continuity_digest(
    classification: RecoveryClassification,
    identity_fingerprint: Option<[u8; 32]>,
    relay_since_ts_ms: Option<u64>,
    accepted_state: &AcceptedStateWitness,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    witness_hash_field(&mut hasher, b"schema", b"mesh_recovery_witness_v1");
    witness_hash_field(
        &mut hasher,
        b"classification",
        &[recovery_classification_tag(classification)],
    );
    witness_hash_field(
        &mut hasher,
        b"identity_present",
        &[u8::from(identity_fingerprint.is_some())],
    );
    if let Some(fingerprint) = identity_fingerprint {
        witness_hash_field(&mut hasher, b"identity_fingerprint", &fingerprint);
    }
    witness_hash_field(
        &mut hasher,
        b"relay_since_present",
        &[u8::from(relay_since_ts_ms.is_some())],
    );
    if let Some(relay_since) = relay_since_ts_ms {
        witness_hash_field(
            &mut hasher,
            b"relay_since_ts_ms",
            &relay_since.to_le_bytes(),
        );
    }
    witness_hash_field(
        &mut hasher,
        b"accepted_ordering",
        ordering_mode_tag(accepted_state.ordering),
    );
    witness_hash_field(
        &mut hasher,
        b"accepted_since_ts_ms",
        &accepted_state.since_ts_ms.to_le_bytes(),
    );
    witness_hash_field(
        &mut hasher,
        b"accepted_event_count",
        &accepted_state.event_count.to_le_bytes(),
    );
    witness_hash_field(
        &mut hasher,
        b"accepted_first_present",
        &[u8::from(accepted_state.first_event_hash.is_some())],
    );
    if let Some(first_event_hash) = accepted_state.first_event_hash {
        witness_hash_field(&mut hasher, b"accepted_first_event_hash", &first_event_hash);
    }
    witness_hash_field(
        &mut hasher,
        b"accepted_last_present",
        &[u8::from(accepted_state.last_event_hash.is_some())],
    );
    if let Some(last_event_hash) = accepted_state.last_event_hash {
        witness_hash_field(&mut hasher, b"accepted_last_event_hash", &last_event_hash);
    }
    witness_hash_field(
        &mut hasher,
        b"accepted_state_digest",
        &accepted_state.state_digest,
    );
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "network")]
fn automatic_recovery_classification(
    identity_fingerprint: Option<[u8; 32]>,
    relay_since_ts_ms: Option<u64>,
    accepted_state: &AcceptedStateWitness,
    invalid_identity_state: bool,
    invalid_relay_state: bool,
) -> RecoveryClassification {
    if invalid_identity_state || invalid_relay_state {
        return RecoveryClassification::Invalid;
    }

    let has_minimal_continuity_evidence =
        accepted_state.event_count > 0 || relay_since_ts_ms.is_some();

    if identity_fingerprint.is_some() && has_minimal_continuity_evidence {
        return RecoveryClassification::Intact;
    }

    if identity_fingerprint.is_none() && !has_minimal_continuity_evidence {
        RecoveryClassification::NewNode
    } else {
        RecoveryClassification::Ambiguous
    }
}

/// Builds the smallest deterministic witness for a local accepted-history slice in v0.
/// This helper is read-only and does not mutate runtime, storage, dedup, or sync state.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) fn build_accepted_state_witness(
    messages: &[StoredMessage],
    since_ts_ms: u64,
) -> Result<AcceptedStateWitness, MeshContractError> {
    validate_sync_cursor(SyncCursor::new(since_ts_ms))?;
    let (ordering, projected) = project_local_accepted_history(messages, since_ts_ms)?;
    let event_hashes = projected
        .iter()
        .map(|event| parse_event_hash_hex(&event.event_hash))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(AcceptedStateWitness {
        ordering,
        since_ts_ms,
        event_count: projected.len() as u64,
        first_event_hash: event_hashes.first().copied(),
        last_event_hash: event_hashes.last().copied(),
        state_digest: accepted_state_digest(ordering, since_ts_ms, &projected, &event_hashes),
    })
}

/// Builds a bandwidth-minimal digest for a local accepted-history window.
/// This helper is read-only and is derived from `AcceptedStateWitness` over the selected window.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) fn build_bandwidth_minimal_sync_digest(
    messages: &[StoredMessage],
    since_ts_ms: u64,
    until_ts_ms: u64,
) -> Result<BandwidthMinimalSyncDigest, MeshContractError> {
    validate_sync_cursor(SyncCursor::new(since_ts_ms))?;
    validate_sync_cursor(SyncCursor::new(until_ts_ms))?;
    if until_ts_ms < since_ts_ms {
        return Err(MeshContractError::InvalidSyncWindow {
            since_ts_ms,
            until_ts_ms,
        });
    }

    let windowed = messages
        .iter()
        .filter(|message| message.timestamp_utc_ms <= until_ts_ms)
        .cloned()
        .collect::<Vec<_>>();
    let accepted = build_accepted_state_witness(&windowed, since_ts_ms)?;

    Ok(BandwidthMinimalSyncDigest {
        ordering: accepted.ordering,
        since_ts_ms,
        until_ts_ms,
        event_count: accepted.event_count,
        state_digest: accepted.state_digest,
    })
}

/// Compares two bandwidth-minimal digests.
/// `ExactMatch` is returned only when all summary fields are equal.
/// Matching digests are local equivalence only and do not prove global convergence.
#[allow(dead_code)]
pub(crate) fn compare_bandwidth_minimal_sync_digest(
    left: &BandwidthMinimalSyncDigest,
    right: &BandwidthMinimalSyncDigest,
) -> BandwidthDigestComparison {
    if left.ordering == right.ordering
        && left.since_ts_ms == right.since_ts_ms
        && left.until_ts_ms == right.until_ts_ms
        && left.event_count == right.event_count
        && left.state_digest == right.state_digest
    {
        BandwidthDigestComparison::ExactMatch
    } else {
        BandwidthDigestComparison::Different
    }
}

/// Returns whether two local slices can be interpreted in the same context.
/// Comparability is intentionally minimal: same ordering and same time window.
#[allow(dead_code)]
pub(crate) fn classify_sync_slice_comparability(
    left: &BandwidthMinimalSyncDigest,
    right: &BandwidthMinimalSyncDigest,
) -> SyncSliceComparability {
    if left.ordering == right.ordering
        && left.since_ts_ms == right.since_ts_ms
        && left.until_ts_ms == right.until_ts_ms
    {
        SyncSliceComparability::Comparable
    } else {
        SyncSliceComparability::NotComparable
    }
}

/// Interprets digest comparison only after comparability is established.
#[allow(dead_code)]
pub(crate) fn classify_sync_convergence_diagnostic(
    comparability: SyncSliceComparability,
    comparison: BandwidthDigestComparison,
) -> SyncConvergenceOutcome {
    match comparability {
        SyncSliceComparability::Comparable => match comparison {
            BandwidthDigestComparison::ExactMatch => SyncConvergenceOutcome::EquivalentLocalSlice,
            BandwidthDigestComparison::Different => SyncConvergenceOutcome::DivergentLocalSlice,
        },
        SyncSliceComparability::NotComparable => SyncConvergenceOutcome::NotComparableLocalSlice,
    }
}

fn sync_convergence_diagnostic_reason(outcome: SyncConvergenceOutcome) -> &'static str {
    match outcome {
        SyncConvergenceOutcome::EquivalentLocalSlice => {
            "Read-only comparable local slice equivalence; not global convergence, not runtime sync authority, and not an automatic sync decision."
        }
        SyncConvergenceOutcome::DivergentLocalSlice => {
            "Read-only comparable local slice divergence; not global convergence, not runtime sync authority, not an automatic sync decision, and not a global/network failure verdict."
        }
        SyncConvergenceOutcome::NotComparableLocalSlice => {
            "Read-only local slice context mismatch (ordering/since/until); treat as not comparable (not local divergence), not global convergence, not runtime sync authority, and not an automatic sync decision."
        }
    }
}

/// Builds a read-only local convergence report from already materialized digest slices.
/// This helper is pure and does not mutate runtime, protocol, relay state, or storage.
#[allow(dead_code)]
pub(crate) fn build_sync_convergence_harness_report_from_digests(
    scenario: SyncConvergenceScenario,
    left: BandwidthMinimalSyncDigest,
    right: BandwidthMinimalSyncDigest,
) -> SyncConvergenceHarnessReport {
    let comparison = compare_bandwidth_minimal_sync_digest(&left, &right);
    let comparability = classify_sync_slice_comparability(&left, &right);
    let outcome = classify_sync_convergence_diagnostic(comparability, comparison);

    SyncConvergenceHarnessReport {
        scenario,
        since_ts_ms: left.since_ts_ms,
        until_ts_ms: left.until_ts_ms,
        left,
        right,
        comparability,
        comparison,
        outcome,
        is_authoritative_for_runtime: false,
        is_global_truth: false,
        reason: sync_convergence_diagnostic_reason(outcome).to_string(),
    }
}

/// Builds a read-only local convergence report for a controlled scenario and window.
/// This helper does not mutate runtime, protocol, relay state, or storage.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) fn build_sync_convergence_harness_report(
    scenario: SyncConvergenceScenario,
    left_messages: &[StoredMessage],
    right_messages: &[StoredMessage],
    since_ts_ms: u64,
    until_ts_ms: u64,
) -> Result<SyncConvergenceHarnessReport, MeshContractError> {
    let left = build_bandwidth_minimal_sync_digest(left_messages, since_ts_ms, until_ts_ms)?;
    let right = build_bandwidth_minimal_sync_digest(right_messages, since_ts_ms, until_ts_ms)?;
    Ok(build_sync_convergence_harness_report_from_digests(
        scenario, left, right,
    ))
}

fn operational_truth_surface(
    kind: OperationalTruthKind,
    source_label: &'static str,
    reason: &'static str,
) -> OperationalTruthSurface {
    OperationalTruthSurface {
        kind,
        source_label: source_label.to_string(),
        is_authoritative_for_runtime: false,
        is_global_truth: false,
        reason: reason.to_string(),
    }
}

/// Classifies accepted-state witness output as local evidence only.
#[allow(dead_code)]
pub(crate) fn classify_accepted_state_witness_truth_surface(
    _witness: &AcceptedStateWitness,
) -> OperationalTruthSurface {
    operational_truth_surface(
        OperationalTruthKind::LocalEvidence,
        "mesh.accepted_state_witness",
        "Deterministic local accepted-history evidence; not runtime authority and not global truth.",
    )
}

/// Classifies recovery witness output as local continuity evidence only.
#[allow(dead_code)]
pub(crate) fn classify_recovery_witness_truth_surface(
    _witness: &RecoveryWitness,
) -> OperationalTruthSurface {
    operational_truth_surface(
        OperationalTruthKind::LocalEvidence,
        "mesh.recovery_witness",
        "Conservative local continuity evidence; does not enforce restore/rejoin runtime behavior.",
    )
}

/// Classifies bandwidth-minimal digests as operational signaling, not convergence proof.
#[allow(dead_code)]
pub(crate) fn classify_bandwidth_minimal_sync_digest_truth_surface(
    _digest: &BandwidthMinimalSyncDigest,
) -> OperationalTruthSurface {
    operational_truth_surface(
        OperationalTruthKind::OperationalSignal,
        "mesh.bandwidth_minimal_sync_digest",
        "Operational comparison signal only; not runtime authority and not a global convergence proof.",
    )
}

/// Classifies sync-convergence harness reports strictly as derived diagnostics.
/// This classification is local and read-only; it is not runtime authority and
/// does not claim global convergence.
#[allow(dead_code)]
pub(crate) fn classify_sync_convergence_harness_truth_surface(
    _report: &SyncConvergenceHarnessReport,
) -> OperationalTruthSurface {
    operational_truth_surface(
        OperationalTruthKind::DerivedDiagnostic,
        "mesh.sync_convergence_harness_report",
        "Derived diagnostic from local slice comparison only; not global convergence, not runtime authority, and not an automatic sync decision.",
    )
}

/// Classifies the relay neutrality harness as a contract surface category.
/// This is not an execution-status signal for a specific proof run.
#[allow(dead_code)]
pub(crate) fn classify_relay_neutrality_contract_surface() -> OperationalTruthSurface {
    operational_truth_surface(
        OperationalTruthKind::ContractTruth,
        "mesh.relay_neutrality_contract_surface",
        "Contract-surface classification only for relay neutrality harness; not proof-run execution status and does not make relay an authority.",
    )
}

/// Reserves a classification slot for future derived diagnostics.
#[allow(dead_code)]
pub(crate) fn classify_reserved_derived_diagnostic_surface() -> OperationalTruthSurface {
    operational_truth_surface(
        OperationalTruthKind::DerivedDiagnostic,
        "mesh.derived_diagnostic.reserved",
        "Reserved derived-diagnostic surface; not contract truth and not runtime authority.",
    )
}

/// Builds the smallest read-only continuity witness for local recovery inspection in v0.
/// This helper never creates identity, never writes store state, and never emits `RestoredValid`
/// automatically without explicit external continuity evidence.
#[cfg(feature = "network")]
#[allow(dead_code)]
pub(crate) fn build_recovery_witness(
    store: &OfflineStore,
    messages: &[StoredMessage],
    since_ts_ms: u64,
) -> Result<RecoveryWitness, MeshContractError> {
    let accepted_state = build_accepted_state_witness(messages, since_ts_ms)?;

    let raw_identity = store
        .read_identity_pubkey_bytes()
        .map_err(|_| MeshContractError::NodeIdentityInspectionFailed)?;
    let (identity_fingerprint, invalid_identity_state) = match raw_identity {
        Some(pubkey_bytes) if pubkey_bytes.len() == 32 => {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&pubkey_bytes);
            (Some(identity_fingerprint(&pubkey)), false)
        }
        Some(_) => (None, true),
        None => (None, false),
    };

    let raw_relay_since = store
        .read_relay_state_value(RECOVERY_WITNESS_RELAY_SINCE_KEY)
        .map_err(|_| MeshContractError::RelayStateInspectionFailed {
            key: RECOVERY_WITNESS_RELAY_SINCE_KEY.to_string(),
        })?;
    let (relay_since_ts_ms, invalid_relay_state) = match raw_relay_since {
        Some(raw) => match raw.parse::<u64>() {
            Ok(parsed) => (Some(parsed), false),
            Err(_) => (None, true),
        },
        None => (None, false),
    };

    let classification = automatic_recovery_classification(
        identity_fingerprint,
        relay_since_ts_ms,
        &accepted_state,
        invalid_identity_state,
        invalid_relay_state,
    );

    Ok(RecoveryWitness {
        classification,
        identity_fingerprint,
        relay_since_ts_ms,
        continuity_digest: recovery_continuity_digest(
            classification,
            identity_fingerprint,
            relay_since_ts_ms,
            &accepted_state,
        ),
        accepted_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "network")]
    use rusqlite::{params, Connection};
    #[cfg(feature = "network")]
    use std::fs;
    #[cfg(feature = "network")]
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(feature = "network")]
    fn temp_db_path(prefix: &str) -> std::path::PathBuf {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{uniq}.db"))
    }

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

    fn sample_accepted_state_witness() -> AcceptedStateWitness {
        AcceptedStateWitness {
            ordering: OrderingMode::TimestampAscLocalTieBreak,
            since_ts_ms: 10,
            event_count: 2,
            first_event_hash: Some([0x11; 32]),
            last_event_hash: Some([0x22; 32]),
            state_digest: [0x33; 32],
        }
    }

    fn sample_recovery_witness() -> RecoveryWitness {
        RecoveryWitness {
            classification: crate::mesh::types::RecoveryClassification::Ambiguous,
            identity_fingerprint: Some([0x44; 32]),
            relay_since_ts_ms: Some(20),
            accepted_state: sample_accepted_state_witness(),
            continuity_digest: [0x55; 32],
        }
    }

    fn sample_bandwidth_digest() -> BandwidthMinimalSyncDigest {
        BandwidthMinimalSyncDigest {
            ordering: OrderingMode::TimestampAscLocalTieBreak,
            since_ts_ms: 10,
            until_ts_ms: 30,
            event_count: 2,
            state_digest: [0x66; 32],
        }
    }

    fn sample_sync_convergence_equivalent_report() -> SyncConvergenceHarnessReport {
        build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Replay,
            sample_bandwidth_digest(),
            sample_bandwidth_digest(),
        )
    }

    fn sample_sync_convergence_divergent_report() -> SyncConvergenceHarnessReport {
        let left = sample_bandwidth_digest();
        let mut right = sample_bandwidth_digest();
        right.state_digest = [0x77; 32];
        right.event_count = 3;
        build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Rejoin,
            left,
            right,
        )
    }

    fn sample_sync_convergence_not_comparable_report() -> SyncConvergenceHarnessReport {
        let left = sample_bandwidth_digest();
        let mut right = sample_bandwidth_digest();
        right.since_ts_ms = left.since_ts_ms + 1;

        build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Restart,
            left,
            right,
        )
    }

    #[cfg(feature = "network")]
    fn sample_convergence_messages() -> Vec<StoredMessage> {
        vec![
            StoredMessage {
                event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
        ]
    }

    #[test]
    fn operational_truth_surface_keeps_witnesses_out_of_global_truth() {
        let accepted_surface =
            classify_accepted_state_witness_truth_surface(&sample_accepted_state_witness());
        let recovery_surface = classify_recovery_witness_truth_surface(&sample_recovery_witness());

        assert_eq!(accepted_surface.kind, OperationalTruthKind::LocalEvidence);
        assert!(!accepted_surface.is_global_truth);
        assert!(!accepted_surface.is_authoritative_for_runtime);
        assert_eq!(recovery_surface.kind, OperationalTruthKind::LocalEvidence);
        assert!(!recovery_surface.is_global_truth);
        assert!(!recovery_surface.is_authoritative_for_runtime);
    }

    #[test]
    fn operational_truth_surface_marks_digest_as_signal_only() {
        let digest_surface =
            classify_bandwidth_minimal_sync_digest_truth_surface(&sample_bandwidth_digest());

        assert_eq!(digest_surface.kind, OperationalTruthKind::OperationalSignal);
        assert!(!digest_surface.is_global_truth);
        assert!(!digest_surface.is_authoritative_for_runtime);
        assert!(digest_surface
            .reason
            .contains("not a global convergence proof"));
    }

    #[test]
    fn operational_truth_surface_sync_convergence_equivalent_is_derived_diagnostic() {
        let surface = classify_sync_convergence_harness_truth_surface(
            &sample_sync_convergence_equivalent_report(),
        );

        assert_eq!(surface.kind, OperationalTruthKind::DerivedDiagnostic);
        assert!(!surface.is_global_truth);
        assert!(!surface.is_authoritative_for_runtime);
        assert!(surface.reason.contains("local slice comparison"));
        assert!(surface.reason.contains("not global convergence"));
        assert!(surface.reason.contains("not runtime authority"));
    }

    #[test]
    fn operational_truth_surface_sync_convergence_divergent_is_derived_diagnostic() {
        let surface = classify_sync_convergence_harness_truth_surface(
            &sample_sync_convergence_divergent_report(),
        );

        assert_eq!(surface.kind, OperationalTruthKind::DerivedDiagnostic);
        assert!(!surface.is_global_truth);
        assert!(!surface.is_authoritative_for_runtime);
        assert!(surface.reason.contains("local slice comparison"));
        assert!(surface.reason.contains("not global convergence"));
    }

    #[test]
    fn operational_truth_surface_contract_truth_is_explicit_and_limited() {
        let relay_surface = classify_relay_neutrality_contract_surface();

        assert_eq!(relay_surface.kind, OperationalTruthKind::ContractTruth);
        assert!(!relay_surface.is_global_truth);
        assert!(!relay_surface.is_authoritative_for_runtime);
        assert!(relay_surface
            .reason
            .contains("does not make relay an authority"));
    }

    #[test]
    fn operational_truth_surface_classification_is_deterministic() {
        let accepted_a =
            classify_accepted_state_witness_truth_surface(&sample_accepted_state_witness());
        let accepted_b =
            classify_accepted_state_witness_truth_surface(&sample_accepted_state_witness());
        let recovery_a = classify_recovery_witness_truth_surface(&sample_recovery_witness());
        let recovery_b = classify_recovery_witness_truth_surface(&sample_recovery_witness());
        let digest_a =
            classify_bandwidth_minimal_sync_digest_truth_surface(&sample_bandwidth_digest());
        let digest_b =
            classify_bandwidth_minimal_sync_digest_truth_surface(&sample_bandwidth_digest());
        let relay_a = classify_relay_neutrality_contract_surface();
        let relay_b = classify_relay_neutrality_contract_surface();
        let sync_report = sample_sync_convergence_equivalent_report();
        let sync_a = classify_sync_convergence_harness_truth_surface(&sync_report);
        let sync_b = classify_sync_convergence_harness_truth_surface(&sync_report);

        assert_eq!(accepted_a, accepted_b);
        assert_eq!(recovery_a, recovery_b);
        assert_eq!(digest_a, digest_b);
        assert_eq!(relay_a, relay_b);
        assert_eq!(sync_a, sync_b);
    }

    #[test]
    fn operational_truth_surface_has_reserved_derived_diagnostic_slot() {
        let derived_surface = classify_reserved_derived_diagnostic_surface();

        assert_eq!(
            derived_surface.kind,
            OperationalTruthKind::DerivedDiagnostic
        );
        assert!(!derived_surface.is_global_truth);
        assert!(!derived_surface.is_authoritative_for_runtime);
        assert!(derived_surface
            .reason
            .contains("Reserved derived-diagnostic surface"));
    }

    #[test]
    fn operational_truth_surface_sync_convergence_reason_avoids_overclaim() {
        let surface = classify_sync_convergence_harness_truth_surface(
            &sample_sync_convergence_equivalent_report(),
        );
        let lower = surface.reason.to_ascii_lowercase();

        assert!(!lower.contains("consensus"));
        assert!(!lower.contains("global truth"));
        assert!(!lower.contains("automatic runtime"));
    }

    #[test]
    fn sync_convergence_diagnostic_equal_comparable_slice_is_equivalent() {
        let report = build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Replay,
            sample_bandwidth_digest(),
            sample_bandwidth_digest(),
        );

        assert_eq!(report.comparability, SyncSliceComparability::Comparable);
        assert_eq!(report.comparison, BandwidthDigestComparison::ExactMatch);
        assert_eq!(report.outcome, SyncConvergenceOutcome::EquivalentLocalSlice);
    }

    #[test]
    fn sync_convergence_diagnostic_different_digest_in_same_context_is_divergent() {
        let left = sample_bandwidth_digest();
        let mut right = sample_bandwidth_digest();
        right.state_digest = [0x88; 32];

        let report = build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Rejoin,
            left,
            right,
        );

        assert_eq!(report.comparability, SyncSliceComparability::Comparable);
        assert_eq!(report.comparison, BandwidthDigestComparison::Different);
        assert_eq!(report.outcome, SyncConvergenceOutcome::DivergentLocalSlice);
    }

    #[test]
    fn sync_convergence_diagnostic_since_mismatch_is_not_comparable() {
        let left = sample_bandwidth_digest();
        let mut right = sample_bandwidth_digest();
        right.since_ts_ms = left.since_ts_ms + 1;

        let report = build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Restart,
            left,
            right,
        );

        assert_eq!(report.comparability, SyncSliceComparability::NotComparable);
        assert_eq!(
            report.outcome,
            SyncConvergenceOutcome::NotComparableLocalSlice
        );
    }

    #[test]
    fn sync_convergence_diagnostic_until_mismatch_is_not_comparable() {
        let left = sample_bandwidth_digest();
        let mut right = sample_bandwidth_digest();
        right.until_ts_ms = left.until_ts_ms + 1;

        let report = build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Restart,
            left,
            right,
        );

        assert_eq!(report.comparability, SyncSliceComparability::NotComparable);
        assert_eq!(
            report.outcome,
            SyncConvergenceOutcome::NotComparableLocalSlice
        );
    }

    #[test]
    fn sync_convergence_diagnostic_ordering_mismatch_is_not_comparable() {
        let left = sample_bandwidth_digest();
        let mut right = sample_bandwidth_digest();
        right.ordering = OrderingMode::TimestampAscRelayRowTieBreak;

        let report = build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Restart,
            left,
            right,
        );

        assert_eq!(report.comparability, SyncSliceComparability::NotComparable);
        assert_eq!(
            report.outcome,
            SyncConvergenceOutcome::NotComparableLocalSlice
        );
    }

    #[test]
    fn sync_convergence_diagnostic_not_comparable_is_never_authoritative_or_global() {
        let report = sample_sync_convergence_not_comparable_report();
        let lower = report.reason.to_ascii_lowercase();

        assert_eq!(report.comparability, SyncSliceComparability::NotComparable);
        assert_eq!(
            report.outcome,
            SyncConvergenceOutcome::NotComparableLocalSlice
        );
        assert!(!report.is_global_truth);
        assert!(!report.is_authoritative_for_runtime);
        assert!(lower.contains("not comparable"));
        assert!(lower.contains("not global convergence"));
        assert!(lower.contains("not runtime sync authority"));
        assert!(!lower.contains("consensus"));
        assert!(!lower.contains("global truth"));
        assert!(!lower.contains("network error"));
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_replay_identical_snapshots_are_equivalent() {
        let messages = sample_convergence_messages();
        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Replay,
            &messages,
            &messages,
            0,
            30,
        )
        .expect("report");

        assert_eq!(report.comparability, SyncSliceComparability::Comparable);
        assert_eq!(report.outcome, SyncConvergenceOutcome::EquivalentLocalSlice);
        assert_eq!(report.comparison, BandwidthDigestComparison::ExactMatch);
        assert!(!report.is_global_truth);
        assert!(!report.is_authoritative_for_runtime);
        assert!(report.reason.contains("not global convergence"));
        assert!(report.reason.contains("not runtime sync authority"));
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_empty_window_is_equivalent_local_slice() {
        let messages = sample_convergence_messages();
        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Replay,
            &messages,
            &messages,
            0,
            5,
        )
        .expect("report");

        assert_eq!(report.comparability, SyncSliceComparability::Comparable);
        assert_eq!(report.outcome, SyncConvergenceOutcome::EquivalentLocalSlice);
        assert_eq!(report.comparison, BandwidthDigestComparison::ExactMatch);
        assert_eq!(report.left.event_count, 0);
        assert_eq!(report.right.event_count, 0);
        assert!(!report.is_global_truth);
        assert!(!report.is_authoritative_for_runtime);
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_rejoin_with_difference_is_divergent() {
        let left = sample_convergence_messages();
        let mut right = sample_convergence_messages();
        right[1].event_hash =
            "3333333333333333333333333333333333333333333333333333333333333333".to_string();

        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Rejoin,
            &left,
            &right,
            0,
            30,
        )
        .expect("report");

        assert_eq!(report.comparability, SyncSliceComparability::Comparable);
        assert_eq!(report.outcome, SyncConvergenceOutcome::DivergentLocalSlice);
        assert_eq!(report.comparison, BandwidthDigestComparison::Different);
        assert!(!report.is_global_truth);
        assert!(!report.is_authoritative_for_runtime);
        assert!(report.reason.contains("comparable local slice divergence"));
        assert!(report.reason.contains("not global convergence"));
        assert!(report.reason.contains("not runtime sync authority"));
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_order_difference_in_same_window_is_divergent() {
        let left = sample_convergence_messages();
        let mut right = sample_convergence_messages();
        right.reverse();

        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Restart,
            &left,
            &right,
            0,
            30,
        )
        .expect("report");

        assert_eq!(report.comparability, SyncSliceComparability::Comparable);
        assert_eq!(report.outcome, SyncConvergenceOutcome::DivergentLocalSlice);
        assert_eq!(report.comparison, BandwidthDigestComparison::Different);
        assert_eq!(report.left.event_count, report.right.event_count);
        assert_ne!(report.left.state_digest, report.right.state_digest);
        assert!(!report.is_global_truth);
        assert!(!report.is_authoritative_for_runtime);
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_exact_match_stays_non_authoritative_and_local() {
        let messages = sample_convergence_messages();
        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Restart,
            &messages,
            &messages,
            0,
            30,
        )
        .expect("report");

        assert_eq!(report.comparability, SyncSliceComparability::Comparable);
        assert_eq!(report.comparison, BandwidthDigestComparison::ExactMatch);
        assert_eq!(report.outcome, SyncConvergenceOutcome::EquivalentLocalSlice);
        assert!(!report.is_global_truth);
        assert!(!report.is_authoritative_for_runtime);
        assert!(report.reason.contains("comparable local slice equivalence"));
        assert!(report.reason.contains("not global convergence"));
        assert!(report.reason.contains("not runtime sync authority"));
        assert!(!report.reason.to_ascii_lowercase().contains("consensus"));
        assert!(!report.reason.to_ascii_lowercase().contains("global truth"));
        assert!(!report.reason.to_ascii_lowercase().contains("automatic"));
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_restart_same_input_is_deterministic() {
        let messages = sample_convergence_messages();

        let report_a = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Restart,
            &messages,
            &messages,
            0,
            30,
        )
        .expect("report a");
        let report_b = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Restart,
            &messages,
            &messages,
            0,
            30,
        )
        .expect("report b");

        assert_eq!(report_a, report_b);
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_invalid_cursor_propagates_error() {
        let messages = sample_convergence_messages();
        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Replay,
            &messages,
            &messages,
            u64::MAX,
            u64::MAX,
        );

        assert_eq!(
            report,
            Err(MeshContractError::InvalidSyncCursor {
                since_ts_ms: u64::MAX
            })
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn sync_convergence_harness_invalid_window_propagates_error() {
        let messages = sample_convergence_messages();
        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Replay,
            &messages,
            &messages,
            30,
            20,
        );

        assert_eq!(
            report,
            Err(MeshContractError::InvalidSyncWindow {
                since_ts_ms: 30,
                until_ts_ms: 20,
            })
        );
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
        assert_eq!(
            project_local_accepted_history(&messages, u64::MAX),
            Err(MeshContractError::InvalidSyncCursor {
                since_ts_ms: u64::MAX,
            })
        );
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

    #[cfg(feature = "network")]
    #[test]
    fn accepted_state_witness_empty_is_deterministic() {
        let messages = vec![StoredMessage {
            event_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            sender_id: "node_a".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 10,
            nonce: 1,
            content: b"one".to_vec(),
        }];

        let witness_a = build_accepted_state_witness(&messages, 20).expect("witness a");
        let witness_b = build_accepted_state_witness(&messages, 20).expect("witness b");

        assert_eq!(witness_a, witness_b);
        assert_eq!(witness_a.ordering, DEFAULT_NODE_ORDERING);
        assert_eq!(witness_a.since_ts_ms, 20);
        assert_eq!(witness_a.event_count, 0);
        assert_eq!(witness_a.first_event_hash, None);
        assert_eq!(witness_a.last_event_hash, None);
    }

    #[cfg(feature = "network")]
    #[test]
    fn accepted_state_witness_same_projection_yields_same_digest() {
        let messages = vec![
            StoredMessage {
                event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
        ];

        let witness_a = build_accepted_state_witness(&messages, 0).expect("witness a");
        let witness_b = build_accepted_state_witness(&messages, 0).expect("witness b");

        assert_eq!(witness_a, witness_b);
        assert_eq!(witness_a.state_digest, witness_b.state_digest);
    }

    #[cfg(feature = "network")]
    #[test]
    fn accepted_state_witness_digest_changes_when_projection_changes() {
        let messages = vec![
            StoredMessage {
                event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
        ];
        let reordered = vec![messages[1].clone(), messages[0].clone()];

        let witness_a = build_accepted_state_witness(&messages, 0).expect("witness a");
        let witness_b = build_accepted_state_witness(&reordered, 0).expect("witness b");

        assert_ne!(witness_a.state_digest, witness_b.state_digest);
        assert_ne!(witness_a.first_event_hash, witness_b.first_event_hash);
        assert_ne!(witness_a.last_event_hash, witness_b.last_event_hash);
    }

    #[cfg(feature = "network")]
    #[test]
    fn accepted_state_witness_rejects_invalid_cursor() {
        let witness = build_accepted_state_witness(&[], u64::MAX);

        assert_eq!(
            witness,
            Err(MeshContractError::InvalidSyncCursor {
                since_ts_ms: u64::MAX,
            })
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn accepted_state_witness_rejects_malformed_projected_hash() {
        let messages = vec![StoredMessage {
            event_hash: "not-hex".to_string(),
            sender_id: "node_a".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 10,
            nonce: 1,
            content: b"one".to_vec(),
        }];

        let witness = build_accepted_state_witness(&messages, 0);

        assert_eq!(
            witness,
            Err(MeshContractError::InvalidAcceptedEventHash {
                event_hash: "not-hex".to_string(),
            })
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn accepted_state_witness_metadata_matches_projection() {
        let messages = vec![
            StoredMessage {
                event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
            StoredMessage {
                event_hash: "3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
                sender_id: "node_c".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 30,
                nonce: 3,
                content: b"three".to_vec(),
            },
        ];

        let (_, projected) =
            project_local_accepted_history(&messages, 15).expect("valid local projection");
        let witness = build_accepted_state_witness(&messages, 15).expect("witness");

        assert_eq!(witness.ordering, DEFAULT_NODE_ORDERING);
        assert_eq!(witness.since_ts_ms, 15);
        assert_eq!(witness.event_count, projected.len() as u64);
        assert_eq!(witness.first_event_hash, Some([0x22; 32]));
        assert_eq!(witness.last_event_hash, Some([0x33; 32]));
        assert_eq!(projected.len(), 2);
        assert_eq!(projected[0].event_hash, messages[1].event_hash);
        assert_eq!(projected[1].event_hash, messages[2].event_hash);
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_same_input_is_deterministic() {
        let messages = vec![
            StoredMessage {
                event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
        ];

        let digest_a = build_bandwidth_minimal_sync_digest(&messages, 0, 25).expect("digest a");
        let digest_b = build_bandwidth_minimal_sync_digest(&messages, 0, 25).expect("digest b");
        let accepted = build_accepted_state_witness(&messages, 0).expect("accepted");

        assert_eq!(digest_a, digest_b);
        assert_eq!(digest_a.ordering, accepted.ordering);
        assert_eq!(digest_a.event_count, accepted.event_count);
        assert_eq!(digest_a.state_digest, accepted.state_digest);
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_empty_window_is_stable() {
        let messages = vec![StoredMessage {
            event_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            sender_id: "node_a".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 100,
            nonce: 1,
            content: b"one".to_vec(),
        }];

        let digest_a = build_bandwidth_minimal_sync_digest(&messages, 0, 50).expect("digest a");
        let digest_b = build_bandwidth_minimal_sync_digest(&messages, 0, 50).expect("digest b");

        assert_eq!(digest_a, digest_b);
        assert_eq!(digest_a.event_count, 0);
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_window_change_updates_digest() {
        let messages = vec![
            StoredMessage {
                event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
        ];

        let narrow = build_bandwidth_minimal_sync_digest(&messages, 0, 15).expect("narrow");
        let wide = build_bandwidth_minimal_sync_digest(&messages, 0, 25).expect("wide");

        assert_ne!(narrow.state_digest, wide.state_digest);
        assert_ne!(narrow.event_count, wide.event_count);
        assert_ne!(narrow.until_ts_ms, wide.until_ts_ms);
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_history_change_updates_digest() {
        let messages_a = vec![
            StoredMessage {
                event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
                sender_id: "node_a".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 10,
                nonce: 1,
                content: b"one".to_vec(),
            },
            StoredMessage {
                event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
                sender_id: "node_b".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"two".to_vec(),
            },
        ];
        let messages_b = vec![
            messages_a[0].clone(),
            StoredMessage {
                event_hash: "3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
                sender_id: "node_c".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 20,
                nonce: 2,
                content: b"three".to_vec(),
            },
        ];

        let digest_a = build_bandwidth_minimal_sync_digest(&messages_a, 0, 25).expect("digest a");
        let digest_b = build_bandwidth_minimal_sync_digest(&messages_b, 0, 25).expect("digest b");

        assert_ne!(digest_a.state_digest, digest_b.state_digest);
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_rejects_invalid_cursor() {
        let digest = build_bandwidth_minimal_sync_digest(&[], u64::MAX, u64::MAX);

        assert_eq!(
            digest,
            Err(MeshContractError::InvalidSyncCursor {
                since_ts_ms: u64::MAX,
            })
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_rejects_invalid_until_cursor() {
        let digest = build_bandwidth_minimal_sync_digest(&[], 0, u64::MAX);

        assert_eq!(
            digest,
            Err(MeshContractError::InvalidSyncCursor {
                since_ts_ms: u64::MAX,
            })
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_rejects_invalid_window() {
        let digest = build_bandwidth_minimal_sync_digest(&[], 100, 99);

        assert_eq!(
            digest,
            Err(MeshContractError::InvalidSyncWindow {
                since_ts_ms: 100,
                until_ts_ms: 99,
            })
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_compare_equal_returns_exact_match() {
        let messages = vec![StoredMessage {
            event_hash: "4444444444444444444444444444444444444444444444444444444444444444"
                .to_string(),
            sender_id: "node_d".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 40,
            nonce: 4,
            content: b"four".to_vec(),
        }];
        let digest = build_bandwidth_minimal_sync_digest(&messages, 0, 50).expect("digest");

        // Local exact match for the same summary fields only; this is not global convergence.
        assert_eq!(
            compare_bandwidth_minimal_sync_digest(&digest, &digest),
            BandwidthDigestComparison::ExactMatch
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn bandwidth_minimal_sync_digest_compare_different_returns_different() {
        let messages = vec![
            StoredMessage {
                event_hash: "5555555555555555555555555555555555555555555555555555555555555555"
                    .to_string(),
                sender_id: "node_e".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 50,
                nonce: 5,
                content: b"five".to_vec(),
            },
            StoredMessage {
                event_hash: "6666666666666666666666666666666666666666666666666666666666666666"
                    .to_string(),
                sender_id: "node_f".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 60,
                nonce: 6,
                content: b"six".to_vec(),
            },
        ];
        let digest_a = build_bandwidth_minimal_sync_digest(&messages, 0, 55).expect("digest a");
        let digest_b = build_bandwidth_minimal_sync_digest(&messages, 0, 65).expect("digest b");

        assert_eq!(
            compare_bandwidth_minimal_sync_digest(&digest_a, &digest_b),
            BandwidthDigestComparison::Different
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_without_identity_or_evidence_is_new_node_and_does_not_create_identity() {
        let store = OfflineStore::open_in_memory().expect("store");
        assert_eq!(
            store.read_identity_pubkey_bytes().expect("identity before"),
            None
        );

        let witness = build_recovery_witness(&store, &[], 0).expect("witness");

        assert_eq!(witness.classification, RecoveryClassification::NewNode);
        assert_eq!(witness.identity_fingerprint, None);
        assert_eq!(witness.relay_since_ts_ms, None);
        assert_eq!(witness.accepted_state.event_count, 0);
        assert_eq!(
            store.read_identity_pubkey_bytes().expect("identity after"),
            None
        );
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_without_identity_but_with_accepted_evidence_is_ambiguous() {
        let store = OfflineStore::open_in_memory().expect("store");
        let messages = vec![StoredMessage {
            event_hash: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            sender_id: "node_a".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 10,
            nonce: 1,
            content: b"one".to_vec(),
        }];

        let witness = build_recovery_witness(&store, &messages, 0).expect("witness");

        assert_eq!(witness.classification, RecoveryClassification::Ambiguous);
        assert_eq!(witness.identity_fingerprint, None);
        assert_eq!(witness.accepted_state.event_count, 1);
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_identity_alone_is_ambiguous() {
        let store = OfflineStore::open_in_memory().expect("store");
        store.get_or_create_identity().expect("identity");

        let witness = build_recovery_witness(&store, &[], 0).expect("witness");

        assert_eq!(witness.classification, RecoveryClassification::Ambiguous);
        assert!(witness.identity_fingerprint.is_some());
        assert_eq!(witness.accepted_state.event_count, 0);
        assert_eq!(witness.relay_since_ts_ms, None);
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_valid_identity_and_accepted_state_is_intact() {
        let store = OfflineStore::open_in_memory().expect("store");
        store.get_or_create_identity().expect("identity");
        let messages = vec![StoredMessage {
            event_hash: "2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            sender_id: "node_b".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 20,
            nonce: 2,
            content: b"two".to_vec(),
        }];

        let witness = build_recovery_witness(&store, &messages, 0).expect("witness");

        assert_eq!(witness.classification, RecoveryClassification::Intact);
        assert_ne!(
            witness.classification,
            RecoveryClassification::RestoredValid
        );
        assert!(witness.identity_fingerprint.is_some());
        assert_eq!(witness.accepted_state.event_count, 1);
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_malformed_identity_is_invalid() {
        let path = temp_db_path("nexo_recovery_invalid_identity");
        {
            let store = OfflineStore::open(path.to_str().expect("path")).expect("store");
            drop(store);
        }
        let conn = Connection::open(&path).expect("conn");
        conn.execute(
            "INSERT INTO node_identity(id, pubkey, seckey) VALUES (1, ?1, ?2)",
            params![vec![7u8; 31], vec![9u8; 64]],
        )
        .expect("insert identity");
        drop(conn);

        let store = OfflineStore::open(path.to_str().expect("path")).expect("store");
        let witness = build_recovery_witness(&store, &[], 0).expect("witness");

        assert_eq!(witness.classification, RecoveryClassification::Invalid);
        assert_eq!(witness.identity_fingerprint, None);
        drop(store);
        fs::remove_file(path).expect("cleanup");
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_same_input_yields_same_continuity_digest() {
        let store = OfflineStore::open_in_memory().expect("store");
        store.get_or_create_identity().expect("identity");
        let messages = vec![StoredMessage {
            event_hash: "3333333333333333333333333333333333333333333333333333333333333333"
                .to_string(),
            sender_id: "node_c".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 30,
            nonce: 3,
            content: b"three".to_vec(),
        }];

        let witness_a = build_recovery_witness(&store, &messages, 0).expect("witness a");
        let witness_b = build_recovery_witness(&store, &messages, 0).expect("witness b");

        assert_eq!(witness_a, witness_b);
        assert_eq!(witness_a.continuity_digest, witness_b.continuity_digest);
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_digest_changes_when_accepted_state_changes() {
        let store = OfflineStore::open_in_memory().expect("store");
        store.get_or_create_identity().expect("identity");
        let messages = vec![
            StoredMessage {
                event_hash: "4444444444444444444444444444444444444444444444444444444444444444"
                    .to_string(),
                sender_id: "node_d".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 40,
                nonce: 4,
                content: b"four".to_vec(),
            },
            StoredMessage {
                event_hash: "5555555555555555555555555555555555555555555555555555555555555555"
                    .to_string(),
                sender_id: "node_e".to_string(),
                channel: "global".to_string(),
                timestamp_utc_ms: 50,
                nonce: 5,
                content: b"five".to_vec(),
            },
        ];
        let reordered = vec![messages[1].clone(), messages[0].clone()];

        let witness_a = build_recovery_witness(&store, &messages, 0).expect("witness a");
        let witness_b = build_recovery_witness(&store, &reordered, 0).expect("witness b");

        assert_ne!(
            witness_a.accepted_state.state_digest,
            witness_b.accepted_state.state_digest
        );
        assert_ne!(witness_a.continuity_digest, witness_b.continuity_digest);
    }

    #[cfg(feature = "network")]
    #[test]
    fn recovery_witness_never_emits_restored_valid_automatically() {
        let intact_store = OfflineStore::open_in_memory().expect("store");
        intact_store.get_or_create_identity().expect("identity");
        let intact = build_recovery_witness(&intact_store, &[], 0).expect("intact");

        let ambiguous_store = OfflineStore::open_in_memory().expect("store");
        let ambiguous_messages = vec![StoredMessage {
            event_hash: "6666666666666666666666666666666666666666666666666666666666666666"
                .to_string(),
            sender_id: "node_f".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: 60,
            nonce: 6,
            content: b"six".to_vec(),
        }];
        let ambiguous =
            build_recovery_witness(&ambiguous_store, &ambiguous_messages, 0).expect("ambiguous");

        assert_ne!(intact.classification, RecoveryClassification::RestoredValid);
        assert_ne!(
            ambiguous.classification,
            RecoveryClassification::RestoredValid
        );
    }
}
