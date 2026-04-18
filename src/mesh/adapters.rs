use crate::message::validate_persistable_timestamp_ms;
use crate::message::{event_hash, CanonicalMessage};
use std::fs;
use std::path::Path;

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
    AcceptedEventRef, AcceptedStateWitness, BandwidthMinimalSyncDigest,
    MeshDiagnosticActionability, MeshEventKind, MeshReplayDedupDiagnostic, OrderingMode,
    RecoveryWitness, SyncConvergenceHarnessReport, SyncConvergenceOutcome, SyncConvergenceScenario,
    SyncDiagnosticFreshness, SyncSliceComparability, SyncWindow, SyncWindowValidationError,
    TwoSnapshotSyncEconomicsRecord,
};

#[cfg(feature = "network")]
use crate::offline_store::{OfflineStore, StoreInsertStatus, StoredMessage};

#[cfg(feature = "network")]
const RECOVERY_WITNESS_RELAY_SINCE_KEY: &str = "last_relay_pull_since_ms";
pub(crate) const TWO_SNAPSHOT_SYNC_ECONOMICS_ARTIFACT_PATH: &str =
    "artifacts/sync_economics/two_snapshot_sync_economics.jsonl";
const TWO_SNAPSHOT_SYNC_ECONOMICS_SCHEMA_VERSION: &str = "v1";
const DIGEST_ORDERING_BYTES: u64 = 1;
const DIGEST_TIMESTAMP_BYTES: u64 = 8;
const DIGEST_EVENT_COUNT_BYTES: u64 = 8;
const DIGEST_STATE_BYTES: u64 = 32;
const ESTIMATED_FULL_SYNC_BYTES_PER_EVENT: u64 = 128;

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
    validate_persistable_mesh_timestamp("since_ts_ms", since_ts_ms).ok()?;
    validate_persistable_mesh_timestamp("message.timestamp_utc_ms", message.timestamp_utc_ms)
        .ok()?;
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
    validate_persistable_mesh_timestamp("since_ts_ms", since_ts_ms)?;
    let projected = messages
        .iter()
        .filter(|message| message.timestamp_utc_ms >= since_ts_ms)
        .map(|message| -> Result<AcceptedEventRef, MeshContractError> {
            validate_persistable_mesh_timestamp(
                "message.timestamp_utc_ms",
                message.timestamp_utc_ms,
            )?;
            Ok(accepted_event_ref_from_stored_message(
                message,
                MeshEventKind::LocalReplay,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((local_node_ordering_mode(), projected))
}

#[cfg(feature = "network")]
fn witness_hash_field(hasher: &mut blake3::Hasher, tag: &[u8], data: &[u8]) {
    hasher.update(&(tag.len() as u32).to_le_bytes());
    hasher.update(tag);
    hasher.update(&(data.len() as u32).to_le_bytes());
    hasher.update(data);
}

fn validate_persistable_mesh_timestamp(
    field: &'static str,
    value: u64,
) -> Result<(), MeshContractError> {
    validate_persistable_timestamp_ms(value)
        .map_err(|_| MeshContractError::TimestampOutOfPersistableRange { field, value })
}

fn mesh_error_from_sync_window_validation(
    err: SyncWindowValidationError,
    since_field: &'static str,
    until_field: &'static str,
) -> MeshContractError {
    match err {
        SyncWindowValidationError::SinceOutOfPersistableRange { value } => {
            MeshContractError::TimestampOutOfPersistableRange {
                field: since_field,
                value,
            }
        }
        SyncWindowValidationError::UntilOutOfPersistableRange { value } => {
            MeshContractError::TimestampOutOfPersistableRange {
                field: until_field,
                value,
            }
        }
        SyncWindowValidationError::UntilBeforeSince {
            since_ts_ms,
            until_ts_ms,
        } => MeshContractError::InvalidSyncWindow {
            since_ts_ms,
            until_ts_ms,
        },
    }
}

fn validated_sync_window(
    since_ts_ms: u64,
    until_ts_ms: u64,
) -> Result<SyncWindow, MeshContractError> {
    SyncWindow::new(since_ts_ms, until_ts_ms)
        .map_err(|err| mesh_error_from_sync_window_validation(err, "since_ts_ms", "until_ts_ms"))
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
    validate_persistable_mesh_timestamp("since_ts_ms", since_ts_ms)?;
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
    let window = validated_sync_window(since_ts_ms, until_ts_ms)?;

    let windowed = messages
        .iter()
        .filter(|message| message.timestamp_utc_ms <= window.until_ts_ms())
        .cloned()
        .collect::<Vec<_>>();
    let accepted = build_accepted_state_witness(&windowed, window.since_ts_ms())?;

    Ok(BandwidthMinimalSyncDigest {
        ordering: accepted.ordering,
        since_ts_ms: window.since_ts_ms(),
        until_ts_ms: window.until_ts_ms(),
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
    let left_window = SyncWindow::new(left.since_ts_ms, left.until_ts_ms);
    let right_window = SyncWindow::new(right.since_ts_ms, right.until_ts_ms);

    match (left_window, right_window) {
        (Ok(left_window), Ok(right_window))
            if left.ordering == right.ordering && left_window == right_window =>
        {
            SyncSliceComparability::Comparable
        }
        _ => SyncSliceComparability::NotComparable,
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

/// Classifies whether a local convergence diagnostic is recent enough for operator use.
/// Freshness is diagnostic-only, not runtime authority, not global truth, and not a sync decision.
#[allow(dead_code)]
pub(crate) fn classify_sync_convergence_diagnostic_freshness(
    report: &SyncConvergenceHarnessReport,
    observed_at_ts_ms: u64,
    max_staleness_ms: u64,
) -> Result<SyncDiagnosticFreshness, MeshContractError> {
    validate_persistable_mesh_timestamp("observed_at_ts_ms", observed_at_ts_ms)?;
    let report_window = match SyncWindow::new(report.since_ts_ms, report.until_ts_ms) {
        Ok(window) => window,
        Err(SyncWindowValidationError::UntilBeforeSince { .. }) => {
            return Ok(SyncDiagnosticFreshness::FreshnessNotAssessable);
        }
        Err(err) => {
            return Err(mesh_error_from_sync_window_validation(
                err,
                "report.since_ts_ms",
                "report.until_ts_ms",
            ));
        }
    };

    if observed_at_ts_ms < report_window.until_ts_ms() {
        return Ok(SyncDiagnosticFreshness::FreshnessNotAssessable);
    }

    let staleness_ms = observed_at_ts_ms - report_window.until_ts_ms();
    if staleness_ms <= max_staleness_ms {
        Ok(SyncDiagnosticFreshness::FreshEnoughLocalDiagnostic)
    } else {
        Ok(SyncDiagnosticFreshness::StaleLocalDiagnostic)
    }
}

/// Classifies sync-convergence harness outputs as diagnostic-only surfaces.
/// Diagnostic output is not a runtime decision, not sync authority, and not global truth.
#[allow(dead_code)]
pub(crate) fn classify_sync_convergence_harness_actionability(
    _report: &SyncConvergenceHarnessReport,
) -> MeshDiagnosticActionability {
    MeshDiagnosticActionability::DiagnosticOnly
}

const fn digest_summary_bytes() -> u64 {
    DIGEST_ORDERING_BYTES
        + DIGEST_TIMESTAMP_BYTES
        + DIGEST_TIMESTAMP_BYTES
        + DIGEST_EVENT_COUNT_BYTES
        + DIGEST_STATE_BYTES
}

fn conservative_estimated_full_sync_bytes(left_event_count: u64, right_event_count: u64) -> u64 {
    left_event_count
        .max(right_event_count)
        .saturating_mul(ESTIMATED_FULL_SYNC_BYTES_PER_EVENT)
}

fn sync_economics_can_skip_heavy_sync(
    report: &SyncConvergenceHarnessReport,
    freshness: Option<SyncDiagnosticFreshness>,
) -> bool {
    report.comparability == SyncSliceComparability::Comparable
        && report.outcome == SyncConvergenceOutcome::EquivalentLocalSlice
        && freshness != Some(SyncDiagnosticFreshness::StaleLocalDiagnostic)
}

/// Builds a deterministic two-snapshot economics record for local comparison-first diagnostics.
/// This helper is read-only and does not perform sync, merge, or runtime actions.
#[allow(dead_code)]
pub(crate) fn build_two_snapshot_sync_economics_record(
    scenario_id: impl Into<String>,
    report: &SyncConvergenceHarnessReport,
    freshness: Option<SyncDiagnosticFreshness>,
) -> Result<TwoSnapshotSyncEconomicsRecord, MeshContractError> {
    validated_sync_window(report.since_ts_ms, report.until_ts_ms)?;
    validated_sync_window(report.left.since_ts_ms, report.left.until_ts_ms)?;
    validated_sync_window(report.right.since_ts_ms, report.right.until_ts_ms)?;

    let left_digest_bytes = digest_summary_bytes();
    let right_digest_bytes = digest_summary_bytes();
    let compared_digest_bytes_total = left_digest_bytes.saturating_add(right_digest_bytes);
    let estimated_full_sync_bytes =
        conservative_estimated_full_sync_bytes(report.left.event_count, report.right.event_count);
    let saved_bytes_if_sync_skipped = if sync_economics_can_skip_heavy_sync(report, freshness) {
        estimated_full_sync_bytes.saturating_sub(compared_digest_bytes_total)
    } else {
        0
    };
    let diagnostic_actionability = classify_sync_convergence_harness_actionability(report);

    Ok(TwoSnapshotSyncEconomicsRecord {
        schema_version: TWO_SNAPSHOT_SYNC_ECONOMICS_SCHEMA_VERSION.to_string(),
        scenario_id: scenario_id.into(),
        since_ts_ms: report.since_ts_ms,
        until_ts_ms: report.until_ts_ms,
        left_event_count: report.left.event_count,
        right_event_count: report.right.event_count,
        left_digest_bytes,
        right_digest_bytes,
        compared_digest_bytes_total,
        estimated_bytes_per_event: ESTIMATED_FULL_SYNC_BYTES_PER_EVENT,
        estimated_full_sync_bytes,
        saved_bytes_if_sync_skipped,
        comparability: report.comparability,
        outcome: report.outcome,
        freshness,
        diagnostic_actionability,
        is_runtime_authority: false,
        is_global_truth: false,
        reason: format!(
            "Two-snapshot local economics diagnostic only; compared bytes are direct digest-summary bytes, full-sync bytes are conservative estimate ({} bytes/event). {}",
            ESTIMATED_FULL_SYNC_BYTES_PER_EVENT, report.reason
        ),
    })
}

fn synthetic_bandwidth_digest(
    ordering: OrderingMode,
    since_ts_ms: u64,
    until_ts_ms: u64,
    event_count: u64,
    digest_fill_byte: u8,
) -> BandwidthMinimalSyncDigest {
    BandwidthMinimalSyncDigest {
        ordering,
        since_ts_ms,
        until_ts_ms,
        event_count,
        state_digest: [digest_fill_byte; 32],
    }
}

/// Builds deterministic local economics scenarios for two-snapshot sync diagnostics.
/// Rust is the source of truth for these artifacts; downstream analysis should only read/analyze.
#[allow(dead_code)]
pub(crate) fn build_two_snapshot_sync_economics_harness_records(
) -> Result<Vec<TwoSnapshotSyncEconomicsRecord>, MeshContractError> {
    let base_left =
        synthetic_bandwidth_digest(OrderingMode::TimestampAscLocalTieBreak, 100, 200, 4, 0x11);
    let report_equivalent_fresh = build_sync_convergence_harness_report_from_digests(
        SyncConvergenceScenario::Replay,
        base_left.clone(),
        base_left.clone(),
    );
    let freshness_equivalent_fresh = Some(classify_sync_convergence_diagnostic_freshness(
        &report_equivalent_fresh,
        report_equivalent_fresh.until_ts_ms + 5,
        20,
    )?);

    let mut divergent_right = base_left.clone();
    divergent_right.event_count = 5;
    divergent_right.state_digest = [0x22; 32];
    let report_divergent_fresh = build_sync_convergence_harness_report_from_digests(
        SyncConvergenceScenario::Rejoin,
        base_left.clone(),
        divergent_right,
    );
    let freshness_divergent_fresh = Some(classify_sync_convergence_diagnostic_freshness(
        &report_divergent_fresh,
        report_divergent_fresh.until_ts_ms + 5,
        20,
    )?);

    let not_comparable_right =
        synthetic_bandwidth_digest(OrderingMode::TimestampAscLocalTieBreak, 120, 220, 4, 0x11);
    let report_not_comparable = build_sync_convergence_harness_report_from_digests(
        SyncConvergenceScenario::Restart,
        base_left.clone(),
        not_comparable_right,
    );

    let report_equivalent_stale = build_sync_convergence_harness_report_from_digests(
        SyncConvergenceScenario::Restart,
        base_left.clone(),
        base_left,
    );
    let freshness_equivalent_stale = Some(classify_sync_convergence_diagnostic_freshness(
        &report_equivalent_stale,
        report_equivalent_stale.until_ts_ms + 500,
        20,
    )?);

    Ok(vec![
        build_two_snapshot_sync_economics_record(
            "comparable_equivalent_fresh",
            &report_equivalent_fresh,
            freshness_equivalent_fresh,
        )?,
        build_two_snapshot_sync_economics_record(
            "comparable_divergent_fresh",
            &report_divergent_fresh,
            freshness_divergent_fresh,
        )?,
        build_two_snapshot_sync_economics_record(
            "not_comparable_context_mismatch",
            &report_not_comparable,
            None,
        )?,
        build_two_snapshot_sync_economics_record(
            "comparable_equivalent_stale",
            &report_equivalent_stale,
            freshness_equivalent_stale,
        )?,
    ])
}

/// Serializes one economics record to canonical JSON.
#[allow(dead_code)]
pub(crate) fn serialize_two_snapshot_sync_economics_record_json(
    record: &TwoSnapshotSyncEconomicsRecord,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(record)
}

/// Serializes economics records as canonical JSONL in stable input order.
#[allow(dead_code)]
pub(crate) fn serialize_two_snapshot_sync_economics_records_jsonl(
    records: &[TwoSnapshotSyncEconomicsRecord],
) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for record in records {
        out.push_str(&serialize_two_snapshot_sync_economics_record_json(record)?);
        out.push('\n');
    }
    Ok(out)
}

/// Writes economics records to JSONL artifact path.
#[allow(dead_code)]
pub(crate) fn write_two_snapshot_sync_economics_artifact_jsonl(
    path: &Path,
    records: &[TwoSnapshotSyncEconomicsRecord],
) -> std::io::Result<()> {
    let jsonl = serialize_two_snapshot_sync_economics_records_jsonl(records)
        .map_err(std::io::Error::other)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, jsonl)
}

/// Exports deterministic two-snapshot sync economics artifacts.
/// The artifact is diagnostic-only: it does not prove global convergence and does not decide sync.
#[allow(dead_code)]
pub(crate) fn export_two_snapshot_sync_economics_harness_artifact() -> std::io::Result<()> {
    let records = build_two_snapshot_sync_economics_harness_records()
        .map_err(|err| std::io::Error::other(format!("mesh economics harness failed: {err:?}")))?;
    write_two_snapshot_sync_economics_artifact_jsonl(
        Path::new(TWO_SNAPSHOT_SYNC_ECONOMICS_ARTIFACT_PATH),
        &records,
    )
}

/// Classifies freshness outputs as diagnostic-only surfaces.
/// Diagnostic output is not a runtime decision, not sync authority, and not global truth.
#[allow(dead_code)]
pub(crate) fn classify_sync_diagnostic_freshness_actionability(
    _freshness: SyncDiagnosticFreshness,
) -> MeshDiagnosticActionability {
    MeshDiagnosticActionability::DiagnosticOnly
}

/// Classifies OperationalTruthSurface actionability in a conservative, fail-closed way.
/// No surface here directly authorizes runtime actions.
#[allow(dead_code)]
pub(crate) fn classify_operational_truth_surface_actionability(
    surface: &OperationalTruthSurface,
) -> MeshDiagnosticActionability {
    match surface.kind {
        OperationalTruthKind::ContractTruth => {
            MeshDiagnosticActionability::RequiresExplicitRuntimeContract
        }
        OperationalTruthKind::LocalEvidence
        | OperationalTruthKind::OperationalSignal
        | OperationalTruthKind::DerivedDiagnostic => MeshDiagnosticActionability::DiagnosticOnly,
    }
}

/// Classifies replay/dedup/sequencing from local evidence only.
/// This diagnostic is local evidence only, not runtime authority, not global truth,
/// and not automatic enforcement.
#[allow(dead_code)]
pub(crate) fn classify_mesh_replay_dedup_sequencing(
    known_events: &[AcceptedEventRef],
    candidate: &AcceptedEventRef,
) -> Result<MeshReplayDedupDiagnostic, MeshContractError> {
    validate_persistable_mesh_timestamp("candidate.timestamp_utc_ms", candidate.timestamp_utc_ms)?;
    for known in known_events {
        validate_persistable_mesh_timestamp(
            "known_event.timestamp_utc_ms",
            known.timestamp_utc_ms,
        )?;
    }

    if known_events
        .iter()
        .any(|known| known.event_hash == candidate.event_hash)
    {
        return Ok(MeshReplayDedupDiagnostic::DuplicateKnownEvent);
    }

    if known_events.iter().any(|known| {
        known.sender_id == candidate.sender_id
            && known.nonce == candidate.nonce
            && known.event_hash != candidate.event_hash
    }) {
        return Ok(MeshReplayDedupDiagnostic::ReplaySuspected);
    }

    let max_known_nonce = known_events
        .iter()
        .filter(|known| known.sender_id == candidate.sender_id)
        .map(|known| known.nonce)
        .max();

    match max_known_nonce {
        None => Ok(MeshReplayDedupDiagnostic::SequencingNotAssessable),
        Some(max_nonce) if candidate.nonce < max_nonce => {
            Ok(MeshReplayDedupDiagnostic::SequenceRegressionSuspected)
        }
        Some(max_nonce) if candidate.nonce > max_nonce.saturating_add(1) => {
            Ok(MeshReplayDedupDiagnostic::SequenceGapDetected)
        }
        _ => Ok(MeshReplayDedupDiagnostic::UniqueLocalCandidate),
    }
}

/// Classifies replay/dedup/sequencing diagnostics as local-evidence truth surface only.
#[allow(dead_code)]
pub(crate) fn classify_mesh_replay_dedup_sequencing_truth_surface(
    _diagnostic: MeshReplayDedupDiagnostic,
) -> OperationalTruthSurface {
    operational_truth_surface(
        OperationalTruthKind::LocalEvidence,
        "mesh.replay_dedup_sequencing_diagnostic",
        "Replay/dedup/sequencing diagnostic is local evidence only, not runtime authority, not global truth, and not automatic enforcement.",
    )
}

/// Classifies replay/dedup/sequencing diagnostics as diagnostic-only outputs.
#[allow(dead_code)]
pub(crate) fn classify_mesh_replay_dedup_sequencing_actionability(
    _diagnostic: MeshReplayDedupDiagnostic,
) -> MeshDiagnosticActionability {
    MeshDiagnosticActionability::DiagnosticOnly
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
            Ok(parsed) => {
                validate_persistable_mesh_timestamp("relay_since_ts_ms", parsed)?;
                (Some(parsed), false)
            }
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
    use std::fs;
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

    fn sample_accepted_event(
        event_hash: &str,
        sender_id: &str,
        timestamp_utc_ms: u64,
        nonce: u64,
    ) -> AcceptedEventRef {
        AcceptedEventRef {
            event_hash: event_hash.to_string(),
            sender_id: sender_id.to_string(),
            timestamp_utc_ms,
            nonce,
            kind: MeshEventKind::LocalReplay,
        }
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
    fn sync_convergence_diagnostic_same_invalid_window_is_not_comparable() {
        let mut left = sample_bandwidth_digest();
        left.since_ts_ms = 20;
        left.until_ts_ms = 10;
        let right = left.clone();

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

    #[test]
    fn sync_convergence_freshness_equivalent_within_window_is_fresh_enough() {
        let report = sample_sync_convergence_equivalent_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 5, 10)
                .expect("freshness");

        assert_eq!(report.outcome, SyncConvergenceOutcome::EquivalentLocalSlice);
        assert_eq!(
            freshness,
            SyncDiagnosticFreshness::FreshEnoughLocalDiagnostic
        );
    }

    #[test]
    fn sync_convergence_freshness_equivalent_outside_window_is_stale() {
        let report = sample_sync_convergence_equivalent_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 25, 10)
                .expect("freshness");

        assert_eq!(report.outcome, SyncConvergenceOutcome::EquivalentLocalSlice);
        assert_eq!(freshness, SyncDiagnosticFreshness::StaleLocalDiagnostic);
    }

    #[test]
    fn sync_convergence_freshness_divergent_outside_window_stays_divergent_local() {
        let report = sample_sync_convergence_divergent_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 50, 10)
                .expect("freshness");

        assert_eq!(report.outcome, SyncConvergenceOutcome::DivergentLocalSlice);
        assert_eq!(freshness, SyncDiagnosticFreshness::StaleLocalDiagnostic);
        assert!(!report.is_global_truth);
        assert!(!report.is_authoritative_for_runtime);
    }

    #[test]
    fn sync_convergence_freshness_not_comparable_remains_not_comparable() {
        let report = sample_sync_convergence_not_comparable_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 50, 10)
                .expect("freshness");

        assert_eq!(
            report.outcome,
            SyncConvergenceOutcome::NotComparableLocalSlice
        );
        assert_ne!(report.outcome, SyncConvergenceOutcome::DivergentLocalSlice);
        assert_eq!(freshness, SyncDiagnosticFreshness::StaleLocalDiagnostic);
    }

    #[test]
    fn sync_convergence_freshness_before_window_end_is_not_assessable() {
        let report = sample_sync_convergence_equivalent_report();
        let freshness = classify_sync_convergence_diagnostic_freshness(
            &report,
            report.until_ts_ms.saturating_sub(1),
            10,
        )
        .expect("freshness");

        assert_eq!(freshness, SyncDiagnosticFreshness::FreshnessNotAssessable);
    }

    #[test]
    fn sync_convergence_freshness_rejects_observed_timestamp_out_of_persistable_range() {
        let report = sample_sync_convergence_equivalent_report();
        let result = classify_sync_convergence_diagnostic_freshness(
            &report,
            (i64::MAX as u64).saturating_add(1),
            10,
        );

        assert_eq!(
            result,
            Err(MeshContractError::TimestampOutOfPersistableRange {
                field: "observed_at_ts_ms",
                value: (i64::MAX as u64).saturating_add(1),
            })
        );
    }

    #[test]
    fn sync_convergence_freshness_classification_is_deterministic() {
        let report = sample_sync_convergence_divergent_report();
        let freshness_a =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 7, 10)
                .expect("freshness a");
        let freshness_b =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 7, 10)
                .expect("freshness b");

        assert_eq!(freshness_a, freshness_b);
    }

    #[test]
    fn sync_convergence_freshness_stays_diagnostic_only_not_authoritative() {
        let report = sample_sync_convergence_equivalent_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 5, 10)
                .expect("freshness");
        let surface = classify_sync_convergence_harness_truth_surface(&report);

        assert_eq!(
            freshness,
            SyncDiagnosticFreshness::FreshEnoughLocalDiagnostic
        );
        assert!(!surface.is_authoritative_for_runtime);
        assert!(!surface.is_global_truth);
    }

    #[test]
    fn sync_convergence_actionability_equivalent_local_slice_is_not_automatic_action() {
        let report = sample_sync_convergence_equivalent_report();
        let actionability = classify_sync_convergence_harness_actionability(&report);

        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
        assert!(!report.is_authoritative_for_runtime);
        assert!(!report.is_global_truth);
    }

    #[test]
    fn sync_convergence_actionability_divergent_local_slice_is_not_automatic_action() {
        let report = sample_sync_convergence_divergent_report();
        let actionability = classify_sync_convergence_harness_actionability(&report);

        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
        assert_eq!(report.outcome, SyncConvergenceOutcome::DivergentLocalSlice);
    }

    #[test]
    fn sync_convergence_actionability_not_comparable_local_slice_is_not_automatic_action() {
        let report = sample_sync_convergence_not_comparable_report();
        let actionability = classify_sync_convergence_harness_actionability(&report);

        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
        assert_eq!(
            report.outcome,
            SyncConvergenceOutcome::NotComparableLocalSlice
        );
    }

    #[test]
    fn sync_freshness_actionability_fresh_enough_is_not_automatic_action() {
        let actionability = classify_sync_diagnostic_freshness_actionability(
            SyncDiagnosticFreshness::FreshEnoughLocalDiagnostic,
        );

        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
    }

    #[test]
    fn sync_freshness_actionability_stale_is_not_automatic_action() {
        let actionability = classify_sync_diagnostic_freshness_actionability(
            SyncDiagnosticFreshness::StaleLocalDiagnostic,
        );

        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
    }

    #[test]
    fn sync_freshness_actionability_not_assessable_is_not_automatic_action() {
        let actionability = classify_sync_diagnostic_freshness_actionability(
            SyncDiagnosticFreshness::FreshnessNotAssessable,
        );

        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
    }

    #[test]
    fn operational_signal_actionability_is_not_automatic_action() {
        let surface =
            classify_bandwidth_minimal_sync_digest_truth_surface(&sample_bandwidth_digest());
        let actionability = classify_operational_truth_surface_actionability(&surface);

        assert_eq!(surface.kind, OperationalTruthKind::OperationalSignal);
        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
    }

    #[test]
    fn derived_diagnostic_actionability_is_not_automatic_action() {
        let surface = classify_sync_convergence_harness_truth_surface(
            &sample_sync_convergence_equivalent_report(),
        );
        let actionability = classify_operational_truth_surface_actionability(&surface);

        assert_eq!(surface.kind, OperationalTruthKind::DerivedDiagnostic);
        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
    }

    #[test]
    fn local_evidence_actionability_is_not_automatic_action() {
        let surface =
            classify_accepted_state_witness_truth_surface(&sample_accepted_state_witness());
        let actionability = classify_operational_truth_surface_actionability(&surface);

        assert_eq!(surface.kind, OperationalTruthKind::LocalEvidence);
        assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
        assert!(!surface.is_authoritative_for_runtime);
        assert!(!surface.is_global_truth);
    }

    #[test]
    fn contract_truth_actionability_requires_explicit_runtime_contract() {
        let surface = classify_relay_neutrality_contract_surface();
        let actionability = classify_operational_truth_surface_actionability(&surface);

        assert_eq!(surface.kind, OperationalTruthKind::ContractTruth);
        assert_eq!(
            actionability,
            MeshDiagnosticActionability::RequiresExplicitRuntimeContract
        );
        assert!(!surface.is_authoritative_for_runtime);
        assert!(!surface.is_global_truth);
    }

    #[test]
    fn diagnostic_actionability_classification_is_deterministic() {
        let report = sample_sync_convergence_equivalent_report();
        let report_a = classify_sync_convergence_harness_actionability(&report);
        let report_b = classify_sync_convergence_harness_actionability(&report);

        let freshness_a = classify_sync_diagnostic_freshness_actionability(
            SyncDiagnosticFreshness::StaleLocalDiagnostic,
        );
        let freshness_b = classify_sync_diagnostic_freshness_actionability(
            SyncDiagnosticFreshness::StaleLocalDiagnostic,
        );

        let surface = classify_sync_convergence_harness_truth_surface(&report);
        let surface_a = classify_operational_truth_surface_actionability(&surface);
        let surface_b = classify_operational_truth_surface_actionability(&surface);

        assert_eq!(report_a, report_b);
        assert_eq!(freshness_a, freshness_b);
        assert_eq!(surface_a, surface_b);
    }

    #[test]
    fn two_snapshot_sync_economics_equivalent_record_is_conservative_and_non_authoritative() {
        let report = sample_sync_convergence_equivalent_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 5, 10)
                .expect("freshness");

        let record = build_two_snapshot_sync_economics_record(
            "comparable_equivalent_fresh",
            &report,
            Some(freshness),
        )
        .expect("record");

        assert_eq!(record.comparability, SyncSliceComparability::Comparable);
        assert_eq!(record.outcome, SyncConvergenceOutcome::EquivalentLocalSlice);
        assert_eq!(
            record.schema_version,
            TWO_SNAPSHOT_SYNC_ECONOMICS_SCHEMA_VERSION
        );
        assert_eq!(record.since_ts_ms, report.since_ts_ms);
        assert_eq!(record.until_ts_ms, report.until_ts_ms);
        assert_eq!(
            record.freshness,
            Some(SyncDiagnosticFreshness::FreshEnoughLocalDiagnostic)
        );
        assert_eq!(record.left_digest_bytes, digest_summary_bytes());
        assert_eq!(record.right_digest_bytes, digest_summary_bytes());
        assert_eq!(
            record.estimated_bytes_per_event,
            ESTIMATED_FULL_SYNC_BYTES_PER_EVENT
        );
        assert_eq!(
            record.compared_digest_bytes_total,
            record.left_digest_bytes + record.right_digest_bytes
        );
        assert!(record.saved_bytes_if_sync_skipped <= record.estimated_full_sync_bytes);
        assert_eq!(
            record.diagnostic_actionability,
            MeshDiagnosticActionability::DiagnosticOnly
        );
        assert!(!record.is_runtime_authority);
        assert!(!record.is_global_truth);
    }

    #[test]
    fn two_snapshot_sync_economics_divergent_record_preserves_outcome_and_stays_diagnostic_only() {
        let report = sample_sync_convergence_divergent_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 5, 10)
                .expect("freshness");

        let record = build_two_snapshot_sync_economics_record(
            "comparable_divergent_fresh",
            &report,
            Some(freshness),
        )
        .expect("record");

        assert_eq!(record.comparability, SyncSliceComparability::Comparable);
        assert_eq!(record.outcome, SyncConvergenceOutcome::DivergentLocalSlice);
        assert_eq!(record.since_ts_ms, report.since_ts_ms);
        assert_eq!(record.until_ts_ms, report.until_ts_ms);
        assert_eq!(
            record.diagnostic_actionability,
            MeshDiagnosticActionability::DiagnosticOnly
        );
        assert_eq!(record.saved_bytes_if_sync_skipped, 0);
    }

    #[test]
    fn two_snapshot_sync_economics_not_comparable_record_preserves_not_comparable() {
        let report = sample_sync_convergence_not_comparable_report();
        let record = build_two_snapshot_sync_economics_record(
            "not_comparable_context_mismatch",
            &report,
            None,
        )
        .expect("record");

        assert_eq!(record.comparability, SyncSliceComparability::NotComparable);
        assert_eq!(
            record.outcome,
            SyncConvergenceOutcome::NotComparableLocalSlice
        );
        assert_eq!(record.since_ts_ms, report.since_ts_ms);
        assert_eq!(record.until_ts_ms, report.until_ts_ms);
        assert_eq!(record.saved_bytes_if_sync_skipped, 0);
        assert_eq!(
            record.diagnostic_actionability,
            MeshDiagnosticActionability::DiagnosticOnly
        );
    }

    #[test]
    fn two_snapshot_sync_economics_stale_diagnostic_is_recorded_conservatively() {
        let report = sample_sync_convergence_equivalent_report();
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 500, 10)
                .expect("freshness");
        let record = build_two_snapshot_sync_economics_record(
            "comparable_equivalent_stale",
            &report,
            Some(freshness),
        )
        .expect("record");

        assert_eq!(freshness, SyncDiagnosticFreshness::StaleLocalDiagnostic);
        assert_eq!(
            record.freshness,
            Some(SyncDiagnosticFreshness::StaleLocalDiagnostic)
        );
        assert_eq!(
            record.estimated_bytes_per_event,
            ESTIMATED_FULL_SYNC_BYTES_PER_EVENT
        );
        assert_eq!(record.saved_bytes_if_sync_skipped, 0);
    }

    #[test]
    fn two_snapshot_sync_economics_saved_bytes_uses_saturating_math_without_underflow() {
        let digest = BandwidthMinimalSyncDigest {
            ordering: OrderingMode::TimestampAscLocalTieBreak,
            since_ts_ms: 10,
            until_ts_ms: 20,
            event_count: 0,
            state_digest: [0xAA; 32],
        };
        let report = build_sync_convergence_harness_report_from_digests(
            SyncConvergenceScenario::Replay,
            digest.clone(),
            digest,
        );
        let freshness =
            classify_sync_convergence_diagnostic_freshness(&report, report.until_ts_ms + 1, 10)
                .expect("freshness");
        let record = build_two_snapshot_sync_economics_record(
            "zero_estimate_no_underflow",
            &report,
            Some(freshness),
        )
        .expect("record");

        assert_eq!(record.estimated_full_sync_bytes, 0);
        assert_eq!(record.saved_bytes_if_sync_skipped, 0);
    }

    #[test]
    fn two_snapshot_sync_economics_serialization_is_deterministic() {
        let records = build_two_snapshot_sync_economics_harness_records().expect("records");
        let jsonl_a =
            serialize_two_snapshot_sync_economics_records_jsonl(&records).expect("jsonl a");
        let jsonl_b =
            serialize_two_snapshot_sync_economics_records_jsonl(&records).expect("jsonl b");

        assert_eq!(jsonl_a, jsonl_b);
        assert!(jsonl_a.ends_with('\n'));
        assert_eq!(jsonl_a.lines().count(), records.len());
    }

    #[test]
    fn two_snapshot_sync_economics_artifact_schema_is_stable_and_legible() {
        let records = build_two_snapshot_sync_economics_harness_records().expect("records");
        let jsonl = serialize_two_snapshot_sync_economics_records_jsonl(&records).expect("jsonl");
        let first = jsonl.lines().next().expect("first line");
        let value: serde_json::Value = serde_json::from_str(first).expect("json");
        let object = value.as_object().expect("json object");

        for field in [
            "schema_version",
            "scenario_id",
            "since_ts_ms",
            "until_ts_ms",
            "left_event_count",
            "right_event_count",
            "left_digest_bytes",
            "right_digest_bytes",
            "compared_digest_bytes_total",
            "estimated_bytes_per_event",
            "estimated_full_sync_bytes",
            "saved_bytes_if_sync_skipped",
            "comparability",
            "outcome",
            "freshness",
            "diagnostic_actionability",
            "is_runtime_authority",
            "is_global_truth",
            "reason",
        ] {
            assert!(object.contains_key(field), "missing field {field}");
        }
        assert_eq!(
            object
                .get("schema_version")
                .and_then(serde_json::Value::as_str),
            Some(TWO_SNAPSHOT_SYNC_ECONOMICS_SCHEMA_VERSION)
        );
    }

    #[test]
    fn two_snapshot_sync_economics_harness_covers_expected_scenarios() {
        let records = build_two_snapshot_sync_economics_harness_records().expect("records");
        let ids = records
            .iter()
            .map(|record| record.scenario_id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec![
                "comparable_equivalent_fresh",
                "comparable_divergent_fresh",
                "not_comparable_context_mismatch",
                "comparable_equivalent_stale"
            ]
        );
    }

    #[test]
    fn two_snapshot_sync_economics_harness_is_deterministic_and_non_authoritative() {
        let records_a = build_two_snapshot_sync_economics_harness_records().expect("records a");
        let records_b = build_two_snapshot_sync_economics_harness_records().expect("records b");

        assert_eq!(records_a, records_b);
        assert!(records_a
            .iter()
            .all(|record| !record.is_runtime_authority && !record.is_global_truth));
        assert!(records_a
            .iter()
            .all(|record| record.diagnostic_actionability
                == MeshDiagnosticActionability::DiagnosticOnly));
    }

    #[test]
    fn two_snapshot_sync_economics_artifact_writer_emits_jsonl() {
        let records = build_two_snapshot_sync_economics_harness_records().expect("records");
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("nexo_sync_economics_{uniq}.jsonl"));
        write_two_snapshot_sync_economics_artifact_jsonl(&path, &records).expect("write");

        let jsonl = fs::read_to_string(&path).expect("read");
        assert_eq!(jsonl.lines().count(), records.len());
        assert!(jsonl.contains("comparable_equivalent_fresh"));

        fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn two_snapshot_sync_economics_default_artifact_path_is_explicit() {
        assert_eq!(
            TWO_SNAPSHOT_SYNC_ECONOMICS_ARTIFACT_PATH,
            "artifacts/sync_economics/two_snapshot_sync_economics.jsonl"
        );
    }

    #[test]
    fn replay_dedup_known_hash_is_duplicate_known_event() {
        let known = vec![sample_accepted_event("hash-1", "node_a", 100, 1)];
        let candidate = sample_accepted_event("hash-1", "node_b", 120, 4);

        let diagnostic =
            classify_mesh_replay_dedup_sequencing(&known, &candidate).expect("diagnostic");

        assert_eq!(diagnostic, MeshReplayDedupDiagnostic::DuplicateKnownEvent);
    }

    #[test]
    fn replay_dedup_new_hash_with_next_nonce_is_unique_local_candidate() {
        let known = vec![sample_accepted_event("hash-1", "node_a", 100, 1)];
        let candidate = sample_accepted_event("hash-2", "node_a", 120, 2);

        let diagnostic =
            classify_mesh_replay_dedup_sequencing(&known, &candidate).expect("diagnostic");

        assert_eq!(diagnostic, MeshReplayDedupDiagnostic::UniqueLocalCandidate);
    }

    #[test]
    fn replay_dedup_same_sender_nonce_different_hash_is_replay_suspected() {
        let known = vec![sample_accepted_event("hash-1", "node_a", 100, 9)];
        let candidate = sample_accepted_event("hash-2", "node_a", 120, 9);

        let diagnostic =
            classify_mesh_replay_dedup_sequencing(&known, &candidate).expect("diagnostic");

        assert_eq!(diagnostic, MeshReplayDedupDiagnostic::ReplaySuspected);
    }

    #[test]
    fn replay_dedup_candidate_timestamp_out_of_persistable_range_fails_closed() {
        let known = vec![sample_accepted_event("hash-1", "node_a", 100, 1)];
        let candidate =
            sample_accepted_event("hash-2", "node_a", (i64::MAX as u64).saturating_add(1), 2);

        let diagnostic = classify_mesh_replay_dedup_sequencing(&known, &candidate);

        assert_eq!(
            diagnostic,
            Err(MeshContractError::TimestampOutOfPersistableRange {
                field: "candidate.timestamp_utc_ms",
                value: (i64::MAX as u64).saturating_add(1),
            })
        );
    }

    #[test]
    fn replay_dedup_without_sender_sequence_is_not_assessable() {
        let known = vec![sample_accepted_event("hash-1", "node_b", 100, 1)];
        let candidate = sample_accepted_event("hash-2", "node_a", 120, 1);

        let diagnostic =
            classify_mesh_replay_dedup_sequencing(&known, &candidate).expect("diagnostic");

        assert_eq!(
            diagnostic,
            MeshReplayDedupDiagnostic::SequencingNotAssessable
        );
    }

    #[test]
    fn replay_dedup_classification_is_deterministic() {
        let known = vec![
            sample_accepted_event("hash-1", "node_a", 100, 1),
            sample_accepted_event("hash-2", "node_a", 120, 2),
        ];
        let candidate = sample_accepted_event("hash-3", "node_a", 140, 3);

        let first = classify_mesh_replay_dedup_sequencing(&known, &candidate)
            .expect("first classification");
        let second = classify_mesh_replay_dedup_sequencing(&known, &candidate)
            .expect("second classification");

        assert_eq!(first, second);
    }

    #[test]
    fn replay_dedup_truth_surface_is_local_only_non_authoritative() {
        let surface = classify_mesh_replay_dedup_sequencing_truth_surface(
            MeshReplayDedupDiagnostic::ReplaySuspected,
        );

        assert_eq!(surface.kind, OperationalTruthKind::LocalEvidence);
        assert!(!surface.is_authoritative_for_runtime);
        assert!(!surface.is_global_truth);
        assert!(surface.reason.contains("local evidence only"));
        assert!(surface.reason.contains("not runtime authority"));
        assert!(surface.reason.contains("not global truth"));
        assert!(surface.reason.contains("not automatic enforcement"));
    }

    #[test]
    fn replay_dedup_actionability_is_always_diagnostic_only() {
        let variants = [
            MeshReplayDedupDiagnostic::UniqueLocalCandidate,
            MeshReplayDedupDiagnostic::DuplicateKnownEvent,
            MeshReplayDedupDiagnostic::ReplaySuspected,
            MeshReplayDedupDiagnostic::SequenceRegressionSuspected,
            MeshReplayDedupDiagnostic::SequenceGapDetected,
            MeshReplayDedupDiagnostic::SequencingNotAssessable,
        ];

        for variant in variants {
            let actionability = classify_mesh_replay_dedup_sequencing_actionability(variant);
            assert_eq!(actionability, MeshDiagnosticActionability::DiagnosticOnly);
        }
    }

    #[test]
    fn replay_dedup_nonce_regression_is_sequence_regression_suspected() {
        let known = vec![sample_accepted_event("hash-1", "node_a", 100, 10)];
        let candidate = sample_accepted_event("hash-2", "node_a", 120, 8);

        let diagnostic =
            classify_mesh_replay_dedup_sequencing(&known, &candidate).expect("diagnostic");

        assert_eq!(
            diagnostic,
            MeshReplayDedupDiagnostic::SequenceRegressionSuspected
        );
    }

    #[test]
    fn replay_dedup_nonce_gap_is_sequence_gap_detected() {
        let known = vec![sample_accepted_event("hash-1", "node_a", 100, 10)];
        let candidate = sample_accepted_event("hash-2", "node_a", 120, 13);

        let diagnostic =
            classify_mesh_replay_dedup_sequencing(&known, &candidate).expect("diagnostic");

        assert_eq!(diagnostic, MeshReplayDedupDiagnostic::SequenceGapDetected);
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
        let lower = report.reason.to_ascii_lowercase();
        assert!(!lower.contains("consensus"));
        assert!(!lower.contains("global truth"));
        assert!(!lower.contains("is an automatic sync decision"));
        assert!(lower.contains("not an automatic sync decision"));
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
    fn sync_convergence_harness_rejects_until_out_of_persistable_range() {
        let messages = sample_convergence_messages();
        let report = build_sync_convergence_harness_report(
            SyncConvergenceScenario::Replay,
            &messages,
            &messages,
            0,
            (i64::MAX as u64).saturating_add(1),
        );

        assert_eq!(
            report,
            Err(MeshContractError::TimestampOutOfPersistableRange {
                field: "until_ts_ms",
                value: (i64::MAX as u64).saturating_add(1),
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
        let out_of_range = StoredMessage {
            timestamp_utc_ms: (i64::MAX as u64).saturating_add(1),
            ..message.clone()
        };
        assert!(project_stored_message_for_sync(&out_of_range, 0).is_none());
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
    fn accepted_state_witness_rejects_timestamp_out_of_persistable_range() {
        let messages = vec![StoredMessage {
            event_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            sender_id: "node_a".to_string(),
            channel: "global".to_string(),
            timestamp_utc_ms: (i64::MAX as u64).saturating_add(1),
            nonce: 1,
            content: b"overflow".to_vec(),
        }];

        let witness = build_accepted_state_witness(&messages, 0);

        assert_eq!(
            witness,
            Err(MeshContractError::TimestampOutOfPersistableRange {
                field: "message.timestamp_utc_ms",
                value: (i64::MAX as u64).saturating_add(1),
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
    fn bandwidth_minimal_sync_digest_rejects_until_out_of_persistable_range() {
        let digest =
            build_bandwidth_minimal_sync_digest(&[], 0, (i64::MAX as u64).saturating_add(1));

        assert_eq!(
            digest,
            Err(MeshContractError::TimestampOutOfPersistableRange {
                field: "until_ts_ms",
                value: (i64::MAX as u64).saturating_add(1),
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
    fn recovery_witness_rejects_relay_since_out_of_persistable_range() {
        let path = temp_db_path("nexo_recovery_invalid_relay_since");
        {
            let store = OfflineStore::open(path.to_str().expect("path")).expect("store");
            drop(store);
        }
        let conn = Connection::open(&path).expect("conn");
        conn.execute(
            "INSERT OR REPLACE INTO relay_state(key, value) VALUES (?1, ?2)",
            params![RECOVERY_WITNESS_RELAY_SINCE_KEY, u64::MAX.to_string()],
        )
        .expect("insert relay state");
        drop(conn);

        let store = OfflineStore::open(path.to_str().expect("path")).expect("store");
        let witness = build_recovery_witness(&store, &[], 0);

        assert_eq!(
            witness,
            Err(MeshContractError::TimestampOutOfPersistableRange {
                field: "relay_since_ts_ms",
                value: u64::MAX,
            })
        );
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
