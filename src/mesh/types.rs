use crate::message::validate_persistable_timestamp_ms;
use serde::{Deserialize, Serialize};

/// Declares the operational role a node may hold in the v0 mesh contract.
/// These roles describe policy and intent, not authority over the Rust core.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    MobileNode,
    StablePcNode,
    Relay,
    Observer,
}

/// Tracks the local lifecycle state of a node installation.
/// The values mirror the documentation contract and remain local-first.
#[allow(dead_code)]
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
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshEventKind {
    LiveIngress,
    SyncItem,
    RelayPullReplay,
    LocalReplay,
}

/// Describes the local outcome of applying the mesh acceptance contract.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshAcceptance {
    Accepted,
    Duplicate,
    RejectedInvalid,
    RejectedLoop,
}

/// Declares the conservative ordering mode used by a node or relay.
/// v0 stays intentionally simple and does not claim global causal ordering.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderingMode {
    TimestampAscLocalTieBreak,
    TimestampAscRelayRowTieBreak,
}

/// Minimal sync cursor used to resume pull or replay from a conservative timestamp boundary.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SyncCursor {
    pub since_ts_ms: u64,
}

impl SyncCursor {
    #[allow(dead_code)]
    pub const fn new(since_ts_ms: u64) -> Self {
        Self { since_ts_ms }
    }
}

/// Validation failure for a sync-window shape.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWindowValidationError {
    SinceOutOfPersistableRange { value: u64 },
    UntilOutOfPersistableRange { value: u64 },
    UntilBeforeSince { since_ts_ms: u64, until_ts_ms: u64 },
}

/// Minimal validated time window used for local sync diagnostics.
/// This keeps invalid window shapes out of internal mesh helpers.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncWindow {
    since_ts_ms: u64,
    until_ts_ms: u64,
}

impl SyncWindow {
    #[allow(dead_code)]
    pub fn new(since_ts_ms: u64, until_ts_ms: u64) -> Result<Self, SyncWindowValidationError> {
        validate_persistable_timestamp_ms(since_ts_ms).map_err(|_| {
            SyncWindowValidationError::SinceOutOfPersistableRange { value: since_ts_ms }
        })?;
        validate_persistable_timestamp_ms(until_ts_ms).map_err(|_| {
            SyncWindowValidationError::UntilOutOfPersistableRange { value: until_ts_ms }
        })?;
        if until_ts_ms < since_ts_ms {
            return Err(SyncWindowValidationError::UntilBeforeSince {
                since_ts_ms,
                until_ts_ms,
            });
        }
        Ok(Self {
            since_ts_ms,
            until_ts_ms,
        })
    }

    #[allow(dead_code)]
    pub const fn since_ts_ms(&self) -> u64 {
        self.since_ts_ms
    }

    #[allow(dead_code)]
    pub const fn until_ts_ms(&self) -> u64 {
        self.until_ts_ms
    }
}

impl TryFrom<(u64, u64)> for SyncWindow {
    type Error = SyncWindowValidationError;

    fn try_from(value: (u64, u64)) -> Result<Self, Self::Error> {
        Self::new(value.0, value.1)
    }
}

/// Lightweight reference to an event that has already been accepted locally.
/// This is a reference shape only; it does not replace the current message or relay formats.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedEventRef {
    pub event_hash: String,
    pub sender_id: String,
    pub timestamp_utc_ms: u64,
    pub nonce: u64,
    pub kind: MeshEventKind,
}

/// Deterministic summary of a local accepted-history slice.
/// This witness is local-only and does not claim global truth or full convergence.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedStateWitness {
    pub ordering: OrderingMode,
    pub since_ts_ms: u64,
    pub event_count: u64,
    pub first_event_hash: Option<[u8; 32]>,
    pub last_event_hash: Option<[u8; 32]>,
    pub state_digest: [u8; 32],
}

/// Conservative local continuity classification for recovery inspection.
/// `RestoredValid` exists for the contract shape but remains reserved until explicit restore evidence exists.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryClassification {
    NewNode,
    Intact,
    RestoredValid,
    Ambiguous,
    Invalid,
}

/// Deterministic summary of the local evidence available for node continuity.
/// This witness is read-only and does not govern runtime restore or rejoin decisions.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryWitness {
    pub classification: RecoveryClassification,
    pub identity_fingerprint: Option<[u8; 32]>,
    pub relay_since_ts_ms: Option<u64>,
    pub accepted_state: AcceptedStateWitness,
    pub continuity_digest: [u8; 32],
}

/// Minimal digest shape used to compare accepted-history windows with low bandwidth cost.
/// This summary is local-only and does not decide sync runtime behavior.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthMinimalSyncDigest {
    pub ordering: OrderingMode,
    pub since_ts_ms: u64,
    pub until_ts_ms: u64,
    pub event_count: u64,
    /// Do not compare this field in isolation.
    /// Valid digest equality must use the full summary through
    /// `compare_bandwidth_minimal_sync_digest`.
    pub state_digest: [u8; 32],
}

/// Result of comparing two bandwidth-minimal digest summaries.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BandwidthDigestComparison {
    ExactMatch,
    Different,
}

/// Classifies the semantic confidence level of a mesh-facing surface.
/// This keeps contract truth separate from local evidence and operational diagnostics.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationalTruthKind {
    ContractTruth,
    LocalEvidence,
    OperationalSignal,
    DerivedDiagnostic,
}

/// Describes how a mesh surface should be interpreted by operators and future runtime integration.
/// This is intentionally conservative: it prevents local/diagnostic artifacts from being treated as
/// global truth or automatic runtime authority.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalTruthSurface {
    pub kind: OperationalTruthKind,
    pub source_label: String,
    pub is_authoritative_for_runtime: bool,
    pub is_global_truth: bool,
    pub reason: String,
}

/// Identifies the simulated continuity context for a read-only convergence harness run.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncConvergenceScenario {
    Replay,
    Restart,
    Rejoin,
}

/// Local-only outcome of comparing two accepted-history slices in the same window.
#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncConvergenceOutcome {
    EquivalentLocalSlice,
    DivergentLocalSlice,
    NotComparableLocalSlice,
}

/// Declares whether two local sync slices can be compared semantically.
/// Comparability is intentionally minimal and based on shared ordering + window context.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncSliceComparability {
    Comparable,
    NotComparable,
}

/// Describes whether a local convergence diagnostic is still recent enough to be useful.
/// Freshness is diagnostic-only and must not be treated as runtime authority or global truth.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncDiagnosticFreshness {
    FreshEnoughLocalDiagnostic,
    StaleLocalDiagnostic,
    FreshnessNotAssessable,
}

/// Declares whether a mesh diagnostic output can drive runtime behavior.
/// Diagnostic output is not a runtime decision, not sync authority, and not global truth.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshDiagnosticActionability {
    DiagnosticOnly,
    RequiresExplicitRuntimeContract,
}

/// Conservative replay/dedup/sequencing diagnostic for local mesh evidence.
/// This diagnostic is local evidence only and cannot be interpreted as runtime authority.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeshReplayDedupDiagnostic {
    UniqueLocalCandidate,
    DuplicateKnownEvent,
    ReplaySuspected,
    SequenceRegressionSuspected,
    SequenceGapDetected,
    SequencingNotAssessable,
}

/// Read-only report produced by the sync-convergence harness for controlled scenarios.
/// This shape is intentionally conservative and does not claim global convergence.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncConvergenceHarnessReport {
    pub scenario: SyncConvergenceScenario,
    pub since_ts_ms: u64,
    pub until_ts_ms: u64,
    pub left: BandwidthMinimalSyncDigest,
    pub right: BandwidthMinimalSyncDigest,
    pub comparability: SyncSliceComparability,
    pub comparison: BandwidthDigestComparison,
    pub outcome: SyncConvergenceOutcome,
    pub is_authoritative_for_runtime: bool,
    pub is_global_truth: bool,
    pub reason: String,
}

/// Canonical read-only artifact record for two-snapshot sync economics.
/// Rust is the source of truth for this schema and exported values.
/// Julia consumers should only read/analyze these records (means/medians/percentiles/ratios),
/// without reinterpreting them as runtime authority or global truth.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoSnapshotSyncEconomicsRecord {
    pub scenario_id: String,
    pub left_event_count: u64,
    pub right_event_count: u64,
    pub left_digest_bytes: u64,
    pub right_digest_bytes: u64,
    pub compared_digest_bytes_total: u64,
    pub estimated_full_sync_bytes: u64,
    pub saved_bytes_if_sync_skipped: u64,
    pub comparability: SyncSliceComparability,
    pub outcome: SyncConvergenceOutcome,
    pub freshness: Option<SyncDiagnosticFreshness>,
    pub diagnostic_actionability: MeshDiagnosticActionability,
    pub is_runtime_authority: bool,
    pub is_global_truth: bool,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::{SyncWindow, SyncWindowValidationError};

    #[test]
    fn sync_window_accepts_equal_bounds() {
        let window = SyncWindow::new(10, 10).expect("window");
        assert_eq!(window.since_ts_ms(), 10);
        assert_eq!(window.until_ts_ms(), 10);
    }

    #[test]
    fn sync_window_accepts_increasing_bounds() {
        let window = SyncWindow::new(10, 20).expect("window");
        assert_eq!(window.since_ts_ms(), 10);
        assert_eq!(window.until_ts_ms(), 20);
    }

    #[test]
    fn sync_window_rejects_until_before_since() {
        let result = SyncWindow::new(20, 10);
        assert_eq!(
            result,
            Err(SyncWindowValidationError::UntilBeforeSince {
                since_ts_ms: 20,
                until_ts_ms: 10
            })
        );
    }

    #[test]
    fn sync_window_rejects_since_out_of_persistable_range() {
        let result = SyncWindow::new((i64::MAX as u64).saturating_add(1), i64::MAX as u64);
        assert_eq!(
            result,
            Err(SyncWindowValidationError::SinceOutOfPersistableRange {
                value: (i64::MAX as u64).saturating_add(1)
            })
        );
    }

    #[test]
    fn sync_window_rejects_until_out_of_persistable_range() {
        let result = SyncWindow::new(0, (i64::MAX as u64).saturating_add(1));
        assert_eq!(
            result,
            Err(SyncWindowValidationError::UntilOutOfPersistableRange {
                value: (i64::MAX as u64).saturating_add(1)
            })
        );
    }
}
