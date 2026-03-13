use std::collections::HashSet;

#[cfg(feature = "network")]
use crate::offline_store::OfflineStore;
use serde::Serialize;

use super::{now_utc_ms, AppState, ChatSendCapability};
use crate::audit_store::AuditRecord;

pub const STATE_RESPONSE_SCHEMA: &str = "nexo/state";
pub const STATE_RESPONSE_SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFieldProvenance {
    /// Field is read from Rust engine/audit/P2P sources without transformation.
    CoreVerbatim,
    /// Field is derived for presentation and diagnostics.
    Derived,
}

#[derive(Debug, Clone, Copy)]
pub struct StateFieldContract {
    pub field: &'static str,
    pub provenance: StateFieldProvenance,
    pub note: &'static str,
}

impl StateFieldContract {
    pub const fn core(field: &'static str, note: &'static str) -> Self {
        Self {
            field,
            provenance: StateFieldProvenance::CoreVerbatim,
            note,
        }
    }

    pub const fn derived(field: &'static str, note: &'static str) -> Self {
        Self {
            field,
            provenance: StateFieldProvenance::Derived,
            note,
        }
    }
}

pub const STATE_FIELD_CONTRACT: &[StateFieldContract] = &[
    StateFieldContract::derived("system_status", "fixed operational status for API surface"),
    StateFieldContract::derived("peers_count", "derived from unique non-empty audit users"),
    StateFieldContract::derived("relay_status", "read from runtime environment defaults"),
    StateFieldContract::derived("network_mode", "read from runtime environment defaults"),
    StateFieldContract::derived("mesh_status", "read from runtime environment defaults"),
    StateFieldContract::derived(
        "chat_send_available",
        "derived from runtime capability check",
    ),
    StateFieldContract::derived("chat_send_mode", "derived from runtime capability check"),
    StateFieldContract::derived("chat_send_reason", "derived from runtime capability check"),
    StateFieldContract::derived("write_status", "derived from chat_send capability"),
    StateFieldContract::derived(
        "audit_chain_status",
        "derived from recent persisted record_hash chain continuity",
    ),
    StateFieldContract::derived(
        "audit_chain_checked_records",
        "derived from recent persisted record window size",
    ),
    StateFieldContract::derived(
        "audit_chain_last_record_hash",
        "derived from latest persisted record_hash when present",
    ),
    StateFieldContract::derived(
        "audit_chain_error",
        "derived from recent persisted record_hash chain validation",
    ),
    StateFieldContract::derived("latest_change_kind", "computed from ordered recent_flow"),
    StateFieldContract::derived("latest_change_summary", "computed from ordered recent_flow"),
    StateFieldContract::derived("latest_change_origin", "computed from ordered recent_flow"),
    StateFieldContract::derived(
        "latest_change_timestamp",
        "computed from ordered recent_flow",
    ),
    StateFieldContract::derived("latest_change_channel", "computed from ordered recent_flow"),
    StateFieldContract::derived(
        "latest_change_source",
        "classified from ordered recent_flow",
    ),
    StateFieldContract::derived(
        "last_operator_action_kind",
        "extracted from ordered recent_flow",
    ),
    StateFieldContract::derived(
        "last_operator_action_summary",
        "extracted from ordered recent_flow",
    ),
    StateFieldContract::derived(
        "last_operator_action_origin",
        "extracted from ordered recent_flow",
    ),
    StateFieldContract::derived(
        "last_operator_action_timestamp",
        "extracted from ordered recent_flow",
    ),
    StateFieldContract::derived(
        "last_operator_action_channel",
        "extracted from ordered recent_flow",
    ),
    StateFieldContract::core("recent_events", "mapped directly from audit records"),
    StateFieldContract::core(
        "recent_chat_messages",
        "mapped directly from p2p message rows",
    ),
    StateFieldContract::core(
        "recent_ai_insights",
        "mapped from deterministic anomaly detector output",
    ),
    StateFieldContract::core(
        "recent_flow",
        "assembled from recent_events / insights / messages",
    ),
    StateFieldContract::derived("ai_last_insight", "first insight summary fallback-safe"),
    StateFieldContract::core(
        "recent_event_hash",
        "latest recent_events hash when present",
    ),
    StateFieldContract::derived("last_sync", "timestamp captured at API request"),
    StateFieldContract::core("last_event_hash", "latest recent_events hash when present"),
    StateFieldContract::derived("event_type", "latest event-type mapping"),
    StateFieldContract::derived("event_timestamp", "latest event timestamp mapping"),
    StateFieldContract::derived("event_origin", "latest event origin mapping"),
    StateFieldContract::derived("event_channel", "latest event channel mapping"),
    StateFieldContract::derived("timestamp", "snapshot timestamp"),
    StateFieldContract::derived("state_schema", "explicit state contract marker"),
    StateFieldContract::derived("state_schema_version", "explicit state contract marker"),
];

#[derive(Debug, Serialize, Clone)]
pub struct StateEvent {
    pub hash: String,
    #[serde(rename = "type")]
    pub r#type: String,
    pub timestamp: u64,
    pub origin: String,
    pub channel: String,
}

#[derive(Debug, Serialize)]
pub struct StateAiInsight {
    pub kind: String,
    pub summary: String,
    pub timestamp: u64,
    pub origin: String,
    pub level: String,
}

#[derive(Debug, Serialize)]
pub struct StateFlowItem {
    pub kind: String,
    pub origin: String,
    pub summary: String,
    pub timestamp: u64,
    pub hash: Option<String>,
    pub channel: String,
}

#[derive(Debug, Serialize)]
pub struct StateChatMessage {
    pub hash: String,
    pub origin: String,
    pub channel: String,
    pub text: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct StateResponse {
    pub system_status: String,
    pub peers_count: usize,
    pub relay_status: String,
    pub network_mode: String,
    pub mesh_status: String,
    pub chat_send_available: bool,
    pub chat_send_mode: String,
    pub chat_send_reason: String,
    pub write_status: String,
    pub audit_chain_status: String,
    pub audit_chain_checked_records: usize,
    pub audit_chain_last_record_hash: Option<String>,
    pub audit_chain_error: String,
    pub latest_change_kind: String,
    pub latest_change_summary: String,
    pub latest_change_origin: String,
    pub latest_change_timestamp: u64,
    pub latest_change_channel: String,
    pub latest_change_source: String,
    pub last_operator_action_kind: String,
    pub last_operator_action_summary: String,
    pub last_operator_action_origin: String,
    pub last_operator_action_timestamp: u64,
    pub last_operator_action_channel: String,
    pub recent_events: Vec<StateEvent>,
    pub recent_chat_messages: Vec<StateChatMessage>,
    pub recent_ai_insights: Vec<StateAiInsight>,
    pub recent_flow: Vec<StateFlowItem>,
    pub ai_last_insight: String,
    pub recent_event_hash: Option<String>,
    pub last_sync: u64,
    pub last_event_hash: Option<String>,
    pub event_type: String,
    pub event_timestamp: u64,
    pub event_origin: String,
    pub event_channel: String,
    pub state_schema: &'static str,
    pub state_schema_version: &'static str,
    pub timestamp: u64,
}

#[derive(Debug)]
struct StateCoreVerbatim {
    recent_events: Vec<StateEvent>,
    recent_chat_messages: Vec<StateChatMessage>,
    recent_ai_insights: Vec<StateAiInsight>,
    recent_flow: Vec<StateFlowItem>,
    latest_event: Option<StateEvent>,
    peers_count: usize,
}

#[derive(Debug)]
struct StateDerived {
    system_status: String,
    relay_status: String,
    network_mode: String,
    mesh_status: String,
    chat_send_available: bool,
    chat_send_mode: String,
    chat_send_reason: String,
    write_status: String,
    audit_chain_status: String,
    audit_chain_checked_records: usize,
    audit_chain_last_record_hash: Option<String>,
    audit_chain_error: String,
    latest_change_kind: String,
    latest_change_summary: String,
    latest_change_origin: String,
    latest_change_timestamp: u64,
    latest_change_channel: String,
    latest_change_source: String,
    last_operator_action_kind: String,
    last_operator_action_summary: String,
    last_operator_action_origin: String,
    last_operator_action_timestamp: u64,
    last_operator_action_channel: String,
    ai_last_insight: String,
    last_sync: u64,
    event_type: String,
    event_timestamp: u64,
    event_origin: String,
    event_channel: String,
    state_schema: &'static str,
    state_schema_version: &'static str,
    timestamp: u64,
}

impl StateResponse {
    fn from_parts(core: StateCoreVerbatim, derived: StateDerived) -> Self {
        Self {
            system_status: derived.system_status,
            peers_count: core.peers_count,
            relay_status: derived.relay_status,
            network_mode: derived.network_mode,
            mesh_status: derived.mesh_status,
            chat_send_available: derived.chat_send_available,
            chat_send_mode: derived.chat_send_mode,
            chat_send_reason: derived.chat_send_reason,
            write_status: derived.write_status,
            audit_chain_status: derived.audit_chain_status,
            audit_chain_checked_records: derived.audit_chain_checked_records,
            audit_chain_last_record_hash: derived.audit_chain_last_record_hash,
            audit_chain_error: derived.audit_chain_error,
            latest_change_kind: derived.latest_change_kind,
            latest_change_summary: derived.latest_change_summary,
            latest_change_origin: derived.latest_change_origin,
            latest_change_timestamp: derived.latest_change_timestamp,
            latest_change_channel: derived.latest_change_channel,
            latest_change_source: derived.latest_change_source,
            last_operator_action_kind: derived.last_operator_action_kind,
            last_operator_action_summary: derived.last_operator_action_summary,
            last_operator_action_origin: derived.last_operator_action_origin,
            last_operator_action_timestamp: derived.last_operator_action_timestamp,
            last_operator_action_channel: derived.last_operator_action_channel,
            recent_events: core.recent_events,
            recent_chat_messages: core.recent_chat_messages,
            recent_ai_insights: core.recent_ai_insights,
            recent_flow: core.recent_flow,
            ai_last_insight: derived.ai_last_insight,
            recent_event_hash: core.latest_event.as_ref().map(|event| event.hash.clone()),
            last_sync: derived.last_sync,
            last_event_hash: core.latest_event.as_ref().map(|event| event.hash.clone()),
            event_type: derived.event_type,
            event_timestamp: derived.event_timestamp,
            event_origin: derived.event_origin,
            event_channel: derived.event_channel,
            state_schema: derived.state_schema,
            state_schema_version: derived.state_schema_version,
            timestamp: derived.timestamp,
        }
    }
}

pub fn state_field_contract() -> &'static [StateFieldContract] {
    STATE_FIELD_CONTRACT
}

pub fn build_state_response(
    state: &AppState,
    records: &[AuditRecord],
    now_sync: u64,
    now_timestamp: u64,
    chat_send: &ChatSendCapability,
    chat_message_limit: usize,
) -> StateResponse {
    debug_assert!(state_field_contract().iter().all(|field| {
        !field.field.is_empty()
            && !field.note.is_empty()
            && matches!(
                field.provenance,
                StateFieldProvenance::CoreVerbatim | StateFieldProvenance::Derived
            )
    }));

    let core = build_core_state(state, records, chat_message_limit);
    let derived = build_state_derived(state, records, now_sync, now_timestamp, chat_send, &core);
    StateResponse::from_parts(core, derived)
}

fn build_core_state(
    state: &AppState,
    records: &[AuditRecord],
    chat_message_limit: usize,
) -> StateCoreVerbatim {
    let recent_events = build_state_events(records);
    let recent_ai_insights = build_state_ai_insights(records);
    let recent_chat_messages =
        load_recent_chat_messages(state.p2p_db_path.as_deref(), chat_message_limit);
    let recent_flow = build_state_flow(&recent_events, &recent_chat_messages, &recent_ai_insights);
    let latest_event = recent_events.first().cloned();

    StateCoreVerbatim {
        recent_events,
        recent_chat_messages,
        recent_ai_insights,
        recent_flow,
        latest_event,
        peers_count: unique_peer_count(records),
    }
}

fn build_state_derived(
    _state: &AppState,
    records: &[AuditRecord],
    now_sync: u64,
    now_timestamp: u64,
    chat_send: &ChatSendCapability,
    core: &StateCoreVerbatim,
) -> StateDerived {
    let audit_chain = audit_chain_summary(records);
    let (
        latest_change_kind,
        latest_change_summary,
        latest_change_origin,
        latest_change_timestamp,
        latest_change_channel,
    ) = latest_change_header(&core.recent_flow);
    let latest_change_source = latest_change_source(&core.recent_flow);
    let (
        last_operator_action_kind,
        last_operator_action_summary,
        last_operator_action_origin,
        last_operator_action_timestamp,
        last_operator_action_channel,
    ) = last_operator_action_header(&core.recent_flow);

    let (event_type, event_timestamp, event_origin, event_channel) =
        state_event_header(core.latest_event.as_ref());

    let ai_last_insight = core
        .recent_ai_insights
        .first()
        .map(|insight| insight.summary.clone())
        .unwrap_or_else(|| "No anomaly patterns observed in this window.".to_string());

    let relay_status = std::env::var("NEXO_RELAY_STATUS").unwrap_or_else(|_| "offline".to_string());
    let network_mode = std::env::var("NEXO_NETWORK_MODE")
        .unwrap_or_else(|_| "hybrid".to_string())
        .to_lowercase();
    let mesh_status = std::env::var("NEXO_MESH_STATUS")
        .unwrap_or_else(|_| "stable".to_string())
        .to_lowercase();

    StateDerived {
        system_status: "operational".to_string(),
        relay_status,
        network_mode,
        mesh_status,
        chat_send_available: chat_send.available,
        chat_send_mode: chat_send.mode.to_string(),
        chat_send_reason: chat_send.reason.to_string(),
        write_status: write_status_from_chat_send(chat_send).to_string(),
        audit_chain_status: audit_chain.status.to_string(),
        audit_chain_checked_records: audit_chain.checked_records,
        audit_chain_last_record_hash: audit_chain.last_record_hash,
        audit_chain_error: audit_chain.error,
        latest_change_kind,
        latest_change_summary,
        latest_change_origin,
        latest_change_timestamp,
        latest_change_channel,
        latest_change_source,
        last_operator_action_kind,
        last_operator_action_summary,
        last_operator_action_origin,
        last_operator_action_timestamp,
        last_operator_action_channel,
        ai_last_insight,
        last_sync: now_sync,
        event_type,
        event_timestamp,
        event_origin,
        event_channel,
        state_schema: STATE_RESPONSE_SCHEMA,
        state_schema_version: STATE_RESPONSE_SCHEMA_VERSION,
        timestamp: now_timestamp,
    }
}

fn build_state_events(records: &[AuditRecord]) -> Vec<StateEvent> {
    records
        .iter()
        .map(|record| {
            let event_type = match &record.final_decision {
                crate::FinalDecision::Approved => "system_event:approved".to_string(),
                crate::FinalDecision::Flagged => "system_event:flagged".to_string(),
                crate::FinalDecision::Blocked => "system_event:blocked".to_string(),
            };

            StateEvent {
                hash: record.audit_hash.clone(),
                r#type: event_type,
                timestamp: record.timestamp_utc_ms,
                origin: event_origin(record),
                channel: "system".to_string(),
            }
        })
        .collect()
}

fn event_origin(record: &AuditRecord) -> String {
    let user_id = record.user_id.trim();
    if user_id.is_empty() {
        "core_engine".to_string()
    } else {
        format!("user:{user_id}")
    }
}

fn state_event_header(latest_event: Option<&StateEvent>) -> (String, u64, String, String) {
    if let Some(event) = latest_event {
        (
            event.r#type.clone(),
            event.timestamp,
            event.origin.clone(),
            event.channel.clone(),
        )
    } else {
        (
            "startup".to_string(),
            0,
            "core_engine".to_string(),
            "system".to_string(),
        )
    }
}

fn build_state_ai_insights(records: &[AuditRecord]) -> Vec<StateAiInsight> {
    let amounts: Vec<f64> = records
        .iter()
        .map(|record| record.amount_cents as f64)
        .collect();

    if records.is_empty() {
        return Vec::new();
    }

    if amounts.len() == 1 {
        return vec![StateAiInsight {
            kind: "observation".to_string(),
            summary: "No anomaly patterns observed in this window.".to_string(),
            timestamp: records
                .first()
                .map(|r| r.timestamp_utc_ms)
                .unwrap_or_else(now_utc_ms),
            origin: event_origin(&records[0]),
            level: "info".to_string(),
        }];
    }

    let total: f64 = amounts.iter().sum();
    let mean = total / amounts.len() as f64;
    let variance: f64 = amounts
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / amounts.len() as f64;
    let std_dev = variance.sqrt();
    let threshold = mean + 3.0 * std_dev;

    let mut insights: Vec<StateAiInsight> = Vec::new();
    for record in records.iter() {
        if (record.amount_cents as f64) > threshold {
            insights.push(StateAiInsight {
                kind: "anomaly".to_string(),
                summary: format!(
                    "amount={} exceeds mean+3σ ({:.2})",
                    record.amount_cents, threshold
                ),
                timestamp: record.timestamp_utc_ms,
                origin: event_origin(record),
                level: "high".to_string(),
            });
        }
    }

    insights.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if insights.is_empty() {
        return vec![StateAiInsight {
            kind: "observation".to_string(),
            summary: "No anomaly patterns observed in this window.".to_string(),
            timestamp: records
                .first()
                .map(|r| r.timestamp_utc_ms)
                .unwrap_or_else(now_utc_ms),
            origin: event_origin(&records[0]),
            level: "info".to_string(),
        }];
    }

    insights.into_iter().take(3).collect()
}

fn build_state_flow(
    events: &[StateEvent],
    chat_messages: &[StateChatMessage],
    ai_insights: &[StateAiInsight],
) -> Vec<StateFlowItem> {
    let mut candidates: Vec<(u64, u8, usize, StateFlowItem)> = Vec::new();

    for (index, event) in events.iter().enumerate() {
        candidates.push((
            event.timestamp,
            0,
            index,
            StateFlowItem {
                kind: "event".to_string(),
                origin: event.origin.clone(),
                summary: describe_state_event_type(&event.r#type),
                timestamp: event.timestamp,
                hash: Some(event.hash.clone()),
                channel: event.channel.clone(),
            },
        ));
    }

    for (index, insight) in ai_insights.iter().enumerate() {
        candidates.push((
            insight.timestamp,
            1,
            index,
            StateFlowItem {
                kind: "ai".to_string(),
                origin: insight.origin.clone(),
                summary: insight.summary.clone(),
                timestamp: insight.timestamp,
                hash: None,
                channel: "ai".to_string(),
            },
        ));
    }

    for (index, message) in chat_messages.iter().enumerate() {
        candidates.push((
            message.timestamp,
            2,
            index,
            StateFlowItem {
                kind: "chat".to_string(),
                origin: message.origin.clone(),
                summary: message.text.clone(),
                timestamp: message.timestamp,
                hash: Some(message.hash.clone()),
                channel: message.channel.clone(),
            },
        ));
    }

    candidates.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.cmp(&b.2))
    });

    candidates
        .into_iter()
        .map(|(_, _, _, item)| item)
        .take(5)
        .collect()
}

fn describe_state_event_type(event_type: &str) -> String {
    match event_type {
        "system_event:approved" => "approved decision".to_string(),
        "system_event:flagged" => "flagged for review".to_string(),
        "system_event:blocked" => "blocked decision".to_string(),
        other => other.to_string(),
    }
}

#[cfg(feature = "network")]
fn load_recent_chat_messages(p2p_db_path: Option<&str>, limit: usize) -> Vec<StateChatMessage> {
    let Some(path) = p2p_db_path else {
        return Vec::new();
    };
    let path = path.trim();
    if path.is_empty() {
        return Vec::new();
    }

    let Ok(store) = OfflineStore::open(path) else {
        return Vec::new();
    };

    let Ok(messages) = store.last_messages(limit) else {
        return Vec::new();
    };

    messages
        .into_iter()
        .map(|row| StateChatMessage {
            hash: row.event_hash,
            origin: row.sender_id,
            channel: row.channel,
            text: String::from_utf8_lossy(&row.content).into_owned(),
            timestamp: row.timestamp_utc_ms,
        })
        .collect()
}

#[cfg(not(feature = "network"))]
fn load_recent_chat_messages(_p2p_db_path: Option<&str>, _limit: usize) -> Vec<StateChatMessage> {
    Vec::new()
}

struct AuditChainSummary {
    status: &'static str,
    checked_records: usize,
    last_record_hash: Option<String>,
    error: String,
}

fn audit_chain_summary(records: &[AuditRecord]) -> AuditChainSummary {
    let checked_records = records.len();
    let last_record_hash = records
        .first()
        .and_then(|record| record.record_hash.clone());

    if records.is_empty() {
        return AuditChainSummary {
            status: "empty",
            checked_records,
            last_record_hash,
            error: String::new(),
        };
    }

    for (index, record) in records.iter().enumerate() {
        if trimmed_hash(record.record_hash.as_deref()).is_none() {
            return AuditChainSummary {
                status: "broken",
                checked_records,
                last_record_hash,
                error: format!("missing record_hash at recent index {index}"),
            };
        }

        if let Some(older) = records.get(index + 1) {
            let older_hash = trimmed_hash(older.record_hash.as_deref());
            if older_hash.is_none() {
                return AuditChainSummary {
                    status: "broken",
                    checked_records,
                    last_record_hash,
                    error: format!("missing record_hash at recent index {}", index + 1),
                };
            }

            if trimmed_hash(record.prev_record_hash.as_deref()) != older_hash {
                return AuditChainSummary {
                    status: "broken",
                    checked_records,
                    last_record_hash,
                    error: format!(
                        "prev_record_hash mismatch between recent indices {index} and {}",
                        index + 1
                    ),
                };
            }
        }
    }

    AuditChainSummary {
        status: "ok",
        checked_records,
        last_record_hash,
        error: String::new(),
    }
}

fn trimmed_hash(value: Option<&str>) -> Option<&str> {
    value.and_then(|hash| {
        let trimmed = hash.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn latest_change_header(flow: &[StateFlowItem]) -> (String, String, String, u64, String) {
    let Some(item) = flow.first() else {
        return (
            String::new(),
            "No recent changes observed.".to_string(),
            "core_engine".to_string(),
            0,
            "system".to_string(),
        );
    };

    (
        item.kind.clone(),
        item.summary.clone(),
        item.origin.clone(),
        item.timestamp,
        item.channel.clone(),
    )
}

fn latest_change_source(flow: &[StateFlowItem]) -> String {
    let Some(item) = flow.first() else {
        return String::new();
    };

    if item.kind == "chat" && item.origin == "ui_dashboard" {
        return "operator_action".to_string();
    }

    if item.kind == "event"
        && matches!(
            item.summary.as_str(),
            "approved decision" | "flagged for review" | "blocked decision"
        )
    {
        return "core_decision".to_string();
    }

    "passive_observation".to_string()
}

fn last_operator_action_header(flow: &[StateFlowItem]) -> (String, String, String, u64, String) {
    if let Some(item) = flow
        .iter()
        .find(|item| item.kind == "chat" && item.origin == "ui_dashboard")
    {
        return (
            item.kind.clone(),
            item.summary.clone(),
            item.origin.clone(),
            item.timestamp,
            item.channel.clone(),
        );
    }

    (
        String::new(),
        String::new(),
        String::new(),
        0,
        String::new(),
    )
}

pub fn write_status_from_chat_send(chat_send: &ChatSendCapability) -> &'static str {
    if chat_send.available {
        "writable"
    } else {
        "read_only"
    }
}

fn unique_peer_count(records: &[AuditRecord]) -> usize {
    records
        .iter()
        .filter_map(|record| {
            let user = record.user_id.trim();
            if user.is_empty() {
                None
            } else {
                Some(user.to_string())
            }
        })
        .collect::<HashSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_store::AuditRecord;
    use crate::{FinalDecision, FinalDecision::*};
    use serde_json::json;
    use std::env;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_record(
        id: &str,
        decision: FinalDecision,
        user_id: &str,
        amount_cents: u64,
    ) -> AuditRecord {
        AuditRecord {
            request_id: format!("{id}-req"),
            calc_version: Some("plca_v1".to_string()),
            profile_name: "br_default_v1".to_string(),
            profile_version: "2026.02".to_string(),
            timestamp_utc_ms: 1_700_000_000_000 + amount_cents,
            user_id: user_id.to_string(),
            amount_cents,
            risk_bps: 1200,
            final_decision: decision,
            trace: json!(["Approved"]),
            audit_hash: format!("{}abcd", user_id),
            hash_algo: "blake3".to_string(),
            sha3_shadow: None,
            prev_record_hash: None,
            record_hash: None,
        }
    }

    #[test]
    fn state_response_exposes_contract_marker() {
        let path = std::env::temp_dir().join(format!(
            "nexo_state_contract_{}.jsonl",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos(),
        ));
        let mut state = AppState::for_tests(path.clone());
        state.p2p_db_path = None;

        let records = vec![
            sample_record("a", Approved, "alice", 10_000),
            sample_record("b", Flagged, "bob", 20_000),
            sample_record("c", Blocked, "alice", 30_000),
        ];
        let chat_send = ChatSendCapability {
            available: false,
            mode: "core_unavailable",
            reason: "network_feature_disabled",
            error_message: "",
        };

        let response = build_state_response(&state, &records, 123, 124, &chat_send, 5);

        assert_eq!(response.state_schema, STATE_RESPONSE_SCHEMA);
        assert_eq!(response.state_schema_version, STATE_RESPONSE_SCHEMA_VERSION);
        assert!(!response.recent_events.is_empty());
        assert_eq!(response.recent_events.len(), records.len());
        assert!(response.recent_flow.len() <= 5);
        assert_eq!(response.audit_chain_status, "broken");
        assert_eq!(response.audit_chain_checked_records, records.len());
        assert_eq!(response.audit_chain_last_record_hash, None);
        assert_eq!(
            response.audit_chain_error,
            "missing record_hash at recent index 0"
        );
        assert_eq!(
            response.recent_flow[0].hash,
            Some(response.recent_events[0].hash.clone())
        );

        let metadata = state_field_contract();
        assert_eq!(metadata[0].field, "system_status");
        assert_eq!(metadata.len(), STATE_FIELD_CONTRACT.len());
        assert!(metadata
            .iter()
            .any(|field| field.field == "state_schema_version"));
        assert_eq!(
            metadata
                .iter()
                .find(|field| field.field == "state_schema")
                .expect("state_schema contract")
                .provenance,
            StateFieldProvenance::Derived
        );
    }

    #[test]
    fn state_flow_shape_and_order_is_stable() {
        let event = StateEvent {
            hash: "event-hash".to_string(),
            r#type: "system_event:approved".to_string(),
            timestamp: 2,
            origin: "core_engine".to_string(),
            channel: "system".to_string(),
        };
        let message = StateChatMessage {
            hash: "chat-hash".to_string(),
            origin: "ui_dashboard".to_string(),
            channel: "global".to_string(),
            text: "hello".to_string(),
            timestamp: 1,
        };
        let insight = StateAiInsight {
            kind: "observation".to_string(),
            summary: "No anomalies".to_string(),
            timestamp: 0,
            origin: "core_engine".to_string(),
            level: "info".to_string(),
        };

        let flow = build_state_flow(&[event], &[message], &[insight]);
        assert_eq!(flow.len(), 3);
        assert_eq!(flow[0].kind, "event");
        assert_eq!(flow[1].kind, "chat");
        assert_eq!(flow[2].kind, "ai");
        assert_eq!(flow[0].timestamp, 2);
        assert_eq!(flow[0].channel, "system");
        assert_eq!(flow[1].hash.as_deref(), Some("chat-hash"));
        assert_eq!(flow[2].hash, None);
    }

    #[test]
    fn derived_fields_follow_expected_semantics_without_records() {
        let previous_network_mode = env::var_os("NEXO_NETWORK_MODE");
        let previous_mesh_status = env::var_os("NEXO_MESH_STATUS");
        let previous_relay_status = env::var_os("NEXO_RELAY_STATUS");

        env::remove_var("NEXO_NETWORK_MODE");
        env::remove_var("NEXO_MESH_STATUS");
        env::remove_var("NEXO_RELAY_STATUS");

        let path = std::env::temp_dir().join(format!(
            "nexo_state_contract_empty_{}.jsonl",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos(),
        ));
        let state = AppState::for_tests(path);

        let chat_send = ChatSendCapability {
            available: false,
            mode: "core_unavailable",
            reason: "network_feature_disabled",
            error_message: "",
        };
        let response = build_state_response(&state, &[], 10, 20, &chat_send, 5);

        assert_eq!(response.state_schema, STATE_RESPONSE_SCHEMA);
        assert_eq!(response.state_schema_version, STATE_RESPONSE_SCHEMA_VERSION);
        assert!(response.recent_events.is_empty());
        assert!(response.recent_flow.is_empty());
        assert_eq!(response.latest_change_kind, "");
        assert_eq!(
            response.latest_change_summary,
            "No recent changes observed."
        );
        assert_eq!(response.latest_change_source, "");
        assert_eq!(response.last_operator_action_kind, "");
        assert_eq!(response.last_operator_action_summary, "");
        assert_eq!(response.network_mode, "hybrid");
        assert_eq!(response.mesh_status, "stable");
        assert_eq!(response.relay_status, "offline");
        assert_eq!(response.audit_chain_status, "empty");
        assert_eq!(response.audit_chain_checked_records, 0);
        assert_eq!(response.audit_chain_last_record_hash, None);
        assert_eq!(response.audit_chain_error, "");
        assert_eq!(
            response.ai_last_insight,
            "No anomaly patterns observed in this window."
        );
        assert_eq!(response.event_type, "startup");
        assert_eq!(response.event_origin, "core_engine");
        assert_eq!(response.write_status, "read_only");

        match previous_network_mode {
            Some(v) => env::set_var("NEXO_NETWORK_MODE", v),
            None => env::remove_var("NEXO_NETWORK_MODE"),
        }
        match previous_mesh_status {
            Some(v) => env::set_var("NEXO_MESH_STATUS", v),
            None => env::remove_var("NEXO_MESH_STATUS"),
        }
        match previous_relay_status {
            Some(v) => env::set_var("NEXO_RELAY_STATUS", v),
            None => env::remove_var("NEXO_RELAY_STATUS"),
        }
    }

    #[test]
    fn state_build_path_keeps_core_and_derived_separate_outputs() {
        let path = std::env::temp_dir().join(format!(
            "nexo_state_core_derived_{}.jsonl",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos(),
        ));
        let mut state = AppState::for_tests(path);
        state.p2p_db_path = None;
        let records = vec![
            sample_record("a", Approved, "alice", 10_000),
            sample_record("b", Blocked, "bob", 20_000),
        ];
        let chat_send = ChatSendCapability {
            available: true,
            mode: "local_only",
            reason: "",
            error_message: "",
        };

        let response = build_state_response(&state, &records, 11, 22, &chat_send, 5);

        assert_eq!(response.recent_events.len(), 2);
        assert_eq!(response.recent_flow.len(), 3);
        assert_eq!(response.audit_chain_status, "broken");
        assert_eq!(response.audit_chain_checked_records, 2);
        assert_eq!(response.audit_chain_last_record_hash, None);
        assert_eq!(
            response.recent_event_hash,
            Some(records[0].audit_hash.clone())
        );
        assert_eq!(response.event_type, "system_event:approved");
        assert_eq!(response.recent_event_hash, response.last_event_hash);
        assert_eq!(response.peers_count, 2);
        assert!(response.chat_send_available);
        assert_eq!(response.chat_send_mode, "local_only");
        assert_eq!(response.state_schema, STATE_RESPONSE_SCHEMA);
        assert_eq!(response.state_schema_version, STATE_RESPONSE_SCHEMA_VERSION);
        assert_eq!(response.timestamp, 22);
    }

    #[test]
    fn state_field_contract_explicitly_separates_core_and_derived_fields() {
        let contract = state_field_contract();

        let recent_events = contract
            .iter()
            .find(|field| field.field == "recent_events")
            .expect("recent_events field contract");
        let recent_flow = contract
            .iter()
            .find(|field| field.field == "recent_flow")
            .expect("recent_flow field contract");
        let state_schema = contract
            .iter()
            .find(|field| field.field == "state_schema")
            .expect("state_schema field contract");
        let latest_change_kind = contract
            .iter()
            .find(|field| field.field == "latest_change_kind")
            .expect("latest_change_kind field contract");
        let audit_chain_status = contract
            .iter()
            .find(|field| field.field == "audit_chain_status")
            .expect("audit_chain_status field contract");

        assert_eq!(recent_events.provenance, StateFieldProvenance::CoreVerbatim);
        assert_eq!(recent_flow.provenance, StateFieldProvenance::CoreVerbatim);
        assert_eq!(state_schema.provenance, StateFieldProvenance::Derived);
        assert_eq!(latest_change_kind.provenance, StateFieldProvenance::Derived);
        assert_eq!(audit_chain_status.provenance, StateFieldProvenance::Derived);
    }

    #[test]
    fn audit_chain_summary_is_ok_for_linked_recent_records() {
        let mut older = sample_record("older", Approved, "alice", 10_000);
        older.record_hash = Some("hash-older".to_string());
        let mut newer = sample_record("newer", Approved, "alice", 20_000);
        newer.prev_record_hash = Some("hash-older".to_string());
        newer.record_hash = Some("hash-newer".to_string());

        let summary = audit_chain_summary(&[newer.clone(), older.clone()]);

        assert_eq!(summary.status, "ok");
        assert_eq!(summary.checked_records, 2);
        assert_eq!(summary.last_record_hash, newer.record_hash);
        assert_eq!(summary.error, "");
    }

    #[test]
    fn audit_chain_summary_reports_prev_hash_mismatch() {
        let mut older = sample_record("older", Approved, "alice", 10_000);
        older.record_hash = Some("hash-older".to_string());
        let mut newer = sample_record("newer", Approved, "alice", 20_000);
        newer.prev_record_hash = Some("hash-wrong".to_string());
        newer.record_hash = Some("hash-newer".to_string());

        let summary = audit_chain_summary(&[newer.clone(), older]);

        assert_eq!(summary.status, "broken");
        assert_eq!(summary.checked_records, 2);
        assert_eq!(summary.last_record_hash, newer.record_hash);
        assert_eq!(
            summary.error,
            "prev_record_hash mismatch between recent indices 0 and 1"
        );
    }
}
