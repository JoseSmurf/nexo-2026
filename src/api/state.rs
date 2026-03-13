use std::collections::HashSet;

#[cfg(feature = "network")]
use crate::offline_store::OfflineStore;
use serde::Serialize;

use super::{now_utc_ms, AppState, ChatSendCapability};
use crate::audit_store::AuditRecord;

#[derive(Debug, Serialize)]
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
    pub timestamp: u64,
}

pub fn build_state_response(
    state: &AppState,
    records: &[AuditRecord],
    now_sync: u64,
    now_timestamp: u64,
    chat_send: &ChatSendCapability,
    chat_message_limit: usize,
) -> StateResponse {
    let recent_events = build_state_events(records);
    let recent_ai_insights = build_state_ai_insights(records);
    let recent_chat_messages =
        load_recent_chat_messages(state.p2p_db_path.as_deref(), chat_message_limit);
    let recent_flow = build_state_flow(&recent_events, &recent_chat_messages, &recent_ai_insights);
    let (
        latest_change_kind,
        latest_change_summary,
        latest_change_origin,
        latest_change_timestamp,
        latest_change_channel,
    ) = latest_change_header(&recent_flow);
    let latest_change_source = latest_change_source(&recent_flow);
    let (
        last_operator_action_kind,
        last_operator_action_summary,
        last_operator_action_origin,
        last_operator_action_timestamp,
        last_operator_action_channel,
    ) = last_operator_action_header(&recent_flow);

    let (latest_hash, latest_type, latest_timestamp, latest_origin, latest_channel) =
        state_event_header(&recent_events);
    let ai_last_insight = recent_ai_insights
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

    StateResponse {
        system_status: "operational".to_string(),
        peers_count: unique_peer_count(records),
        relay_status,
        network_mode,
        mesh_status,
        chat_send_available: chat_send.available,
        chat_send_mode: chat_send.mode.to_string(),
        chat_send_reason: chat_send.reason.to_string(),
        write_status: write_status_from_chat_send(chat_send).to_string(),
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
        recent_events,
        recent_chat_messages,
        recent_ai_insights,
        recent_flow,
        ai_last_insight,
        recent_event_hash: latest_hash.clone(),
        last_sync: now_sync,
        last_event_hash: latest_hash,
        event_type: latest_type,
        event_timestamp: latest_timestamp,
        event_origin: latest_origin,
        event_channel: latest_channel,
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

fn state_event_header(events: &[StateEvent]) -> (Option<String>, String, u64, String, String) {
    let latest = events.first();
    if let Some(event) = latest {
        (
            Some(event.hash.clone()),
            event.r#type.clone(),
            event.timestamp,
            event.origin.clone(),
            event.channel.clone(),
        )
    } else {
        (
            None,
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
                .map(|record| record.timestamp_utc_ms)
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
