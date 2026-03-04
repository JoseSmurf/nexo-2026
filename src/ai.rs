use std::collections::BTreeMap;
use std::io::BufRead;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::analyzer::{analyze_bytes, deterministic_ai_response};
use crate::message::CanonicalMessage;
use crate::offline_store::{OfflineStore, RawMessageInput, StoreInsertStatus};

#[derive(Debug)]
pub struct AiArgs {
    pub db: String,
    pub sender: String,
}

pub async fn run_ai(args: AiArgs) -> Result<(), String> {
    let store = OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
    let mut stdin = std::io::stdin().lock();
    let mut line = String::new();
    let n = stdin
        .read_line(&mut line)
        .map_err(|e| format!("stdin read failed: {e}"))?;
    if n == 0 {
        return Err("missing prompt from stdin".to_string());
    }
    let prompt = line.trim_end_matches(['\r', '\n']).to_string();
    let response = process_ai_prompt(&store, &args.sender, &prompt, now_utc_ms(), 120_000)?;
    println!("{}", response);
    Ok(())
}

pub fn parse_ai(args: &[String]) -> Result<AiArgs, String> {
    let flags = parse_flags(args)?;
    let db = required(&flags, "db")?;
    let sender = required(&flags, "sender")?;
    Ok(AiArgs { db, sender })
}

pub(crate) fn process_ai_prompt(
    store: &OfflineStore,
    sender: &str,
    prompt: &str,
    now_ms: u64,
    seen_ttl_ms: u64,
) -> Result<String, String> {
    validate_input_bytes(prompt)?;
    let prompt_nonce = store
        .next_nonce(sender)
        .map_err(|e| format!("next_nonce failed: {e}"))?;
    let prompt_msg = CanonicalMessage::new_with_nonce(
        sender.to_string(),
        now_ms,
        prompt_nonce,
        prompt.as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    store
        .insert_message_with_channel(&prompt_msg, "global", now_ms, seen_ttl_ms)
        .map_err(|e| format!("store prompt failed: {e}"))?;

    let response = deterministic_ai_response(prompt.as_bytes());
    let ai_now = now_ms.saturating_add(1);
    let ai_nonce = store
        .next_nonce("ai")
        .map_err(|e| format!("next_nonce ai failed: {e}"))?;
    store
        .insert_raw_message_with_channel(
            RawMessageInput {
                sender_id: "ai",
                timestamp_utc_ms: ai_now,
                nonce: ai_nonce,
                content: response.as_bytes(),
                channel: "ai",
            },
            ai_now,
            seen_ttl_ms,
        )
        .map_err(|e| format!("store ai response failed: {e}"))?;

    Ok(response)
}

pub(crate) fn build_repetition_insight(topic: &str, repeats: usize, intent: &str) -> String {
    format!(
        "deterministic_ai insight=repetition topic={} repeats={} intent={} action=observe_global",
        topic, repeats, intent
    )
}

pub fn maybe_generate_ai_insight_for_global(
    store: &OfflineStore,
    msg: &CanonicalMessage,
    status: StoreInsertStatus,
    now_ms: u64,
    seen_ttl_ms: u64,
) -> Result<Option<String>, String> {
    if status != StoreInsertStatus::Inserted {
        return Ok(None);
    }

    let msg_analysis = analyze_bytes(&msg.content);
    if msg_analysis.topics.is_empty() {
        return Ok(None);
    }

    let globals = store
        .last_messages_by_channel("global", 1000)
        .map_err(|e| format!("last_messages_by_channel failed: {e}"))?;
    let mut counts = BTreeMap::<String, usize>::new();
    for row in globals {
        let analysis = analyze_bytes(&row.content);
        for topic in analysis.topics {
            let entry = counts.entry(topic).or_insert(0);
            *entry = entry.saturating_add(1);
        }
    }

    let mut repeated: Vec<(String, usize)> = counts.into_iter().filter(|(_, c)| *c >= 3).collect();
    if repeated.is_empty() {
        return Ok(None);
    }
    repeated.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let (topic, repeats) = repeated[0].clone();
    let insight = build_repetition_insight(&topic, repeats, msg_analysis.intent);

    let ai_ts = now_ms.saturating_add(1);
    let ai_nonce = store
        .next_nonce("ai")
        .map_err(|e| format!("next_nonce ai failed: {e}"))?;
    let ai_status = store
        .insert_raw_message_with_channel(
            RawMessageInput {
                sender_id: "ai",
                timestamp_utc_ms: ai_ts,
                nonce: ai_nonce,
                content: insight.as_bytes(),
                channel: "ai",
            },
            ai_ts,
            seen_ttl_ms,
        )
        .map_err(|e| format!("store ai insight failed: {e}"))?;
    if ai_status == StoreInsertStatus::Inserted {
        return Ok(Some(insight));
    }
    Ok(None)
}

fn validate_input_bytes(line: &str) -> Result<(), String> {
    let bytes = line.as_bytes();
    if bytes.len() > CanonicalMessage::MAX_CONTENT_BYTES {
        return Err("content_bytes > 32".to_string());
    }
    Ok(())
}

fn now_utc_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as u64
}

fn parse_flags(args: &[String]) -> Result<std::collections::HashMap<String, String>, String> {
    let mut flags = std::collections::HashMap::new();
    let mut i = 0usize;
    while i < args.len() {
        let key = &args[i];
        if !key.starts_with("--") {
            return Err(format!("invalid argument: {key}"));
        }
        let key = key.trim_start_matches("--").to_string();
        let value = match args.get(i + 1) {
            Some(next) if !next.starts_with("--") => {
                i += 2;
                next.clone()
            }
            _ => {
                i += 1;
                "true".to_string()
            }
        };
        flags.insert(key, value);
    }
    Ok(flags)
}

fn required(
    flags: &std::collections::HashMap<String, String>,
    key: &str,
) -> Result<String, String> {
    flags
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing --{key}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_input_over_32_bytes_is_rejected() {
        let input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(validate_input_bytes(input).is_err());
    }

    #[test]
    fn ai_response_is_deterministic() {
        let store = OfflineStore::open_in_memory().expect("store");
        let a = process_ai_prompt(&store, "u1", "help invalid signature", 10_000, 1_000)
            .expect("run a");
        let b = process_ai_prompt(&store, "u2", "help invalid signature", 20_000, 1_000)
            .expect("run b");
        assert_eq!(a, b);
    }

    #[test]
    fn ai_channel_is_saved_correctly() {
        let store = OfflineStore::open_in_memory().expect("store");
        process_ai_prompt(&store, "u1", "hello", 10_000, 1_000).expect("run");
        let rows = store.last_messages(2).expect("rows");
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .any(|m| m.sender_id == "u1" && m.channel == "global"));
        assert!(rows.iter().any(|m| m.sender_id == "ai"));
        assert!(rows
            .iter()
            .any(|m| m.sender_id == "ai" && m.channel == "ai"));
    }

    #[test]
    fn same_input_yields_same_insight() {
        let a = build_repetition_insight("pix", 3, "transaction");
        let b = build_repetition_insight("pix", 3, "transaction");
        assert_eq!(a, b);
    }

    #[test]
    fn does_not_create_insight_on_duplicate() {
        let store = OfflineStore::open_in_memory().expect("store");
        let msg = CanonicalMessage::new_with_nonce("u1", 1_000, 1, b"pix").expect("msg");
        let maybe = maybe_generate_ai_insight_for_global(
            &store,
            &msg,
            StoreInsertStatus::Duplicate,
            1_000,
            1_000,
        )
        .expect("insight");
        assert!(maybe.is_none());
        let ai_rows = store.last_messages_by_channel("ai", 10).expect("ai rows");
        assert!(ai_rows.is_empty());
    }

    #[test]
    fn creates_insight_when_topic_repeats_three_times() {
        let store = OfflineStore::open_in_memory().expect("store");
        for i in 0..3u64 {
            let msg =
                CanonicalMessage::new_with_nonce("u1", 10_000 + i, i + 1, b"pix").expect("msg");
            let status = store
                .insert_message(&msg, 10_000 + i, 1_000)
                .expect("insert");
            let maybe =
                maybe_generate_ai_insight_for_global(&store, &msg, status, 10_000 + i, 1_000)
                    .expect("insight");
            if i < 2 {
                assert!(maybe.is_none());
            } else {
                assert!(maybe.is_some());
            }
        }
        let ai_rows = store.last_messages_by_channel("ai", 10).expect("ai rows");
        assert!(!ai_rows.is_empty());
    }
}
