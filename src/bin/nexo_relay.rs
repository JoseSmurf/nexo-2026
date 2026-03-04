#[cfg(feature = "network")]
use std::sync::Arc;

#[cfg(feature = "network")]
use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
#[cfg(feature = "network")]
use rusqlite::{params, Connection};
#[cfg(feature = "network")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "network")]
use serde_json::Value;
#[cfg(feature = "network")]
use syntax_engine::message::{
    event_hash_bytes_from_parts, signed_envelope_hash_bytes, verify_event_hash_signature,
};
#[cfg(feature = "network")]
use syntax_engine::network_udp::SignedEvent;
#[cfg(feature = "network")]
use syntax_engine::relay_client::signed_event_from_json_value;
#[cfg(all(feature = "network", test))]
use syntax_engine::relay_client::signed_event_to_json_value;

#[cfg(feature = "network")]
#[derive(Clone)]
struct RelayState {
    db_path: Arc<String>,
}

#[cfg(feature = "network")]
impl RelayState {
    fn new(db_path: String) -> Self {
        Self {
            db_path: Arc::new(db_path),
        }
    }
}

#[cfg(feature = "network")]
#[derive(Debug, Deserialize)]
struct PushRequest {
    items: Vec<Value>,
}

#[cfg(feature = "network")]
#[derive(Debug, Serialize, Deserialize)]
struct PushResponse {
    inserted: usize,
    duplicates: usize,
}

#[cfg(feature = "network")]
#[derive(Debug, Deserialize)]
struct PullQuery {
    since_ms: Option<u64>,
    limit: Option<usize>,
}

#[cfg(feature = "network")]
#[derive(Debug, Serialize, Deserialize)]
struct PullResponse {
    items: Vec<Value>,
}

#[cfg(feature = "network")]
#[derive(Debug)]
enum RelayError {
    BadRequest(String),
    Internal(String),
}

#[cfg(feature = "network")]
impl RelayError {
    fn into_status(self) -> StatusCode {
        match self {
            RelayError::BadRequest(_) => StatusCode::BAD_REQUEST,
            RelayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(feature = "network")]
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cfg = match parse_args(&args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let listener = match tokio::net::TcpListener::bind(&cfg.bind).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("bind failed: {e}");
            std::process::exit(2);
        }
    };
    let local = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| cfg.bind.clone());
    println!("nexo_relay listening on http://{local} db={}", cfg.db);

    let state = RelayState::new(cfg.db);
    if let Err(e) = axum::serve(listener, app(state)).await {
        eprintln!("server error: {e}");
        std::process::exit(2);
    }
}

#[cfg(not(feature = "network"))]
fn main() {
    eprintln!("nexo_relay requires --features network");
    std::process::exit(2);
}

#[cfg(feature = "network")]
struct RelayArgs {
    bind: String,
    db: String,
}

#[cfg(feature = "network")]
fn parse_args(args: &[String]) -> Result<RelayArgs, String> {
    let mut bind = "127.0.0.1:9100".to_string();
    let mut db = "/tmp/nexo_relay.db".to_string();
    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                let Some(v) = args.get(i + 1) else {
                    return Err("missing value for --bind".to_string());
                };
                bind = v.clone();
                i += 2;
            }
            "--db" => {
                let Some(v) = args.get(i + 1) else {
                    return Err("missing value for --db".to_string());
                };
                db = v.clone();
                i += 2;
            }
            "--help" | "-h" => {
                return Err(
                    "usage: nexo_relay [--bind 127.0.0.1:9100] [--db /tmp/nexo_relay.db]"
                        .to_string(),
                );
            }
            other => {
                return Err(format!("invalid argument: {other}"));
            }
        }
    }
    Ok(RelayArgs { bind, db })
}

#[cfg(feature = "network")]
fn app(state: RelayState) -> Router {
    Router::new()
        .route("/push", post(push_handler))
        .route("/pull", get(pull_handler))
        .with_state(state)
}

#[cfg(feature = "network")]
async fn push_handler(
    State(state): State<RelayState>,
    Json(req): Json<PushRequest>,
) -> Result<Json<PushResponse>, StatusCode> {
    let db_path = state.db_path.as_ref().clone();
    let items = req.items;
    let outcome = tokio::task::spawn_blocking(move || push_items(&db_path, items))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match outcome {
        Ok(resp) => Ok(Json(resp)),
        Err(err) => {
            match &err {
                RelayError::BadRequest(msg) | RelayError::Internal(msg) => {
                    eprintln!("relay push rejected: {msg}");
                }
            }
            Err(err.into_status())
        }
    }
}

#[cfg(feature = "network")]
async fn pull_handler(
    State(state): State<RelayState>,
    Query(query): Query<PullQuery>,
) -> Result<Json<PullResponse>, StatusCode> {
    let db_path = state.db_path.as_ref().clone();
    let since_ms = query.since_ms.unwrap_or(0);
    let limit = query.limit.unwrap_or(200).clamp(1, 200);
    let outcome = tokio::task::spawn_blocking(move || pull_items(&db_path, since_ms, limit))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    match outcome {
        Ok(items) => Ok(Json(PullResponse { items })),
        Err(err) => {
            match &err {
                RelayError::BadRequest(msg) | RelayError::Internal(msg) => {
                    eprintln!("relay pull rejected: {msg}");
                }
            }
            Err(err.into_status())
        }
    }
}

#[cfg(feature = "network")]
fn push_items(db_path: &str, items: Vec<Value>) -> Result<PushResponse, RelayError> {
    let mut conn = Connection::open(db_path)
        .map_err(|e| RelayError::Internal(format!("db open failed: {e}")))?;
    init_relay_schema(&conn)?;
    let tx = conn
        .transaction()
        .map_err(|e| RelayError::Internal(format!("tx begin failed: {e}")))?;

    let mut inserted = 0usize;
    let mut duplicates = 0usize;

    for raw in items {
        let item = signed_event_from_json_value(raw.clone()).map_err(RelayError::BadRequest)?;
        let event_hash = validate_and_event_hash(&item)?;
        let blob_json = serde_json::to_string(&raw)
            .map_err(|e| RelayError::Internal(format!("json encode failed: {e}")))?;
        let changed = tx
            .execute(
                "INSERT OR IGNORE INTO relay_events(event_hash, timestamp_ms, blob_json)
                 VALUES (?1, ?2, ?3)",
                params![event_hash, item.timestamp_utc_ms as i64, blob_json],
            )
            .map_err(|e| RelayError::Internal(format!("insert failed: {e}")))?;
        if changed == 0 {
            duplicates += 1;
        } else {
            inserted += 1;
        }
    }

    tx.commit()
        .map_err(|e| RelayError::Internal(format!("tx commit failed: {e}")))?;
    Ok(PushResponse {
        inserted,
        duplicates,
    })
}

#[cfg(feature = "network")]
fn pull_items(db_path: &str, since_ms: u64, limit: usize) -> Result<Vec<Value>, RelayError> {
    let conn = Connection::open(db_path)
        .map_err(|e| RelayError::Internal(format!("db open failed: {e}")))?;
    init_relay_schema(&conn)?;
    let mut stmt = conn
        .prepare(
            "SELECT blob_json
             FROM relay_events
             WHERE timestamp_ms >= ?1
             ORDER BY timestamp_ms ASC, rowid ASC
             LIMIT ?2",
        )
        .map_err(|e| RelayError::Internal(format!("prepare failed: {e}")))?;
    let mut rows = stmt
        .query(params![since_ms as i64, limit as i64])
        .map_err(|e| RelayError::Internal(format!("query failed: {e}")))?;

    let mut out = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| RelayError::Internal(format!("row read failed: {e}")))?
    {
        let blob: String = row
            .get(0)
            .map_err(|e| RelayError::Internal(format!("row decode failed: {e}")))?;
        let item: Value = serde_json::from_str(&blob)
            .map_err(|e| RelayError::Internal(format!("stored json invalid: {e}")))?;
        out.push(item);
    }
    Ok(out)
}

#[cfg(feature = "network")]
fn init_relay_schema(conn: &Connection) -> Result<(), RelayError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS relay_events (
            event_hash TEXT PRIMARY KEY NOT NULL,
            timestamp_ms INTEGER NOT NULL,
            blob_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_relay_events_ts ON relay_events(timestamp_ms);
        "#,
    )
    .map_err(|e| RelayError::Internal(format!("schema init failed: {e}")))?;
    Ok(())
}

#[cfg(feature = "network")]
fn validate_and_event_hash(item: &SignedEvent) -> Result<String, RelayError> {
    if item.sender_id.trim().is_empty() {
        return Err(RelayError::BadRequest("invalid sender_id".to_string()));
    }
    let signed_hash = signed_envelope_hash_bytes(
        &item.sender_id,
        item.timestamp_utc_ms,
        item.nonce,
        &item.content_hash,
        &item.origin_event_hash,
        item.hops_remaining,
    );
    if !verify_event_hash_signature(&signed_hash, &item.sender_pubkey, &item.signature) {
        return Err(RelayError::BadRequest("invalid_sig".to_string()));
    }
    let event_hash_bytes = event_hash_bytes_from_parts(
        &item.sender_id,
        item.timestamp_utc_ms,
        item.nonce,
        &item.content_hash,
    );
    Ok(blake3::Hash::from(event_hash_bytes).to_hex().to_string())
}

#[cfg(feature = "network")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use ed25519_dalek::SigningKey;
    use reqwest::Client;
    use serde_json::json;
    use tokio::net::TcpListener;

    use syntax_engine::message::{
        content_hash_bytes, event_hash_bytes_from_parts, sign_event_hash,
    };

    #[tokio::test]
    async fn relay_push_pull_is_deterministic_and_dedups() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let db_path = std::env::temp_dir().join(format!("nexo_relay_{uniq}.db"));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let app = app(RelayState::new(
            db_path.to_str().expect("db path").to_string(),
        ));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;

        let item_a = make_signed_event("node_a", 1000, 1, b"hello", 4);
        let item_b = make_signed_event("node_b", 2000, 1, b"world", 4);
        let item_a_json = signed_event_to_json_value(&item_a);
        let item_b_json = signed_event_to_json_value(&item_b);

        let client = Client::new();
        let base = format!("http://{}", addr);

        let push_1 = client
            .post(format!("{base}/push"))
            .json(&json!({ "items": [item_a_json.clone(), item_b_json.clone()] }))
            .send()
            .await
            .expect("push");
        assert_eq!(push_1.status(), StatusCode::OK);
        let push_1_json = push_1.json::<PushResponse>().await.expect("push json");
        assert_eq!(push_1_json.inserted, 2);
        assert_eq!(push_1_json.duplicates, 0);

        let pull = client
            .get(format!("{base}/pull?since_ms=0&limit=200"))
            .send()
            .await
            .expect("pull");
        assert_eq!(pull.status(), StatusCode::OK);
        let pull_json = pull.json::<PullResponse>().await.expect("pull json");
        assert_eq!(pull_json.items.len(), 2);
        let got_0 =
            signed_event_from_json_value(pull_json.items[0].clone()).expect("item0 to signed");
        let got_1 =
            signed_event_from_json_value(pull_json.items[1].clone()).expect("item1 to signed");
        assert_eq!(got_0.timestamp_utc_ms, 1000);
        assert_eq!(got_1.timestamp_utc_ms, 2000);

        let push_2 = client
            .post(format!("{base}/push"))
            .json(&json!({ "items": [item_a_json, item_b_json] }))
            .send()
            .await
            .expect("push dup");
        assert_eq!(push_2.status(), StatusCode::OK);
        let push_2_json = push_2.json::<PushResponse>().await.expect("push dup json");
        assert_eq!(push_2_json.inserted, 0);
        assert_eq!(push_2_json.duplicates, 2);

        server.abort();
        let _ = server.await;
        let _ = fs::remove_file(db_path);
    }

    fn make_signed_event(
        sender_id: &str,
        timestamp_utc_ms: u64,
        nonce: u64,
        payload: &[u8],
        hops_remaining: u8,
    ) -> SignedEvent {
        let content_hash = content_hash_bytes(payload);
        let origin_event_hash =
            event_hash_bytes_from_parts(sender_id, timestamp_utc_ms, nonce, &content_hash);
        let signing = SigningKey::from_bytes(&[11u8; 32]);
        let sender_pubkey = signing.verifying_key().to_bytes();
        let signing_bytes = signing.to_keypair_bytes();
        let envelope_hash = signed_envelope_hash_bytes(
            sender_id,
            timestamp_utc_ms,
            nonce,
            &content_hash,
            &origin_event_hash,
            hops_remaining,
        );
        let signature = sign_event_hash(&envelope_hash, &signing_bytes).expect("sign");

        SignedEvent {
            sender_id: sender_id.to_string(),
            timestamp_utc_ms,
            nonce,
            content_hash,
            origin_event_hash,
            hops_remaining,
            payload: payload.to_vec(),
            crypto_nonce: None,
            sender_pubkey,
            signature,
            known_peers: Vec::new(),
        }
    }
}
