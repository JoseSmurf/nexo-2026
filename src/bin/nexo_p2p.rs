#[cfg(feature = "network")]
mod network_cli {
    use std::collections::HashMap;
    use std::io::BufRead;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use syntax_engine::message::{event_hash, event_hash_bytes, CanonicalMessage};
    use syntax_engine::network_udp::UdpNode;
    use syntax_engine::offline_store::{OfflineStore, StoreInsertStatus};

    #[derive(Debug)]
    pub struct ListenArgs {
        bind: String,
        db: String,
        seen_ttl_ms: u64,
    }

    #[derive(Debug)]
    pub struct SendArgs {
        bind: String,
        peer: SocketAddr,
        sender: String,
        msg: String,
        retries: u8,
        ack_timeout_ms: u64,
        db: String,
        seen_ttl_ms: u64,
    }

    #[derive(Debug)]
    pub struct ChatArgs {
        bind: String,
        peer: SocketAddr,
        sender: String,
        db: String,
        retries: u8,
        ack_timeout_ms: u64,
        seen_ttl_ms: u64,
    }

    pub fn usage() -> &'static str {
        "nexo_p2p (network feature)\n\
         usage:\n\
          nexo_p2p listen --bind 127.0.0.1:9001 --db /tmp/nexo_a.db [--seen-ttl-ms 120000]\n\
          nexo_p2p send --bind 127.0.0.1:9002 --peer 127.0.0.1:9001 --sender node_b --msg \"hello\" --db /tmp/nexo_b.db [--retries 3] [--ack-timeout-ms 200] [--seen-ttl-ms 120000]\n\
          nexo_p2p chat --bind 127.0.0.1:9001 --peer 127.0.0.1:9002 --sender node_a --db /tmp/nexo_a.db [--retries 3] [--ack-timeout-ms 200] [--seen-ttl-ms 120000]"
    }

    fn chat_help() -> &'static str {
        "chat commands: /help /id /last N /quit"
    }

    pub fn parse_listen(args: &[String]) -> Result<ListenArgs, String> {
        let flags = parse_flags(args)?;
        let bind = required(&flags, "bind")?;
        let db = required(&flags, "db")?;
        let seen_ttl_ms = parse_u64(flags.get("seen-ttl-ms"), 120_000, "seen-ttl-ms")?;
        Ok(ListenArgs {
            bind,
            db,
            seen_ttl_ms,
        })
    }

    pub fn parse_send(args: &[String]) -> Result<SendArgs, String> {
        let flags = parse_flags(args)?;
        let bind = required(&flags, "bind")?;
        let peer = required(&flags, "peer")?
            .parse::<SocketAddr>()
            .map_err(|_| "invalid --peer socket addr".to_string())?;
        let sender = required(&flags, "sender")?;
        let msg = required(&flags, "msg")?;
        let db = required(&flags, "db")?;
        let retries = parse_u8(flags.get("retries"), 3, "retries")?;
        let ack_timeout_ms = parse_u64(flags.get("ack-timeout-ms"), 200, "ack-timeout-ms")?;
        let seen_ttl_ms = parse_u64(flags.get("seen-ttl-ms"), 120_000, "seen-ttl-ms")?;
        Ok(SendArgs {
            bind,
            peer,
            sender,
            msg,
            retries,
            ack_timeout_ms,
            db,
            seen_ttl_ms,
        })
    }

    pub fn parse_chat(args: &[String]) -> Result<ChatArgs, String> {
        let flags = parse_flags(args)?;
        let bind = required(&flags, "bind")?;
        let peer = required(&flags, "peer")?
            .parse::<SocketAddr>()
            .map_err(|_| "invalid --peer socket addr".to_string())?;
        let sender = required(&flags, "sender")?;
        let db = required(&flags, "db")?;
        let retries = parse_u8(flags.get("retries"), 3, "retries")?;
        let ack_timeout_ms = parse_u64(flags.get("ack-timeout-ms"), 200, "ack-timeout-ms")?;
        let seen_ttl_ms = parse_u64(flags.get("seen-ttl-ms"), 120_000, "seen-ttl-ms")?;
        Ok(ChatArgs {
            bind,
            peer,
            sender,
            db,
            retries,
            ack_timeout_ms,
            seen_ttl_ms,
        })
    }

    pub async fn run_listen(args: ListenArgs) -> Result<(), String> {
        let node = UdpNode::bind(&args.bind)
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let store = OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
        println!("listening on {} db={}", args.bind, args.db);

        loop {
            let (msg, from) = node
                .recv_event()
                .await
                .map_err(|e| format!("recv failed: {e}"))?;
            let now = now_utc_ms();
            let ehash = event_hash(&msg);
            let inserted = store
                .insert_message(&msg, now, args.seen_ttl_ms)
                .map_err(|e| format!("store insert failed: {e}"))?;
            match inserted {
                StoreInsertStatus::Inserted => {
                    println!(
                        "recv inserted sender={} ts={} nonce={} content_bytes={:?} event_hash={}",
                        msg.sender_id, msg.timestamp_utc_ms, msg.nonce, msg.content, ehash
                    );
                }
                StoreInsertStatus::Duplicate => {
                    println!("recv duplicate event_hash={}", ehash);
                }
            }

            node.send_ack(from, event_hash_bytes(&msg))
                .await
                .map_err(|e| format!("ack failed: {e}"))?;
        }
    }

    pub async fn run_send(args: SendArgs) -> Result<(), String> {
        let node = UdpNode::bind(&args.bind)
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let store = OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;

        validate_chat_input_bytes(&args.msg)?;
        let now = now_utc_ms();
        let nonce = store
            .next_nonce(&args.sender)
            .map_err(|e| format!("next_nonce failed: {e}"))?;
        let msg = CanonicalMessage::new_with_nonce(args.sender, now, nonce, args.msg.as_bytes())
            .map_err(|e| e.to_string())?;
        let ehash = event_hash(&msg);
        node.send_with_ack(
            args.peer,
            &msg,
            args.retries,
            Duration::from_millis(args.ack_timeout_ms),
        )
        .await
        .map_err(|e| format!("send_with_ack failed: {e}"))?;
        println!(
            "sent ok peer={} event_hash={} bytes={:?}",
            args.peer, ehash, msg.content
        );

        let status = store
            .insert_message(&msg, now_utc_ms(), args.seen_ttl_ms)
            .map_err(|e| format!("store insert failed: {e}"))?;
        println!("stored local {:?} db={}", status, args.db);

        Ok(())
    }

    pub async fn run_chat(args: ChatArgs) -> Result<(), String> {
        let recv_bind = args.bind.clone();
        let recv_db = args.db.clone();
        let recv_ttl = args.seen_ttl_ms;
        let recv_task = tokio::spawn(async move {
            let node = UdpNode::bind(&recv_bind)
                .await
                .map_err(|e| format!("bind failed: {e}"))?;
            let store = OfflineStore::open(&recv_db).map_err(|e| format!("db open failed: {e}"))?;
            loop {
                let (msg, from) = node
                    .recv_event()
                    .await
                    .map_err(|e| format!("recv failed: {e}"))?;
                let now = now_utc_ms();
                let inserted = store
                    .insert_message(&msg, now, recv_ttl)
                    .map_err(|e| format!("store insert failed: {e}"))?;
                match inserted {
                    StoreInsertStatus::Inserted => {
                        println!("[{}] {}", msg.sender_id, render_content(&msg.content));
                    }
                    StoreInsertStatus::Duplicate => {
                        println!("[dup] {}", event_hash(&msg));
                    }
                }
                node.send_ack(from, event_hash_bytes(&msg))
                    .await
                    .map_err(|e| format!("ack failed: {e}"))?;
            }
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        });

        println!(
            "chat ready: bind={} peer={} sender={} db={} (/help /id /last N /quit)",
            args.bind, args.peer, args.sender, args.db
        );

        let stdin = std::io::stdin();
        let mut stdin = stdin.lock();
        let mut line = String::new();

        loop {
            line.clear();
            let n = stdin
                .read_line(&mut line)
                .map_err(|e| format!("stdin read failed: {e}"))?;
            if n == 0 {
                break;
            }
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }

            if line == "/quit" {
                break;
            }
            if line == "/help" {
                println!("{}", chat_help());
                continue;
            }
            if line == "/id" {
                println!(
                    "sender={} bind={} peer={}",
                    args.sender, args.bind, args.peer
                );
                continue;
            }
            if let Some(rest) = line.strip_prefix("/last ") {
                let count = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid /last N value".to_string())?;
                let store =
                    OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
                let items = store
                    .last_messages(count)
                    .map_err(|e| format!("last_messages failed: {e}"))?;
                for item in items {
                    println!(
                        "[{}] {} (ts={} hash={})",
                        item.sender_id,
                        render_content(&item.content),
                        item.timestamp_utc_ms,
                        item.event_hash
                    );
                }
                continue;
            }

            if let Err(e) = validate_chat_input_bytes(&line) {
                println!("rejected: {e}");
                continue;
            }

            let store = OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
            let nonce = store
                .next_nonce(&args.sender)
                .map_err(|e| format!("next_nonce failed: {e}"))?;
            let now = now_utc_ms();
            let msg =
                CanonicalMessage::new_with_nonce(args.sender.clone(), now, nonce, line.as_bytes())
                    .map_err(|e| e.to_string())?;

            let sender_node = UdpNode::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("bind failed: {e}"))?;
            match sender_node
                .send_with_ack(
                    args.peer,
                    &msg,
                    args.retries,
                    Duration::from_millis(args.ack_timeout_ms),
                )
                .await
            {
                Ok(()) => {
                    let status = store
                        .insert_message(&msg, now_utc_ms(), args.seen_ttl_ms)
                        .map_err(|e| format!("store insert failed: {e}"))?;
                    println!("sent ok {:?} nonce={}", status, msg.nonce);
                }
                Err(e) => {
                    println!("timeout: {e}");
                }
            }
        }

        recv_task.abort();
        let _ = recv_task.await;
        Ok(())
    }

    fn parse_flags(args: &[String]) -> Result<HashMap<String, String>, String> {
        let mut flags = HashMap::new();
        let mut i = 0usize;
        while i < args.len() {
            let key = &args[i];
            if !key.starts_with("--") {
                return Err(format!("invalid argument: {key}"));
            }
            let key = key.trim_start_matches("--").to_string();
            let Some(value) = args.get(i + 1) else {
                return Err(format!("missing value for --{key}"));
            };
            flags.insert(key, value.clone());
            i += 2;
        }
        Ok(flags)
    }

    fn required(flags: &HashMap<String, String>, key: &str) -> Result<String, String> {
        flags
            .get(key)
            .cloned()
            .ok_or_else(|| format!("missing --{key}"))
    }

    fn parse_u64(raw: Option<&String>, default: u64, key: &str) -> Result<u64, String> {
        match raw {
            Some(v) => v
                .parse::<u64>()
                .map_err(|_| format!("invalid --{key} value")),
            None => Ok(default),
        }
    }

    fn parse_u8(raw: Option<&String>, default: u8, key: &str) -> Result<u8, String> {
        match raw {
            Some(v) => v
                .parse::<u8>()
                .map_err(|_| format!("invalid --{key} value")),
            None => Ok(default),
        }
    }

    fn validate_chat_input_bytes(line: &str) -> Result<(), String> {
        let bytes = line.as_bytes();
        if bytes.len() > CanonicalMessage::MAX_CONTENT_BYTES {
            return Err("content_bytes > 32".to_string());
        }
        Ok(())
    }

    fn render_content(content: &[u8]) -> String {
        match std::str::from_utf8(content) {
            Ok(v) => v.to_string(),
            Err(_) => format!("{:?}", content),
        }
    }

    fn now_utc_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_millis() as u64
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn chat_input_over_32_bytes_is_rejected() {
            let input = "ááááááááááááááááá";
            assert!(input.as_bytes().len() > 32);
            assert!(validate_chat_input_bytes(input).is_err());
        }

        #[test]
        fn chat_help_includes_all_commands() {
            let help = chat_help();
            assert!(help.contains("/help"));
            assert!(help.contains("/id"));
            assert!(help.contains("/last N"));
            assert!(help.contains("/quit"));
        }
    }
}

#[cfg(feature = "network")]
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("listen") => match network_cli::parse_listen(&args[2..]) {
            Ok(cfg) => network_cli::run_listen(cfg).await,
            Err(e) => Err(e),
        },
        Some("send") => match network_cli::parse_send(&args[2..]) {
            Ok(cfg) => network_cli::run_send(cfg).await,
            Err(e) => Err(e),
        },
        Some("chat") => match network_cli::parse_chat(&args[2..]) {
            Ok(cfg) => network_cli::run_chat(cfg).await,
            Err(e) => Err(e),
        },
        _ => Err(network_cli::usage().to_string()),
    };

    if let Err(e) = result {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

#[cfg(not(feature = "network"))]
fn main() {
    eprintln!("nexo_p2p requires --features network");
    std::process::exit(2);
}
