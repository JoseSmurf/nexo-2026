#[cfg(feature = "network")]
mod network_cli {
    use std::collections::HashMap;
    use std::io::BufRead;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time::timeout;

    use syntax_engine::message::{
        content_hash_bytes, event_hash, event_hash_bytes_from_parts, sign_event_hash,
        verify_event_hash_signature, CanonicalMessage,
    };
    use syntax_engine::network_udp::{SignedEvent, UdpFrame, UdpNode};
    use syntax_engine::offline_store::{OfflineStore, StoreInsertStatus};
    #[cfg(feature = "crypto")]
    use syntax_engine::p2p_crypto::{
        decrypt_content, encrypt_content, parse_shared_key_hex, random_aead_nonce,
    };

    #[derive(Debug)]
    pub struct ListenArgs {
        bind: String,
        db: String,
        seen_ttl_ms: u64,
        crypto: bool,
        shared_key_hex: Option<String>,
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
        crypto: bool,
        shared_key_hex: Option<String>,
    }

    #[derive(Debug)]
    pub struct ChatArgs {
        bind: String,
        peer: Option<SocketAddr>,
        discover: bool,
        discover_broadcast: SocketAddr,
        discover_timeout_ms: u64,
        sender: String,
        db: String,
        retries: u8,
        ack_timeout_ms: u64,
        seen_ttl_ms: u64,
        crypto: bool,
        shared_key_hex: Option<String>,
    }

    #[derive(Debug)]
    pub struct DiscoverArgs {
        bind: String,
        broadcast: SocketAddr,
        timeout_ms: u64,
    }

    pub fn usage() -> &'static str {
        "nexo_p2p (network feature)\n\
         usage:\n\
          nexo_p2p listen --bind 127.0.0.1:9001 --db /tmp/nexo_a.db [--seen-ttl-ms 120000] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p send --bind 127.0.0.1:9002 --peer 127.0.0.1:9001 --sender node_b --msg \"hello\" --db /tmp/nexo_b.db [--retries 3] [--ack-timeout-ms 200] [--seen-ttl-ms 120000] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p chat --bind 127.0.0.1:9001 --peer 127.0.0.1:9002 --sender node_a --db /tmp/nexo_a.db [--retries 3] [--ack-timeout-ms 200] [--seen-ttl-ms 120000] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p chat --bind 0.0.0.0:9001 --discover --broadcast 255.255.255.255:9001 --discover-timeout-ms 800 --sender node_a --db /tmp/nexo_a.db [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p discover --bind 0.0.0.0:9001 --broadcast 255.255.255.255:9001 [--timeout-ms 800]"
    }

    fn chat_help() -> &'static str {
        "chat commands: /help /id /last N /quit"
    }

    pub fn parse_listen(args: &[String]) -> Result<ListenArgs, String> {
        let flags = parse_flags(args)?;
        let bind = required(&flags, "bind")?;
        let db = required(&flags, "db")?;
        let seen_ttl_ms = parse_u64(flags.get("seen-ttl-ms"), 120_000, "seen-ttl-ms")?;
        let crypto = parse_bool(flags.get("crypto"), false, "crypto")?;
        let shared_key_hex = flags.get("shared-key-hex").cloned();
        let _ = resolve_shared_key(crypto, shared_key_hex.as_deref())?;
        Ok(ListenArgs {
            bind,
            db,
            seen_ttl_ms,
            crypto,
            shared_key_hex,
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
        let crypto = parse_bool(flags.get("crypto"), false, "crypto")?;
        let shared_key_hex = flags.get("shared-key-hex").cloned();
        let _ = resolve_shared_key(crypto, shared_key_hex.as_deref())?;
        Ok(SendArgs {
            bind,
            peer,
            sender,
            msg,
            retries,
            ack_timeout_ms,
            db,
            seen_ttl_ms,
            crypto,
            shared_key_hex,
        })
    }

    pub fn parse_chat(args: &[String]) -> Result<ChatArgs, String> {
        let flags = parse_flags(args)?;
        let bind = required(&flags, "bind")?;
        let peer = flags
            .get("peer")
            .map(|v| {
                v.parse::<SocketAddr>()
                    .map_err(|_| "invalid --peer socket addr".to_string())
            })
            .transpose()?;
        let discover = parse_bool(flags.get("discover"), false, "discover")?;
        let discover_broadcast = flags
            .get("broadcast")
            .map(|v| {
                v.parse::<SocketAddr>()
                    .map_err(|_| "invalid --broadcast socket addr".to_string())
            })
            .transpose()?
            .unwrap_or_else(|| {
                "255.255.255.255:9001"
                    .parse()
                    .expect("valid default broadcast")
            });
        let discover_timeout_ms =
            parse_u64(flags.get("discover-timeout-ms"), 800, "discover-timeout-ms")?;
        if peer.is_none() && !discover {
            return Err("missing --peer (or set --discover)".to_string());
        }
        let sender = required(&flags, "sender")?;
        let db = required(&flags, "db")?;
        let retries = parse_u8(flags.get("retries"), 3, "retries")?;
        let ack_timeout_ms = parse_u64(flags.get("ack-timeout-ms"), 200, "ack-timeout-ms")?;
        let seen_ttl_ms = parse_u64(flags.get("seen-ttl-ms"), 120_000, "seen-ttl-ms")?;
        let crypto = parse_bool(flags.get("crypto"), false, "crypto")?;
        let shared_key_hex = flags.get("shared-key-hex").cloned();
        let _ = resolve_shared_key(crypto, shared_key_hex.as_deref())?;
        Ok(ChatArgs {
            bind,
            peer,
            discover,
            discover_broadcast,
            discover_timeout_ms,
            sender,
            db,
            retries,
            ack_timeout_ms,
            seen_ttl_ms,
            crypto,
            shared_key_hex,
        })
    }

    pub fn parse_discover(args: &[String]) -> Result<DiscoverArgs, String> {
        let flags = parse_flags(args)?;
        let bind = required(&flags, "bind")?;
        let broadcast = required(&flags, "broadcast")?
            .parse::<SocketAddr>()
            .map_err(|_| "invalid --broadcast socket addr".to_string())?;
        let timeout_ms = parse_u64(flags.get("timeout-ms"), 800, "timeout-ms")?;
        Ok(DiscoverArgs {
            bind,
            broadcast,
            timeout_ms,
        })
    }

    pub async fn run_listen(args: ListenArgs) -> Result<(), String> {
        let node = UdpNode::bind(&args.bind)
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let store = OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
        let shared_key = resolve_shared_key(args.crypto, args.shared_key_hex.as_deref())?;
        println!("listening on {} db={}", args.bind, args.db);

        loop {
            let (frame, from) = node
                .recv_frame()
                .await
                .map_err(|e| format!("recv failed: {e}"))?;
            let (msg, hash_bytes) = match frame {
                UdpFrame::Event(ev) => match decode_wire_event(&ev, shared_key) {
                    Ok(v) => v,
                    Err("invalid_sig") => {
                        println!("invalid_sig");
                        continue;
                    }
                    Err(_) => {
                        println!("decrypt_failed");
                        continue;
                    }
                },
                UdpFrame::Discover => {
                    let local = node
                        .local_addr()
                        .map_err(|e| format!("local addr failed: {e}"))?;
                    node.send_here(from, local)
                        .await
                        .map_err(|e| format!("here failed: {e}"))?;
                    continue;
                }
                UdpFrame::Here(_) => continue,
            };
            let now = now_utc_ms();
            let ehash = event_hash(&msg);
            let expires_at = now.saturating_add(args.seen_ttl_ms);
            let already_seen = store
                .is_seen(&ehash, now)
                .map_err(|e| format!("store seen failed: {e}"))?;
            if already_seen {
                store
                    .mark_seen(&ehash, expires_at)
                    .map_err(|e| format!("store mark_seen failed: {e}"))?;
                println!("recv duplicate event_hash={}", ehash);
                node.send_ack(from, hash_bytes)
                    .await
                    .map_err(|e| format!("ack failed: {e}"))?;
                continue;
            }
            let inserted = store
                .insert_message(&msg, now, args.seen_ttl_ms)
                .map_err(|e| format!("store insert failed: {e}"))?;
            store
                .mark_seen(&ehash, expires_at)
                .map_err(|e| format!("store mark_seen failed: {e}"))?;
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

            node.send_ack(from, hash_bytes)
                .await
                .map_err(|e| format!("ack failed: {e}"))?;
        }
    }

    pub async fn run_send(args: SendArgs) -> Result<(), String> {
        let node = UdpNode::bind(&args.bind)
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let store = OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
        let shared_key = resolve_shared_key(args.crypto, args.shared_key_hex.as_deref())?;

        validate_chat_input_bytes(&args.msg)?;
        let now = now_utc_ms();
        let nonce = store
            .next_nonce(&args.sender)
            .map_err(|e| format!("next_nonce failed: {e}"))?;
        let msg = CanonicalMessage::new_with_nonce(args.sender, now, nonce, args.msg.as_bytes())
            .map_err(|e| e.to_string())?;
        let wire = build_signed_event(&store, &msg, shared_key)?;
        let ehash = event_hash(&msg);
        node.send_with_ack(
            args.peer,
            &wire,
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
        let peer = if let Some(peer) = args.peer {
            peer
        } else if args.discover {
            discover_peer(
                &args.bind,
                args.discover_broadcast,
                Duration::from_millis(args.discover_timeout_ms),
            )
            .await?
        } else {
            return Err("missing peer".to_string());
        };
        let shared_key = resolve_shared_key(args.crypto, args.shared_key_hex.as_deref())?;

        let recv_bind = args.bind.clone();
        let recv_db = args.db.clone();
        let recv_ttl = args.seen_ttl_ms;
        let recv_task = tokio::spawn(async move {
            let node = UdpNode::bind(&recv_bind)
                .await
                .map_err(|e| format!("bind failed: {e}"))?;
            let store = OfflineStore::open(&recv_db).map_err(|e| format!("db open failed: {e}"))?;
            loop {
                let (frame, from) = node
                    .recv_frame()
                    .await
                    .map_err(|e| format!("recv failed: {e}"))?;
                let (msg, hash_bytes) = match frame {
                    UdpFrame::Event(ev) => match decode_wire_event(&ev, shared_key) {
                        Ok(v) => v,
                        Err("invalid_sig") => {
                            println!("invalid_sig");
                            continue;
                        }
                        Err(_) => {
                            println!("decrypt_failed");
                            continue;
                        }
                    },
                    UdpFrame::Discover => {
                        let local = node
                            .local_addr()
                            .map_err(|e| format!("local addr failed: {e}"))?;
                        node.send_here(from, local)
                            .await
                            .map_err(|e| format!("here failed: {e}"))?;
                        continue;
                    }
                    UdpFrame::Here(_) => continue,
                };
                let now = now_utc_ms();
                let ehash = event_hash(&msg);
                let expires_at = now.saturating_add(recv_ttl);
                let already_seen = store
                    .is_seen(&ehash, now)
                    .map_err(|e| format!("store seen failed: {e}"))?;
                if already_seen {
                    store
                        .mark_seen(&ehash, expires_at)
                        .map_err(|e| format!("store mark_seen failed: {e}"))?;
                    println!("[dup] {}", ehash);
                    node.send_ack(from, hash_bytes)
                        .await
                        .map_err(|e| format!("ack failed: {e}"))?;
                    continue;
                }
                let inserted = store
                    .insert_message(&msg, now, recv_ttl)
                    .map_err(|e| format!("store insert failed: {e}"))?;
                store
                    .mark_seen(&ehash, expires_at)
                    .map_err(|e| format!("store mark_seen failed: {e}"))?;
                match inserted {
                    StoreInsertStatus::Inserted => {
                        println!("[{}] {}", msg.sender_id, render_content(&msg.content));
                    }
                    StoreInsertStatus::Duplicate => {
                        println!("[dup] {}", ehash);
                    }
                }
                node.send_ack(from, hash_bytes)
                    .await
                    .map_err(|e| format!("ack failed: {e}"))?;
            }
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        });

        println!(
            "chat ready: bind={} peer={} sender={} db={} (/help /id /last N /quit)",
            args.bind, peer, args.sender, args.db
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
                println!("sender={} bind={} peer={}", args.sender, args.bind, peer);
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
            let wire = build_signed_event(&store, &msg, shared_key)?;

            let sender_node = UdpNode::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("bind failed: {e}"))?;
            match sender_node
                .send_with_ack(
                    peer,
                    &wire,
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

    pub async fn run_discover(args: DiscoverArgs) -> Result<(), String> {
        let peer = discover_peer(
            &args.bind,
            args.broadcast,
            Duration::from_millis(args.timeout_ms),
        )
        .await?;
        println!("{}", peer);
        Ok(())
    }

    async fn discover_peer(
        bind: &str,
        broadcast: SocketAddr,
        timeout_dur: Duration,
    ) -> Result<SocketAddr, String> {
        let node = UdpNode::bind(bind)
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        node.set_broadcast(true)
            .map_err(|e| format!("set broadcast failed: {e}"))?;
        node.send_discover(broadcast)
            .await
            .map_err(|e| format!("discover send failed: {e}"))?;

        let found = timeout(timeout_dur, async {
            loop {
                let (frame, _from) = node
                    .recv_frame()
                    .await
                    .map_err(|e| format!("recv failed: {e}"))?;
                if let UdpFrame::Here(addr) = frame {
                    return Ok(addr);
                }
            }
            #[allow(unreachable_code)]
            Err::<SocketAddr, String>("discover loop aborted".to_string())
        })
        .await;

        match found {
            Ok(result) => result,
            Err(_) => Err("discover timeout".to_string()),
        }
    }

    fn resolve_shared_key(
        crypto: bool,
        shared_key_hex: Option<&str>,
    ) -> Result<Option<[u8; 32]>, String> {
        #[cfg(feature = "crypto")]
        {
            if crypto {
                let raw = shared_key_hex.ok_or_else(|| {
                    "missing --shared-key-hex when --crypto is enabled".to_string()
                })?;
                let key = parse_shared_key_hex(raw).map_err(|e| e.to_string())?;
                return Ok(Some(key));
            }
            if shared_key_hex.is_some() {
                return Err("--shared-key-hex requires --crypto".to_string());
            }
            Ok(None)
        }
        #[cfg(not(feature = "crypto"))]
        {
            if crypto || shared_key_hex.is_some() {
                return Err("crypto feature not enabled in this build".to_string());
            }
            Ok(None)
        }
    }

    fn decode_wire_event(
        ev: &SignedEvent,
        shared_key: Option<[u8; 32]>,
    ) -> Result<(CanonicalMessage, [u8; 32]), &'static str> {
        let hash = event_hash_bytes_from_parts(
            &ev.sender_id,
            ev.timestamp_utc_ms,
            ev.nonce,
            &ev.content_hash,
        );
        if !verify_event_hash_signature(&hash, &ev.sender_pubkey, &ev.signature) {
            return Err("invalid_sig");
        }

        let plaintext = match ev.crypto_nonce {
            Some(aead_nonce) => {
                #[cfg(feature = "crypto")]
                {
                    let key = shared_key.ok_or("decrypt_failed")?;
                    decrypt_content(&ev.payload, &key, &aead_nonce).map_err(|_| "decrypt_failed")?
                }
                #[cfg(not(feature = "crypto"))]
                {
                    let _ = shared_key;
                    let _ = aead_nonce;
                    return Err("decrypt_failed");
                }
            }
            None => ev.payload.clone(),
        };

        if content_hash_bytes(&plaintext) != ev.content_hash {
            return Err("decrypt_failed");
        }

        let msg = CanonicalMessage::new_with_nonce(
            ev.sender_id.clone(),
            ev.timestamp_utc_ms,
            ev.nonce,
            &plaintext,
        )
        .map_err(|_| "decrypt_failed")?;

        Ok((msg, hash))
    }

    fn build_signed_event(
        store: &OfflineStore,
        msg: &CanonicalMessage,
        shared_key: Option<[u8; 32]>,
    ) -> Result<SignedEvent, String> {
        let content_hash = content_hash_bytes(&msg.content);
        let (payload, crypto_nonce) = match shared_key {
            Some(key) => {
                #[cfg(feature = "crypto")]
                {
                    let nonce = random_aead_nonce().map_err(|e| e.to_string())?;
                    let ciphertext =
                        encrypt_content(&msg.content, &key, &nonce).map_err(|e| e.to_string())?;
                    (ciphertext, Some(nonce))
                }
                #[cfg(not(feature = "crypto"))]
                {
                    let _ = key;
                    return Err("crypto feature not enabled in this build".to_string());
                }
            }
            None => (msg.content.clone(), None),
        };

        let (sender_pubkey, sender_seckey) = store
            .get_or_create_identity()
            .map_err(|e| format!("identity failed: {e}"))?;
        let hash = event_hash_bytes_from_parts(
            &msg.sender_id,
            msg.timestamp_utc_ms,
            msg.nonce,
            &content_hash,
        );
        let signature = sign_event_hash(&hash, &sender_seckey).map_err(|e| e.to_string())?;

        Ok(SignedEvent {
            sender_id: msg.sender_id.clone(),
            timestamp_utc_ms: msg.timestamp_utc_ms,
            nonce: msg.nonce,
            content_hash,
            payload,
            crypto_nonce,
            sender_pubkey,
            signature,
        })
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

    fn parse_bool(raw: Option<&String>, default: bool, key: &str) -> Result<bool, String> {
        match raw {
            Some(v) => match v.as_str() {
                "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
                "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
                _ => Err(format!("invalid --{key} value")),
            },
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
            assert!(input.len() > 32);
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

        #[test]
        fn parse_chat_accepts_discover_without_peer() {
            let args = vec![
                "--bind".to_string(),
                "0.0.0.0:9001".to_string(),
                "--discover".to_string(),
                "--broadcast".to_string(),
                "255.255.255.255:9001".to_string(),
                "--sender".to_string(),
                "node_a".to_string(),
                "--db".to_string(),
                "/tmp/a.db".to_string(),
            ];
            let parsed = parse_chat(&args).expect("parse");
            assert!(parsed.peer.is_none());
            assert!(parsed.discover);
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
        Some("discover") => match network_cli::parse_discover(&args[2..]) {
            Ok(cfg) => network_cli::run_discover(cfg).await,
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
