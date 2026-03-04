#[cfg(feature = "network")]
mod network_cli {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::io::BufRead;
    use std::net::SocketAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tokio::time::timeout;

    use syntax_engine::analyzer::{analyze_bytes, deterministic_ai_response};
    use syntax_engine::message::{
        content_hash_bytes, event_hash, event_hash_bytes_from_parts, sign_event_hash,
        signed_envelope_hash_bytes, verify_event_hash_signature, CanonicalMessage,
    };
    use syntax_engine::network_udp::{SignedEvent, UdpFrame, UdpNode};
    use syntax_engine::offline_store::{OfflineStore, RawMessageInput, StoreInsertStatus};
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
        daemon: bool,
        discover: bool,
        discover_broadcast: SocketAddr,
        discover_timeout_ms: u64,
        sync_on_start: bool,
        since_ms: Option<u64>,
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

    #[derive(Debug)]
    pub struct SyncArgs {
        bind: String,
        peer: SocketAddr,
        db: String,
        since_ms: u64,
        timeout_ms: u64,
        crypto: bool,
        shared_key_hex: Option<String>,
    }

    #[derive(Debug)]
    pub struct AiArgs {
        db: String,
        sender: String,
    }

    pub fn usage() -> &'static str {
        "nexo_p2p (network feature)\n\
         usage:\n\
          nexo_p2p listen --bind 127.0.0.1:9001 --db /tmp/nexo_a.db [--seen-ttl-ms 120000] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p send --bind 127.0.0.1:9002 --peer 127.0.0.1:9001 --sender node_b --msg \"hello\" --db /tmp/nexo_b.db [--retries 3] [--ack-timeout-ms 200] [--seen-ttl-ms 120000] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p chat --bind 127.0.0.1:9001 --peer 127.0.0.1:9002 --sender node_a --db /tmp/nexo_a.db [--daemon] [--retries 3] [--ack-timeout-ms 200] [--seen-ttl-ms 120000] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p chat --bind 0.0.0.0:9001 --discover --broadcast 255.255.255.255:9001 --discover-timeout-ms 800 --sender node_a --db /tmp/nexo_a.db [--sync-on-start --since-ms 0] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p ai --db /tmp/nexo_ai.db --sender node_a\n\
          nexo_p2p sync --bind 127.0.0.1:9010 --peer 127.0.0.1:9001 --db /tmp/nexo_b.db --since-ms 0 [--timeout-ms 800] [--crypto --shared-key-hex <64hex>]\n\
          nexo_p2p discover --bind 0.0.0.0:9001 --broadcast 255.255.255.255:9001 [--timeout-ms 800]"
    }

    fn chat_help() -> &'static str {
        "chat commands: /help /id /last N /ai last N /quit"
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
        let daemon = parse_bool(flags.get("daemon"), false, "daemon")?;
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
        let sync_on_start = parse_bool(flags.get("sync-on-start"), false, "sync-on-start")?;
        let since_ms = flags
            .get("since-ms")
            .map(|v| {
                v.parse::<u64>()
                    .map_err(|_| "invalid --since-ms value".to_string())
            })
            .transpose()?;
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
            daemon,
            discover,
            discover_broadcast,
            discover_timeout_ms,
            sync_on_start,
            since_ms,
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

    pub fn parse_sync(args: &[String]) -> Result<SyncArgs, String> {
        let flags = parse_flags(args)?;
        let bind = required(&flags, "bind")?;
        let peer = required(&flags, "peer")?
            .parse::<SocketAddr>()
            .map_err(|_| "invalid --peer socket addr".to_string())?;
        let db = required(&flags, "db")?;
        let since_ms = parse_u64(flags.get("since-ms"), 0, "since-ms")?;
        let timeout_ms = parse_u64(flags.get("timeout-ms"), 800, "timeout-ms")?;
        let crypto = parse_bool(flags.get("crypto"), false, "crypto")?;
        let shared_key_hex = flags.get("shared-key-hex").cloned();
        let _ = resolve_shared_key(crypto, shared_key_hex.as_deref())?;
        Ok(SyncArgs {
            bind,
            peer,
            db,
            since_ms,
            timeout_ms,
            crypto,
            shared_key_hex,
        })
    }

    pub fn parse_ai(args: &[String]) -> Result<AiArgs, String> {
        let flags = parse_flags(args)?;
        let db = required(&flags, "db")?;
        let sender = required(&flags, "sender")?;
        Ok(AiArgs { db, sender })
    }

    pub async fn run_listen(args: ListenArgs) -> Result<(), String> {
        let node = UdpNode::bind(&args.bind)
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let store = OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
        let shared_key = resolve_shared_key(args.crypto, args.shared_key_hex.as_deref())?;
        let mut known_peers: HashSet<SocketAddr> = HashSet::new();
        println!("listening on {} db={}", args.bind, args.db);

        loop {
            let (frame, from) = node
                .recv_frame()
                .await
                .map_err(|e| format!("recv failed: {e}"))?;
            let decoded = match frame {
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
                UdpFrame::SyncItem(_) => continue,
                UdpFrame::SyncRequest(req) => {
                    let items = store
                        .messages_since(req.since_ts_ms, 200)
                        .map_err(|e| format!("messages_since failed: {e}"))?;
                    for item in items {
                        let msg = CanonicalMessage::new_with_nonce(
                            item.sender_id,
                            item.timestamp_utc_ms,
                            item.nonce,
                            item.content,
                        )
                        .map_err(|e| e.to_string())?;
                        let wire = build_signed_event(&store, &msg, shared_key)?;
                        node.send_sync_item(from, &wire)
                            .await
                            .map_err(|e| format!("sync item send failed: {e}"))?;
                    }
                    continue;
                }
            };
            known_peers.insert(from);
            let msg = decoded.msg;
            let hash_bytes = decoded.ack_hash;
            let origin_hex = hash32_to_hex(&decoded.origin_event_hash);
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
            if store
                .is_forwarded(&origin_hex)
                .map_err(|e| format!("store forwarded check failed: {e}"))?
            {
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
            let should_forward = inserted == StoreInsertStatus::Inserted;
            match inserted {
                StoreInsertStatus::Inserted => {
                    println!(
                        "recv inserted sender={} ts={} nonce={} content_bytes={:?} event_hash={}",
                        msg.sender_id, msg.timestamp_utc_ms, msg.nonce, msg.content, ehash
                    );
                    if let Some(insight) = maybe_generate_ai_insight_for_global(
                        &store,
                        &msg,
                        inserted,
                        now,
                        args.seen_ttl_ms,
                    )? {
                        println!("analysis ai channel=ai summary={}", insight);
                    }
                }
                StoreInsertStatus::Duplicate => {
                    println!("recv duplicate event_hash={}", ehash);
                }
            }

            node.send_ack(from, hash_bytes)
                .await
                .map_err(|e| format!("ack failed: {e}"))?;

            if should_forward && decoded.hops_remaining > 0 {
                let forward_hops = decoded.hops_remaining.saturating_sub(1);
                let fwd = build_signed_event_with_hops(
                    &store,
                    &msg,
                    shared_key,
                    decoded.origin_event_hash,
                    forward_hops,
                )?;
                for peer in known_peers.iter().copied().filter(|p| *p != from) {
                    node.send_event(peer, &fwd)
                        .await
                        .map_err(|e| format!("forward send failed: {e}"))?;
                }
                store
                    .mark_forwarded(&origin_hex, now)
                    .map_err(|e| format!("store forward mark failed: {e}"))?;
            }
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

        if args.sync_on_start {
            let synced = run_sync_inner(
                &args.bind,
                peer,
                &args.db,
                args.since_ms.unwrap_or(0),
                800,
                shared_key,
                args.seen_ttl_ms,
            )
            .await?;
            println!("sync_on_start synced={}", synced);
        }

        let recv_bind = args.bind.clone();
        let recv_db = args.db.clone();
        let recv_ttl = args.seen_ttl_ms;
        let recv_task = tokio::spawn(async move {
            let node = UdpNode::bind(&recv_bind)
                .await
                .map_err(|e| format!("bind failed: {e}"))?;
            let store = OfflineStore::open(&recv_db).map_err(|e| format!("db open failed: {e}"))?;
            let mut known_peers: HashSet<SocketAddr> = HashSet::new();
            loop {
                let (frame, from) = node
                    .recv_frame()
                    .await
                    .map_err(|e| format!("recv failed: {e}"))?;
                let decoded = match frame {
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
                    UdpFrame::SyncItem(_) => continue,
                    UdpFrame::SyncRequest(req) => {
                        let items = store
                            .messages_since(req.since_ts_ms, 200)
                            .map_err(|e| format!("messages_since failed: {e}"))?;
                        for item in items {
                            let msg = CanonicalMessage::new_with_nonce(
                                item.sender_id,
                                item.timestamp_utc_ms,
                                item.nonce,
                                item.content,
                            )
                            .map_err(|e| e.to_string())?;
                            let wire = build_signed_event(&store, &msg, shared_key)?;
                            node.send_sync_item(from, &wire)
                                .await
                                .map_err(|e| format!("sync item send failed: {e}"))?;
                        }
                        continue;
                    }
                };
                known_peers.insert(from);
                let msg = decoded.msg;
                let hash_bytes = decoded.ack_hash;
                let origin_hex = hash32_to_hex(&decoded.origin_event_hash);
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
                if store
                    .is_forwarded(&origin_hex)
                    .map_err(|e| format!("store forwarded check failed: {e}"))?
                {
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
                let should_forward = inserted == StoreInsertStatus::Inserted;
                match inserted {
                    StoreInsertStatus::Inserted => {
                        println!("[{}] {}", msg.sender_id, render_content(&msg.content));
                        let analysis = analyze_bytes(&msg.content);
                        println!(
                            "analysis intent={} topics=[{}] summary={}",
                            analysis.intent,
                            analysis.topics.join(","),
                            analysis.summary
                        );
                        if let Some(insight) = maybe_generate_ai_insight_for_global(
                            &store, &msg, inserted, now, recv_ttl,
                        )? {
                            println!("analysis ai channel=ai summary={}", insight);
                        }
                    }
                    StoreInsertStatus::Duplicate => {
                        println!("[dup] {}", ehash);
                    }
                }
                node.send_ack(from, hash_bytes)
                    .await
                    .map_err(|e| format!("ack failed: {e}"))?;

                if should_forward && decoded.hops_remaining > 0 {
                    let forward_hops = decoded.hops_remaining.saturating_sub(1);
                    let fwd = build_signed_event_with_hops(
                        &store,
                        &msg,
                        shared_key,
                        decoded.origin_event_hash,
                        forward_hops,
                    )?;
                    for peer in known_peers.iter().copied().filter(|p| *p != from) {
                        node.send_event(peer, &fwd)
                            .await
                            .map_err(|e| format!("forward send failed: {e}"))?;
                    }
                    store
                        .mark_forwarded(&origin_hex, now)
                        .map_err(|e| format!("store forward mark failed: {e}"))?;
                }
            }
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        });

        println!(
            "chat ready: bind={} peer={} sender={} db={} (/help /id /last N /ai last N /quit)",
            args.bind, peer, args.sender, args.db
        );

        if args.daemon {
            println!("chat daemon mode enabled");
            return match recv_task.await {
                Ok(inner) => inner,
                Err(e) => Err(format!("recv task join failed: {e}")),
            };
        }

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
            if let Some(rest) = line.strip_prefix("/ai last ") {
                let count = rest
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "invalid /ai last N value".to_string())?;
                let store =
                    OfflineStore::open(&args.db).map_err(|e| format!("db open failed: {e}"))?;
                let items = store
                    .last_messages_by_channel("ai", count)
                    .map_err(|e| format!("last_messages_by_channel failed: {e}"))?;
                for item in items {
                    println!(
                        "[{}] {} (channel={} ts={} hash={})",
                        item.sender_id,
                        render_content(&item.content),
                        item.channel,
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
                    if status == StoreInsertStatus::Inserted {
                        let analysis = analyze_bytes(&msg.content);
                        println!(
                            "analysis intent={} topics=[{}] summary={}",
                            analysis.intent,
                            analysis.topics.join(","),
                            analysis.summary
                        );
                        if let Some(insight) = maybe_generate_ai_insight_for_global(
                            &store,
                            &msg,
                            status,
                            now_utc_ms(),
                            args.seen_ttl_ms,
                        )? {
                            println!("analysis ai channel=ai summary={}", insight);
                        }
                    }
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

    pub async fn run_sync(args: SyncArgs) -> Result<(), String> {
        let shared_key = resolve_shared_key(args.crypto, args.shared_key_hex.as_deref())?;
        let synced = run_sync_inner(
            &args.bind,
            args.peer,
            &args.db,
            args.since_ms,
            args.timeout_ms,
            shared_key,
            120_000,
        )
        .await?;
        println!("synced={}", synced);
        Ok(())
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

    async fn run_sync_inner(
        bind: &str,
        peer: SocketAddr,
        db: &str,
        since_ms: u64,
        timeout_ms: u64,
        shared_key: Option<[u8; 32]>,
        seen_ttl_ms: u64,
    ) -> Result<usize, String> {
        let node = UdpNode::bind(bind)
            .await
            .map_err(|e| format!("bind failed: {e}"))?;
        let store = OfflineStore::open(db).map_err(|e| format!("db open failed: {e}"))?;
        node.send_sync_request(peer, since_ms)
            .await
            .map_err(|e| format!("sync request failed: {e}"))?;

        let mut synced = 0usize;
        loop {
            let recv = timeout(Duration::from_millis(timeout_ms), node.recv_frame()).await;
            let (frame, _from) = match recv {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => return Err(format!("sync recv failed: {e}")),
                Err(_) => break,
            };
            let ev = match frame {
                UdpFrame::SyncItem(ev) => ev,
                _ => continue,
            };
            let decoded = match decode_wire_event(&ev, shared_key) {
                Ok(v) => v,
                Err("invalid_sig") => continue,
                Err(_) => continue,
            };
            let status = store
                .insert_message(&decoded.msg, now_utc_ms(), seen_ttl_ms)
                .map_err(|e| format!("store insert failed: {e}"))?;
            if status == StoreInsertStatus::Inserted {
                synced += 1;
            }
        }
        Ok(synced)
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

    struct DecodedEvent {
        msg: CanonicalMessage,
        ack_hash: [u8; 32],
        origin_event_hash: [u8; 32],
        hops_remaining: u8,
    }

    fn hash32_to_hex(hash: &[u8; 32]) -> String {
        blake3::Hash::from(*hash).to_hex().to_string()
    }

    fn decode_wire_event(
        ev: &SignedEvent,
        shared_key: Option<[u8; 32]>,
    ) -> Result<DecodedEvent, &'static str> {
        let signed_hash = signed_envelope_hash_bytes(
            &ev.sender_id,
            ev.timestamp_utc_ms,
            ev.nonce,
            &ev.content_hash,
            &ev.origin_event_hash,
            ev.hops_remaining,
        );
        if !verify_event_hash_signature(&signed_hash, &ev.sender_pubkey, &ev.signature) {
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

        let ack_hash = event_hash_bytes_from_parts(
            &ev.sender_id,
            ev.timestamp_utc_ms,
            ev.nonce,
            &ev.content_hash,
        );

        Ok(DecodedEvent {
            msg,
            ack_hash,
            origin_event_hash: ev.origin_event_hash,
            hops_remaining: ev.hops_remaining,
        })
    }

    fn build_signed_event(
        store: &OfflineStore,
        msg: &CanonicalMessage,
        shared_key: Option<[u8; 32]>,
    ) -> Result<SignedEvent, String> {
        build_signed_event_with_hops(
            store,
            msg,
            shared_key,
            event_hash_bytes_from_parts(
                &msg.sender_id,
                msg.timestamp_utc_ms,
                msg.nonce,
                &content_hash_bytes(&msg.content),
            ),
            4,
        )
    }

    fn build_signed_event_with_hops(
        store: &OfflineStore,
        msg: &CanonicalMessage,
        shared_key: Option<[u8; 32]>,
        origin_event_hash: [u8; 32],
        hops_remaining: u8,
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
        let hash = signed_envelope_hash_bytes(
            &msg.sender_id,
            msg.timestamp_utc_ms,
            msg.nonce,
            &content_hash,
            &origin_event_hash,
            hops_remaining,
        );
        let signature = sign_event_hash(&hash, &sender_seckey).map_err(|e| e.to_string())?;

        Ok(SignedEvent {
            sender_id: msg.sender_id.clone(),
            timestamp_utc_ms: msg.timestamp_utc_ms,
            nonce: msg.nonce,
            content_hash,
            origin_event_hash,
            hops_remaining,
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

    fn process_ai_prompt(
        store: &OfflineStore,
        sender: &str,
        prompt: &str,
        now_ms: u64,
        seen_ttl_ms: u64,
    ) -> Result<String, String> {
        validate_chat_input_bytes(prompt)?;
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

    fn build_repetition_insight(topic: &str, repeats: usize, intent: &str) -> String {
        format!(
            "deterministic_ai insight=repetition topic={} repeats={} intent={} action=observe_global",
            topic, repeats, intent
        )
    }

    fn maybe_generate_ai_insight_for_global(
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

        let mut repeated: Vec<(String, usize)> =
            counts.into_iter().filter(|(_, c)| *c >= 3).collect();
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tokio::time::{sleep, Duration};

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
            assert!(help.contains("/ai last N"));
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

        #[test]
        fn parse_chat_accepts_daemon_flag() {
            let args = vec![
                "--bind".to_string(),
                "127.0.0.1:9001".to_string(),
                "--peer".to_string(),
                "127.0.0.1:9002".to_string(),
                "--sender".to_string(),
                "node_a".to_string(),
                "--db".to_string(),
                "/tmp/a.db".to_string(),
                "--daemon".to_string(),
            ];
            let parsed = parse_chat(&args).expect("parse");
            assert!(parsed.daemon);
        }

        #[test]
        fn ai_input_over_32_bytes_is_rejected() {
            let input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
            assert!(validate_chat_input_bytes(input).is_err());
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

        #[tokio::test]
        async fn sync_replays_without_duplicates() {
            fn free_addr() -> SocketAddr {
                let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind free addr");
                let addr = sock.local_addr().expect("local addr");
                drop(sock);
                addr
            }

            let uniq = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos();
            let db_a = std::env::temp_dir().join(format!("nexo_sync_a_{uniq}.db"));
            let db_b = std::env::temp_dir().join(format!("nexo_sync_b_{uniq}.db"));
            let bind_a = free_addr();
            let bind_b = free_addr();

            {
                let store = OfflineStore::open(db_a.to_str().expect("db a")).expect("store a");
                let m1 = CanonicalMessage::new_with_nonce("node_a", 1_000, 1, b"m1").expect("m1");
                let m2 = CanonicalMessage::new_with_nonce("node_a", 2_000, 2, b"m2").expect("m2");
                assert_eq!(
                    store
                        .insert_message(&m1, 1_000, 120_000)
                        .expect("insert m1"),
                    StoreInsertStatus::Inserted
                );
                assert_eq!(
                    store
                        .insert_message(&m2, 2_000, 120_000)
                        .expect("insert m2"),
                    StoreInsertStatus::Inserted
                );
            }

            let listen_args = ListenArgs {
                bind: bind_a.to_string(),
                db: db_a.to_str().expect("db a").to_string(),
                seen_ttl_ms: 120_000,
                crypto: false,
                shared_key_hex: None,
            };
            let listener = tokio::spawn(async move { run_listen(listen_args).await });
            sleep(Duration::from_millis(150)).await;

            let first = run_sync_inner(
                &bind_b.to_string(),
                bind_a,
                db_b.to_str().expect("db b"),
                0,
                400,
                None,
                120_000,
            )
            .await
            .expect("first sync");
            assert_eq!(first, 2);

            let second = run_sync_inner(
                &bind_b.to_string(),
                bind_a,
                db_b.to_str().expect("db b"),
                0,
                400,
                None,
                120_000,
            )
            .await
            .expect("second sync");
            assert_eq!(second, 0);

            listener.abort();
            let _ = listener.await;

            let store_b = OfflineStore::open(db_b.to_str().expect("db b")).expect("store b");
            let all = store_b.messages_since(0, 10).expect("messages");
            assert_eq!(all.len(), 2);

            let _ = fs::remove_file(db_a);
            let _ = fs::remove_file(db_b);
        }

        #[tokio::test]
        async fn gossip_forward_a_to_b_to_c_no_loop() {
            fn free_addr() -> SocketAddr {
                let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind free addr");
                let addr = sock.local_addr().expect("local addr");
                drop(sock);
                addr
            }

            let uniq = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos();
            let db_a = std::env::temp_dir().join(format!("nexo_gossip_a_{uniq}.db"));
            let db_b = std::env::temp_dir().join(format!("nexo_gossip_b_{uniq}.db"));
            let db_c = std::env::temp_dir().join(format!("nexo_gossip_c_{uniq}.db"));

            let bind_a = free_addr();
            let bind_b = free_addr();
            let bind_c = free_addr();

            let db_b_s = db_b.to_str().expect("db b").to_string();
            let listener_b = tokio::spawn(async move {
                run_listen(ListenArgs {
                    bind: bind_b.to_string(),
                    db: db_b_s,
                    seen_ttl_ms: 120_000,
                    crypto: false,
                    shared_key_hex: None,
                })
                .await
            });
            sleep(Duration::from_millis(250)).await;

            let node_c = UdpNode::bind(&bind_c.to_string())
                .await
                .expect("bind node c");
            let store_c = OfflineStore::open(db_c.to_str().expect("db c")).expect("store c");
            let seed = CanonicalMessage::new_with_nonce("node_c", now_utc_ms(), 1, b"seed")
                .expect("seed msg");
            let seed_wire = build_signed_event(&store_c, &seed, None).expect("seed wire");
            node_c
                .send_event(bind_b, &seed_wire)
                .await
                .expect("seed send");
            sleep(Duration::from_millis(100)).await;

            run_send(SendArgs {
                bind: bind_a.to_string(),
                peer: bind_b,
                sender: "node_a".to_string(),
                msg: "hello-gossip".to_string(),
                retries: 2,
                ack_timeout_ms: 200,
                db: db_a.to_str().expect("db a").to_string(),
                seen_ttl_ms: 120_000,
                crypto: false,
                shared_key_hex: None,
            })
            .await
            .expect("send A->B");

            let deadline = tokio::time::Instant::now() + Duration::from_millis(800);
            let mut c_msg_count = 0usize;
            while tokio::time::Instant::now() < deadline {
                let recv =
                    tokio::time::timeout(Duration::from_millis(120), node_c.recv_frame()).await;
                let Ok(Ok((frame, _from))) = recv else {
                    continue;
                };
                let UdpFrame::Event(ev) = frame else {
                    continue;
                };
                if ev.sender_id == "node_a" && ev.payload == b"hello-gossip" {
                    c_msg_count += 1;
                }
            }
            assert_eq!(c_msg_count, 1);

            listener_b.abort();
            let _ = listener_b.await;

            let _ = fs::remove_file(db_a);
            let _ = fs::remove_file(db_b);
            let _ = fs::remove_file(db_c);
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
        Some("sync") => match network_cli::parse_sync(&args[2..]) {
            Ok(cfg) => network_cli::run_sync(cfg).await,
            Err(e) => Err(e),
        },
        Some("ai") => match network_cli::parse_ai(&args[2..]) {
            Ok(cfg) => network_cli::run_ai(cfg).await,
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
