use crate::ai;
use crate::chat;

pub fn usage() -> &'static str {
    chat::usage()
}

pub fn parse_listen(args: &[String]) -> Result<chat::ListenArgs, String> {
    chat::parse_listen(args)
}

pub fn parse_send(args: &[String]) -> Result<chat::SendArgs, String> {
    chat::parse_send(args)
}

pub fn parse_chat(args: &[String]) -> Result<chat::ChatArgs, String> {
    chat::parse_chat(args)
}

pub fn parse_discover(args: &[String]) -> Result<chat::DiscoverArgs, String> {
    chat::parse_discover(args)
}

pub fn parse_sync(args: &[String]) -> Result<chat::SyncArgs, String> {
    chat::parse_sync(args)
}

pub fn parse_ai(args: &[String]) -> Result<ai::AiArgs, String> {
    ai::parse_ai(args)
}

pub async fn run_nexo_p2p(args: &[String]) -> Result<(), String> {
    match args.get(1).map(String::as_str) {
        Some("listen") => match parse_listen(&args[2..]) {
            Ok(cfg) => chat::run_listen(cfg).await,
            Err(e) => Err(e),
        },
        Some("send") => match parse_send(&args[2..]) {
            Ok(cfg) => chat::run_send(cfg).await,
            Err(e) => Err(e),
        },
        Some("chat") => match parse_chat(&args[2..]) {
            Ok(cfg) => chat::run_chat(cfg).await,
            Err(e) => Err(e),
        },
        Some("discover") => match parse_discover(&args[2..]) {
            Ok(cfg) => chat::run_discover(cfg).await,
            Err(e) => Err(e),
        },
        Some("sync") => match parse_sync(&args[2..]) {
            Ok(cfg) => chat::run_sync(cfg).await,
            Err(e) => Err(e),
        },
        Some("ai") => match parse_ai(&args[2..]) {
            Ok(cfg) => ai::run_ai(cfg).await,
            Err(e) => Err(e),
        },
        _ => Err(usage().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn parse_chat_accepts_relay_without_peer() {
        let args = vec![
            "--bind".to_string(),
            "127.0.0.1:9001".to_string(),
            "--relay".to_string(),
            "http://127.0.0.1:9100".to_string(),
            "--sender".to_string(),
            "node_a".to_string(),
            "--db".to_string(),
            "/tmp/a.db".to_string(),
        ];
        let parsed = parse_chat(&args).expect("parse");
        assert!(parsed.peer.is_none());
        assert_eq!(parsed.relay_url.as_deref(), Some("http://127.0.0.1:9100"));
    }
}
