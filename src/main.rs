use std::env;

const DEFAULT_HTTP_BIND: &str = "0.0.0.0:3000";

#[tokio::main]
async fn main() {
    init_tracing();
    let state = syntax_engine::api::AppState::from_env();
    let bind = http_bind_addr();
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .unwrap_or_else(|_| panic!("failed to bind {bind}"));

    println!("HTTP server running on http://{bind}");
    axum::serve(
        listener,
        syntax_engine::api::app_with_state(state)
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("server error");
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
}

fn http_bind_addr() -> String {
    let configured = env::var("NEXO_HTTP_BIND").unwrap_or_default();
    let trimmed = configured.trim();

    if trimmed.is_empty() {
        DEFAULT_HTTP_BIND.to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn http_bind_addr_uses_default_when_env_missing() {
        let _guard = env_lock().lock().expect("env lock");
        let previous = env::var("NEXO_HTTP_BIND").ok();
        env::remove_var("NEXO_HTTP_BIND");

        assert_eq!(http_bind_addr(), DEFAULT_HTTP_BIND);

        restore_env(previous);
    }

    #[test]
    fn http_bind_addr_uses_env_override() {
        let _guard = env_lock().lock().expect("env lock");
        let previous = env::var("NEXO_HTTP_BIND").ok();
        env::set_var("NEXO_HTTP_BIND", "127.0.0.1:3900");

        assert_eq!(http_bind_addr(), "127.0.0.1:3900");

        restore_env(previous);
    }

    fn restore_env(previous: Option<String>) {
        if let Some(value) = previous {
            env::set_var("NEXO_HTTP_BIND", value);
        } else {
            env::remove_var("NEXO_HTTP_BIND");
        }
    }
}
