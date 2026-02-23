#[tokio::main]
async fn main() {
    init_tracing();
    let state = syntax_engine::api::AppState::from_env();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind 0.0.0.0:3000");

    println!("HTTP server running on http://0.0.0.0:3000");
    axum::serve(listener, syntax_engine::api::app_with_state(state))
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
