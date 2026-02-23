#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind 0.0.0.0:3000");

    println!("HTTP server running on http://0.0.0.0:3000");
    axum::serve(listener, syntax_engine::api::app())
        .await
        .expect("server error");
}
