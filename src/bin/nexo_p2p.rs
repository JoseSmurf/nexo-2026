#[cfg(feature = "network")]
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(e) = syntax_engine::cli::run_nexo_p2p(&args).await {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

#[cfg(not(feature = "network"))]
fn main() {
    eprintln!("nexo_p2p requires --features network");
    std::process::exit(2);
}
