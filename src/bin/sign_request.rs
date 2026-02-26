use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: sign_request <secret> <key_id> <request_id> <timestamp_ms> <json_body>");
        std::process::exit(2);
    }

    let secret = &args[1];
    let key_id = &args[2];
    let request_id = &args[3];
    let timestamp_ms: u64 = args[4].parse().unwrap_or_else(|_| {
        eprintln!("invalid timestamp_ms: {}", args[4]);
        std::process::exit(2);
    });
    let body = &args[5];

    let sig = syntax_engine::api::compute_signature(
        secret,
        key_id,
        request_id,
        timestamp_ms,
        body.as_bytes(),
    );
    println!("{}", sig);
}
