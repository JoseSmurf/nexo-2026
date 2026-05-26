use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 6 && args.len() != 7 {
        eprintln!(
            "usage: sign_request <secret> <key_id> <request_id> <timestamp_ms> <json_body> [nonce]"
        );
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
    let nonce = if args.len() == 7 {
        args[6].parse().unwrap_or_else(|_| {
            eprintln!("invalid nonce: {}", args[6]);
            std::process::exit(2);
        })
    } else {
        timestamp_ms
    };

    let sig = syntax_engine::api::compute_signature_with_nonce(
        secret,
        key_id,
        request_id,
        timestamp_ms,
        nonce,
        body.as_bytes(),
    );
    println!("{}", sig);
}
