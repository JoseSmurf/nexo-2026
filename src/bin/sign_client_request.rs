use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 7 {
        eprintln!(
            "usage: sign_client_request <seed_base64_32bytes> <client_id> <key_id> <request_id> <timestamp_ms> <json_body>"
        );
        std::process::exit(2);
    }

    let seed_b64 = &args[1];
    let client_id = &args[2];
    let key_id = &args[3];
    let request_id = &args[4];
    let timestamp_ms: u64 = args[5].parse().unwrap_or_else(|_| {
        eprintln!("invalid timestamp_ms: {}", args[5]);
        std::process::exit(2);
    });
    let body = &args[6];

    let sig = syntax_engine::api::compute_client_signature_base64(
        seed_b64,
        client_id,
        key_id,
        request_id,
        timestamp_ms,
        body.as_bytes(),
    );
    println!("{sig}");
}
