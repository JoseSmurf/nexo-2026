use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: client_pubkey <seed_base64_32bytes>");
        std::process::exit(2);
    }
    let pubkey = syntax_engine::api::derive_client_public_key_base64(&args[1]);
    println!("{pubkey}");
}
