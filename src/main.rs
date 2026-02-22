use syntax_engine::{evaluate, TransactionIntent};

fn main() {
    let server_time = 1_736_986_900_000;

    let tx = TransactionIntent::new(
        "user_pep",
        150_000,
        true,
        false,
        server_time - 60_000,
        server_time,
        4_500,
        true,
    )
    .expect("invalid transaction");

    let (decision, trace, hash) = evaluate(&tx);

    println!("Final decision: {:?}", decision);
    println!("Trace: {:?}", trace);
    println!("Audit hash: {}", hash);
}
