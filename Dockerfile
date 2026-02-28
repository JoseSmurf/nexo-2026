FROM rust:1.91-bookworm AS builder
WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches

RUN cargo build --release --bin syntax-engine --bin sign_request --bin sign_client_request --bin client_pubkey

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/syntax-engine /usr/local/bin/syntax-engine
COPY --from=builder /app/target/release/sign_request /usr/local/bin/sign_request
COPY --from=builder /app/target/release/sign_client_request /usr/local/bin/sign_client_request
COPY --from=builder /app/target/release/client_pubkey /usr/local/bin/client_pubkey

EXPOSE 3000
CMD ["syntax-engine"]
