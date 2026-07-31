# SIKKA node image.
#
# Peer mesh is Tor: the runtime ships `tor` and an entrypoint that publishes a
# v3 onion derived from the node key, then runs sikka-node with SOCKS outbound.
# Users still hit plain HTTP on :64552 (map the port for wallets / gateways).

FROM rust:1.90-slim-trixie AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY public ./public
RUN cargo build --release --locked --bin sikka-node --bin sikka \
    && strip target/release/sikka-node target/release/sikka

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tor \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 sikka \
    && mkdir -p /data \
    && chown -R sikka:sikka /data

COPY --from=builder /build/target/release/sikka-node /usr/local/bin/sikka-node
COPY --from=builder /build/target/release/sikka /usr/local/bin/sikka
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

USER sikka
WORKDIR /data
VOLUME ["/data"]
EXPOSE 64552

ENV SIKKA_LOG=info \
    SIKKA_KEYSTORE=/data/node_key.json \
    SIKKA_NODE=http://127.0.0.1:64552 \
    SIKKA_DATA_DIR=/data

HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=5 \
    CMD curl -fsS http://127.0.0.1:64552/api/health > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
