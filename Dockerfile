# SIKKA node image.
#
# Clearnet peer mesh: the container runs sikka-node and dials the hardcoded
# bootstrap hosts (1/2/3.sikkalabs.com) over plain HTTP(S). Set SIKKA_NODE_URL
# to the public URL peers should use to reach this node.

FROM rust:1.90-slim-trixie AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY public ./public
RUN cargo build --release --locked --bin sikka-node --bin sikka \
    && strip target/release/sikka-node target/release/sikka

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 sikka \
    && mkdir -p /data \
    && chown -R sikka:sikka /data

COPY --from=builder /build/target/release/sikka-node /usr/local/bin/sikka-node
COPY --from=builder /build/target/release/sikka /usr/local/bin/sikka

USER sikka
WORKDIR /data
VOLUME ["/data"]
EXPOSE 64552

ENV SIKKA_LOG=info \
    SIKKA_KEYSTORE=/data/node_key.json \
    SIKKA_NODE=http://127.0.0.1:64552 \
    SIKKA_DATA_DIR=/data

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=8 \
    CMD curl -fsS http://127.0.0.1:64552/api/health > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/sikka-node"]
