# SIKKA node image.
#
# Two stages: a builder with the Rust toolchain, and a runtime that carries
# nothing but the binaries and the CA store. Multi-arch builds use buildx +
# QEMU (slower on arm64, but plain and reliable).

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
    && chown sikka:sikka /data

COPY --from=builder /build/target/release/sikka-node /usr/local/bin/sikka-node
COPY --from=builder /build/target/release/sikka /usr/local/bin/sikka

USER sikka
WORKDIR /data
VOLUME ["/data"]
EXPOSE 64552

ENV SIKKA_LOG=info \
    SIKKA_KEYSTORE=/data/node_key.json \
    SIKKA_NODE=http://127.0.0.1:64552

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:64552/api/health > /dev/null || exit 1

ENTRYPOINT ["sikka-node"]
