# SIKKA node image.
#
# Tor-native peer mesh: entrypoint prepares deterministic HS keys, starts `tor`
# (SOCKS + hidden service), then `sikka-node`. Peer advertise is the onion
# derived from SIKKA_PRIVATE_KEY. Optional clearnet reverse proxies may front
# :64552 for wallets; peers never dial clearnet.

FROM rust:1.90-slim-trixie AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY public ./public
RUN cargo build --release --locked --bin sikka-node --bin sikka \
    && strip target/release/sikka-node target/release/sikka

FROM debian:trixie-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tor bash \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 sikka \
    && mkdir -p /data \
    && chown -R sikka:sikka /data

COPY --from=builder /build/target/release/sikka-node /usr/local/bin/sikka-node
COPY --from=builder /build/target/release/sikka /usr/local/bin/sikka
COPY docker/entrypoint.sh /usr/local/bin/sikka-entrypoint
COPY docker/healthcheck.sh /usr/local/bin/sikka-healthcheck
RUN chmod 755 /usr/local/bin/sikka-entrypoint /usr/local/bin/sikka-healthcheck

USER sikka
WORKDIR /data
VOLUME ["/data"]
EXPOSE 64552

# Node knobs: SIKKA_PRIVATE_KEY, SIKKA_TRUSTED_CHECKPOINT (optional), SIKKA_LOG.
# SIKKA_KEYSTORE / SIKKA_NODE are for the in-container `sikka` CLI only.
ENV SIKKA_LOG=info \
    SIKKA_KEYSTORE=/data/node_key.json \
    SIKKA_NODE=http://127.0.0.1:64552

# start-period covers Tor bootstrap; health requires RPC + SOCKS (not onion ok).
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=8 \
    CMD ["/usr/local/bin/sikka-healthcheck"]

ENTRYPOINT ["/usr/local/bin/sikka-entrypoint"]
