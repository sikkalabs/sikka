# Run SIKKA with Docker

Image: [`ghcr.io/sikkalabs/sikka:latest`](https://github.com/orgs/sikkalabs/packages) (amd64 + arm64).

**Peer mesh is Tor-only.** The image runs the Tor daemon (`tor`: SOCKS +
hidden service) alongside `sikka-node`. The entrypoint waits until SOCKS is
ready before starting the node, restarts Tor if it exits (capped), and exits
the container if Tor cannot stay up — so Docker `restart` policies recover the
pair. Healthchecks require RPC **and** a live SOCKS listener.
Bootstrap defaults to the two genesis validators' onions. HS key material is
written under `/data/arti/ctor/` in C-Tor format (Arti ctor-compatible); an
`arti.toml` is also generated for a future Arti sidecar swap.

Optional clearnet (e.g. `https://1.sikkalabs.com`) is an operator reverse proxy
in front of port **64552** for wallets/RPC — peers never dial clearnet.

Data in `/data`, key at `/data/node_key.json`, Tor HS keys under
`/data/arti/ctor/`, and resumable state snapshot chunks under `/data/snapshots/`.
Genesis is baked in (supply **19,960,907 SIKKA**: cold admin mint at
`0x9949…447`, two validators with **10,000** and **4,000** bonded plus
**20,000 liquid** each).

---

## Pull

```bash
docker pull ghcr.io/sikkalabs/sikka:latest
```

Or build yourself:

```bash
docker build -t ghcr.io/sikkalabs/sikka:latest .
```

---

## Run a node (Pi / validator)

Only the seed is required — no domain, no advertise URL:

```bash
docker run -d --name sikka \
  -p 64552:64552 \
  -v sikka-data:/data \
  -e SIKKA_PRIVATE_KEY=<32-byte-seed-hex> \
  ghcr.io/sikkalabs/sikka:latest
```

```bash
docker logs -f sikka
curl -s http://127.0.0.1:64552/api/health
curl -s http://127.0.0.1:64552/          # landing page
open http://127.0.0.1:64552/wallet.html  # browser wallet on this node
```

Joiners: different `--name`, volume, and seed. Peers find each other over Tor
via the hardcoded onion bootstrap.

### Local Tor mesh test (two validators)

With `.env` containing `validator1=` / `validator2=` seeds:

```bash
./docker/test-tor-mesh.sh
# or
docker compose -f docker-compose.tor.yml --env-file .env up --build
```

Maps `64553` / `64554` for local RPC health checks while the peer mesh stays
on onions. Docker needs outbound access to the Tor network for full onion
discovery; the script still verifies boot, HS key derivation, SOCKS, and health
when Tor relays are unreachable.

### Fund and bond (joiners)

Genesis already stakes the bootstrap operators. A new node needs coins, then a
bond (at least ~0.001% of supply ≈ **200 SIKKA** on the default mint):

```bash
docker exec sikka-2 sikka address
docker exec sikka sikka send <joiner-address> 400
docker exec sikka-2 sikka bond 400
docker exec sikka-2 sikka unbond    # later — starts the cooldown
```

---

## Useful `docker exec` commands

The image includes the `sikka` CLI. It talks to `http://127.0.0.1:64552` inside
the container and signs with `/data/node_key.json`.

```bash
# Identity
docker exec sikka sikka address
docker exec sikka sikka balance
docker exec sikka sikka balance --verify

# Chain
docker exec sikka sikka info
docker exec sikka sikka validators
docker exec sikka sikka checkpoint
docker exec sikka sikka peers
docker exec sikka sikka mempool

# Move value / stake (amounts in SIKKA)
docker exec sikka sikka send <to-address> 10
docker exec sikka sikka send <to-address> 10 --wait
docker exec sikka sikka bond 400
docker exec sikka sikka unbond

# Transaction still in the mempool?
docker exec sikka sikka status <tx-id>

# Help
docker exec sikka sikka help
```

---

## Config (env)

| Variable | Default in image | Meaning |
| --- | --- | --- |
| `SIKKA_PRIVATE_KEY` | unset | 32-byte seed or full secret (hex); else a key is created under `/data` |
| `SIKKA_TRUSTED_CHECKPOINT` | unset | `<height>:<hash>` trust anchor required when fast-sync crosses more than one height |
| `SIKKA_LOG` | `info` | tracing filter |

Paths, Tor SOCKS (`127.0.0.1:9050`), and bootstrap peers are fixed in the image.
Optional custom genesis: drop a file at `/data/genesis.json` (otherwise baked-in).

`SIKKA_KEYSTORE` / `SIKKA_NODE` are set in the image for the in-container
`sikka` CLI (`docker exec sikka sikka …`), not for `sikka-node` itself.

Do not copy `SIKKA_TRUSTED_CHECKPOINT` from an untrusted peer. Verify the
checkpoint hash independently through multiple operators or a release
announcement first. Any gap beyond one height needs a pin, even when the
validator root is unchanged.

---

## Stop / wipe

```bash
docker stop sikka sikka-2
docker rm sikka sikka-2
docker volume rm sikka-data sikka-2-data   # deletes chain state + keys
```
