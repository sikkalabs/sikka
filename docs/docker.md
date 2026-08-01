# Run SIKKA with Docker

Image: [`ghcr.io/sikkalabs/sikka:latest`](https://github.com/orgs/sikkalabs/packages) (amd64 + arm64).

**Peer mesh is clearnet HTTP(S).** The image runs `sikka-node` only. Bootstrap
defaults to `https://1.sikkalabs.com`, `https://2.sikkalabs.com`, and
`https://3.sikkalabs.com`. Set `SIKKA_NODE_URL` to the public URL other nodes
should dial for this instance. Users hit plain HTTP on port **64552** (wallet /
RPC / landing page) locally, or your reverse-proxied HTTPS hostname.

Data in `/data`, key at `/data/node_key.json`, and resumable state snapshot
chunks under `/data/snapshots/`. Snapshot sync is chunked and zstd-compressed so
interrupted downloads continue from the last verified chunk. Genesis is baked in
(supply **19,960,907 SIKKA**: cold admin mint at `0x9949…447`, three validators
each with **20,000 bonded** + **20,000 liquid**).

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

Map `64552` and advertise the clearnet URL peers should use:

```bash
docker run -d --name sikka \
  -p 64552:64552 \
  -v sikka-data:/data \
  -e SIKKA_PRIVATE_KEY=<seed> \
  -e SIKKA_NODE_URL=https://1.sikkalabs.com \
  ghcr.io/sikkalabs/sikka:latest
```

```bash
docker logs -f sikka
curl -s http://127.0.0.1:64552/api/health
curl -s http://127.0.0.1:64552/          # landing page
open http://127.0.0.1:64552/wallet.html  # browser wallet on this node
```

Joiners: different `--name`, volume, seed, and `SIKKA_NODE_URL`.

### Fund and bond (joiners)

Genesis already stakes three operators. A new node needs coins, then a bond (at
least ~0.001% of supply ≈ **200 SIKKA** on the default mint):

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
| `SIKKA_NODE_URL` | `http://$HOSTNAME:64552` | public URL peers should dial for this node (`SIKKA_ADVERTISE` still works as an alias) |
| `SIKKA_BOOTSTRAP` | `https://1.sikkalabs.com,https://2.sikkalabs.com,https://3.sikkalabs.com` | first peers |
| `SIKKA_GENESIS` | baked-in if missing | optional custom genesis path |
| `SIKKA_TRUSTED_CHECKPOINT` | unset | `<height>:<hash>` trust anchor required when fast-sync crosses more than one height |
| `SIKKA_LOG` | `info` | tracing filter |

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
