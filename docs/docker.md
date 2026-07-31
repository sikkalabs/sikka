# Run SIKKA with Docker

Image: [`ghcr.io/sikkalabs/sikka:latest`](https://github.com/orgs/sikkalabs/packages) (amd64 + arm64).

**Peer mesh is Tor.** The image runs `tor` + `sikka-node`: a v3 onion is
derived from the node key and published automatically. Users still use plain
HTTP on port **64552** (wallet / RPC / landing page) on any node they can reach
— localhost or LAN HTTP on that node.

Data in `/data`, key at `/data/node_key.json`, onion keys under `/data/tor/`.
Genesis is baked in (supply **19,960,907 SIKKA** to `0x9949…447`).

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

Same command for everyone. The container derives `http://….onion` from the key
and dials peers over Tor SOCKS. Map `64552` only if you want a local wallet UI.

```bash
docker run -d --name sikka \
  -p 64552:64552 \
  -v sikka-data:/data \
  -e SIKKA_PRIVATE_KEY=<seed> \
  ghcr.io/sikkalabs/sikka:latest
```

```bash
docker logs -f sikka          # shows onion + advertise
docker exec sikka sikka tor-id
curl -s http://127.0.0.1:64552/api/health
curl -s http://127.0.0.1:64552/          # landing page
open http://127.0.0.1:64552/wallet.html  # browser wallet on this node
```

Joiners: different `--name`, volume, and seed. The entrypoint always advertises
the onion derived from that key; peers find each other over Tor.

### Fund and bond (joiners)

Genesis already stakes the admin. A new node needs coins, then a bond (at least
~0.001% of supply ≈ **200 SIKKA** on the default mint):

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
docker exec sikka sikka tor-id
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
| `SIKKA_BOOTSTRAP` | two Tor onions (see `BOOTSTRAP_NODES`) | first peers |
| `SIKKA_GENESIS` | baked-in if missing | optional custom genesis path |
| `SIKKA_LOG` | `info` | tracing filter |
| `SIKKA_TOR_READY_TIMEOUT_SECS` | `300` | how long to wait for Tor `Bootstrapped 100%` before starting the node |

`SIKKA_ADVERTISE` and `SIKKA_TOR_PROXY` are set by the entrypoint from the
derived onion and local Tor SOCKS — do not set them.

Tor writes notices to `/data/tor/notice.log` (not container stdout). Inspect with:

```bash
docker exec sikka tail -n 50 /data/tor/notice.log
```

---

## Stop / wipe

```bash
docker stop sikka sikka-2
docker rm sikka sikka-2
docker volume rm sikka-data sikka-2-data   # deletes chain state + keys + onion
```
