# Run SIKKA with Docker

Image: [`ghcr.io/sikkalabs/sikka:latest`](https://github.com/orgs/sikkalabs/packages) (amd64 + arm64).

Port **64552**, data in `/data`, key at `/data/node_key.json`. Genesis is baked
in (supply **19,960,907 SIKKA** to `0x9949…447`).

---

## Pull

```bash
docker pull ghcr.io/sikkalabs/sikka:latest
```

Or build yourself:

```bash
docker build -t ghcr.io/sikkalabs/sikka:latest .
# multi-arch push: ./dockerhub.sh
```

---

## Run a node

Same command for everyone. Admin (#1) uses the seed for `0x9949…447` and
publishes `64552`; joiners pick their own seed and advertise URL. Bootstrap
defaults to `https://1.sikkalabs.com` and `https://2.sikkalabs.com`.

```bash
docker run -d --name sikka \
  -p 64552:64552 \
  -v sikka-data:/data \
  -e SIKKA_PRIVATE_KEY=<seed> \
  -e SIKKA_ADVERTISE=https://1.sikkalabs.com \
  ghcr.io/sikkalabs/sikka:latest
```

Second node: change `--name`, volume, seed, and `SIKKA_ADVERTISE` (e.g.
`sikka-2`, `sikka-2-data`, `https://2.sikkalabs.com`). Publish `-p` only if you
want the site/API on the host.

```bash
docker logs -f sikka
curl -s http://127.0.0.1:64552/api/health
curl -s http://127.0.0.1:64552/          # landing page
open http://127.0.0.1:64552/wallet.html  # browser wallet
```

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

Same pattern on a joiner: `docker exec sikka-2 sikka …`.

---

## Config (env)

| Variable | Default | Meaning |
| --- | --- | --- |
| `SIKKA_PRIVATE_KEY` | unset | 32-byte seed or full secret (hex); else a key is created under `/data` |
| `SIKKA_ADVERTISE` | from host + `64552` | public URL peers should dial |
| `SIKKA_BOOTSTRAP` | `https://1.sikkalabs.com`, `https://2.sikkalabs.com` | first peers |
| `SIKKA_GENESIS` | baked-in if missing | optional custom genesis path |
| `SIKKA_TOR_PROXY` | unset | SOCKS5 for outbound (e.g. Tor) |
| `SIKKA_LOG` | `info` | tracing filter |

---

## Local four-node testnet

From the repo:

```bash
docker compose up --build -d
docker compose run --rm cli info
docker compose run --rm cli balance
docker compose run --rm cli send 0xbbbb…bbbb 100
docker compose stop node4    # quorum is 3/4; chain continues
```

---

## Stop / wipe

```bash
docker stop sikka sikka-2
docker rm sikka sikka-2
docker volume rm sikka-data sikka-2-data   # deletes chain state + keys
```
