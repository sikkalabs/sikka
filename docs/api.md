# SIKKA API

Public pages live at the site root. Every machine API is under **`/api/`**.

Nodes listen on port **64552**. Locally: `http://localhost:64552`. Public:
`https://1.sikkalabs.com`.

| Surface | Path |
| --- | --- |
| Landing | `GET /` → `public/index.html` |
| Wallet | `GET /wallet.html` (also `/wallet`) |
| API | `GET/POST /api/…` |

All amounts in API payloads are **CHILLAR** integers (`1 SIKKA = 10⁹ CHILLAR`).
Addresses are `0x` + 64 hex chars (SHA3-256 of an ML-DSA-87 public key). Public
keys and signatures are hex **without** a `0x` prefix.

CORS is open (`Access-Control-Allow-Origin: *`). `OPTIONS` is accepted on every
route.

Errors on federation routes look like `{ "error": "…" }` with HTTP 4xx/5xx.
JSON-RPC errors use `{ "jsonrpc":"2.0", "error":{ "code", "message" }, "id" }`.

---

## Quick index

| Method | Path | Audience |
| --- | --- | --- |
| `GET` | `/` | site |
| `GET` | `/wallet.html` | humans |
| `GET` | `/api/` | discovery JSON |
| `GET` | `/api/health` | ops / probes |
| `POST` | `/api/rpc` | wallets / CLI |
| `POST` | `/api/tx` | peers / clients |
| `GET` | `/api/tx/{id}` | peers |
| `POST` | `/api/tx/sync` | peers |
| `POST` | `/api/vote` | peers |
| `POST` | `/api/checkpoint/proposal` | peers |
| `POST` | `/api/checkpoint/finalized` | peers |
| `GET` | `/api/checkpoint/latest` | peers / clients |
| `GET` | `/api/checkpoint/{height}` | peers / clients |
| `POST` | `/api/peers` | peers |
| `GET` | `/api/state/snapshot` | peers (fast sync) |

---

## Site

### `GET /`

Network status page (`public/index.html`).

### `GET /wallet.html`

Browser wallet (`public/wallet.html`).

---

## Discovery and ops

### `GET /api/`

Software string, chain id, height, this node's address, endpoint list, and RPC
method names.

```bash
curl -s https://1.sikkalabs.com/api/
```

### `GET /api/health`

Lightweight readiness probe.

**Response:** `chain_id`, `height`, `state_root`, `mempool`, `peers`, `validator`.

```bash
curl -s https://1.sikkalabs.com/api/health
```

---

## JSON-RPC (`POST /api/rpc`)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "chain.info",
  "params": null
}
```

```bash
curl -s -X POST https://1.sikkalabs.com/api/rpc \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain.info","params":null}'
```

There is no history API: once a checkpoint is final, only the resulting state
remains. Confirm a payment by reading the recipient's balance.

### `chain.info`

**Params:** `null`

**Result:** `chain_id`, `genesis_fingerprint`, `height`, `state_root`,
`validator_root`, `last_checkpoint_hash`, `last_checkpoint_time`,
`total_supply`, `total_bonded`, `accounts`, `active_validators`,
`checkpoint_tx_interval`, `mempool`, `peers`, `node_address`, `validator`.

### `account.get`

**Params:** `{ "address": "0x…" }`

**Result:** `address`, `exists`, `balance`, `nonce`, `credits`, `credits_now`,
`last_regen_time`, `seconds_until_credit?`, `next_nonce`, `bond?`.

### `account.proof`

**Params:** `{ "address": "0x…" }`

**Result:** Merkle inclusion/absence proof plus the signed checkpoint that
commits to `state_root`.

### `tx.submit`

**Params:** `{ "transaction": { … } }`

**Result:** `{ "id": "0x…", "accepted": true }`

### `tx.status`

**Params:** `{ "id": "0x…" }`

**Result:** `{ "id", "pending", "transaction"? }` — pending means still in the
mempool. After finality the body is forgotten.

### `checkpoint.get`

**Params:** `null` (latest) or `{ "height": 12 }`

Only the last 100 heights are retained.

### `validator.list`

**Params:** `null` — array of validators (`address`, `public_key`, `bond`,
`active_from`, `active`, `unbonding_since?`, `slashed`).

### `peer.list`

**Params:** `null` — peer addresses known to this node.

### `mempool.info`

**Params:** `null` — `{ "pending", "capacity", "until_checkpoint" }`.

---

## Shared types

### Transaction

| Field | Type | Notes |
| --- | --- | --- |
| `kind` | `"transfer"` \| `"bond"` \| `"unbond"` | default `transfer` |
| `from` | address | must equal `SHA3-256(public_key)` |
| `to` | address | recipient; zero address for bond/unbond |
| `amount` | u64 | CHILLAR; `0` for unbond |
| `nonce` | u64 | must match `next_nonce` |
| `timestamp` | u64 | unix seconds; ±5 minutes of node clock |
| `public_key` | hex (2592 bytes) | ML-DSA-87 |
| `signature` | hex (4627 bytes) | context `SIKKA-v1` |

Signing payload (little-endian u64s):  
`SIKKA/tx/v1` ‖ kind_tag ‖ from ‖ to ‖ amount ‖ nonce ‖ timestamp  
(`transfer=0`, `bond=1`, `unbond=2`).

---

## Federation (peer HTTP)

All under `/api/`. Wallets should prefer `/api/rpc`.

### `POST /api/tx`

```json
{ "transaction": { … } }
```

**Response:** `{ "id": "0x…", "accepted": true }`

### `GET /api/tx/{id}`

**Response:** `{ "id": "0x…", "known": true }`

### `POST /api/tx/sync`

```json
{ "filter": { … }, "limit": 1000 }
```

### `POST /api/vote`

```json
{ "vote": { … } }
```

### `POST /api/checkpoint/proposal`

```json
{ "proposal": { … } }
```

### `POST /api/checkpoint/finalized`

```json
{ "checkpoint": { … }, "transactions": [ … ] }
```

### `GET /api/checkpoint/latest`

### `GET /api/checkpoint/{height}`

### `POST /api/peers`

```json
{ "announce": { … } }
```

### `GET /api/state/snapshot`

Full ledger dump for fast sync.

---

## Examples

**Balance**

```bash
curl -s -X POST https://1.sikkalabs.com/api/rpc \
  -H 'content-type: application/json' \
  -d '{
    "jsonrpc":"2.0","id":1,
    "method":"account.get",
    "params":{"address":"0x994992556d62b895dd34da64f4389d16404c81d57a91c737ab641cf652f1c447"}
  }'
```

Prefer the CLI or wallet for signing:

```bash
docker exec sikka sikka send 0x… 10
# or open https://1.sikkalabs.com/wallet.html
```
