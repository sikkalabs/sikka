# Node HTTP API

This document describes the HTTP routes currently served by the Sikka node.

Base URL during local Docker use:

```text
http://127.0.0.1:64552
```

## Conventions

- JSON responses use `Content-Type: application/json`.
- CORS is enabled with `Access-Control-Allow-Origin: *`.
- Supported CORS methods are `GET`, `POST`, and `OPTIONS`.
- `OPTIONS` requests return `204 No Content`.
- Most validation failures on `POST` endpoints return `400 Bad Request` with a plain-text error body.
- Missing resources return `404 Not Found`.
- Addresses accepted by runtime endpoints are lower-case `sikka1...` bech32m addresses.
- POST request bodies are capped at **1 MiB** (`http.MaxBytesReader` on all JSON POST routes).
- List endpoints return a unified pagination envelope (see below). Invalid resume keys return `400 Bad Request`.

### List response envelope

Paged list routes return:

```json
{
  "items": [ … ],
  "page": {
    "limit": 100,
    "has_more": true,
    "next": { "after_global": 899 }
  },
  "meta": { … }
}
```

- `items`: page payload (transactions, UTXOs, peer URLs, etc.)
- `page.limit`: effective page size for this response
- `page.has_more`: whether another page exists
- `page.next`: resume keys for the following request (omitted when `has_more` is `false`)
- `meta`: route-specific fields that are not part of the page (balances, `dag_size`, etc.)

### Request and response limits

| Endpoint | Limit |
| -------- | ----- |
| All `POST` JSON bodies | 1 MiB max |
| `POST /v1/sync` | `have` ≤ 64 tx IDs; `limit` ≤ 200 transactions per response (default 200) |
| `GET/POST /v1/sync/tail` | default `limit` 100, max 2000; ≤ 64 filter addresses |
| `GET /v1/address/{address}` | default UTXO `limit` 100, max 500; `meta.balance` / `meta.utxo_count` always full |
| `GET /v1/discovery/nodes` | default `limit` 32, max 64 |
| `POST /v1/txs` | ≤ 1024 transaction IDs per request (not paginated) |
| Outbound peer JSON (node as client) | 4 MiB max per response |

## Route Summary

| Method | Path                     | Purpose                                                    |
| ------ | ------------------------ | ---------------------------------------------------------- |
| `GET`  | `/`                      | Node homepage                                              |
| `GET`  | `/healthz`               | Process health check                                       |
| `GET`  | `/v1/status`             | Runtime, DAG, and Tor status                               |
| `GET`  | `/v1/tx/{txid}/weight`   | Cumulative weight and confirmation state for a transaction |
| `GET`  | `/v1/sync/status`        | Federation sync metadata (caught-up check via tips_fingerprint + dag_size) |
| `POST` | `/v1/sync`               | `sync_v1` federation catch-up; returns exactly the transactions the caller is missing |
| `GET/POST` | `/v1/sync/tail`      | Recent transactions from the end (or after_global). Primary for light clients / history |
| `GET`  | `/v1/discovery/nodes`    | Known peer directory                                       |
| `POST` | `/v1/discovery/announce` | Announce a node address set                                |
| `GET`  | `/v1/tx/{txid}`          | Transaction lookup                                         |
| `GET`  | `/v1/address/{address}`  | Address summary and spendable outputs                      |
| `POST` | `/v1/tx/submit`          | Submit a DAG transaction                                   |

## Health And Runtime

### `GET /healthz`

Simple process health check.

Example response:

```json
{
  "status": "ok"
}
```

### `GET /v1/status`

Returns node runtime settings plus high-level DAG, federation, and Tor state.

Response fields:

- `addresses`: advertised addresses for this node; in the current runtime this is the node's onion address
- `node_address`: Sikka donation address from `nodeaddress` (valid `sikka1…` bech32m), or the network genesis address when unset
- `node_message`: short node blurb from `nodemessage`, or `SIKKA` + `software_version` when unset
- `software_version`: software release version from embedded release metadata
- `protocol_version`: HTTP federation protocol version
- `capabilities`: optional sync and relay features supported by this node
- `api_listen`: HTTP listen address inside the container
- `known_node_count`: known HTTP nodes tracked in memory
- `configured_nodes`: built-in bootstrap node URLs used by this node
- `sync_interval_s`: federation polling interval in seconds
- `last_sync_at`: latest successful sync time in RFC3339 format, or empty if none yet
- `last_sync_source`: upstream URL used for the latest sync, or empty if none yet
- `last_sync_error`: last sync error text, or empty if the latest sync succeeded
- `dag_size`: total number of transactions currently in the DAG
- `genesis_tx_id`: transaction ID of the genesis transaction
- `tip_count`: current number of open tips
- `tips`: current open tip transaction IDs
- `max_dag_depth`: current longest path from genesis to any tip
- `submit_pow_base_bits`: base PoW bits before congestion surcharges apply
- `submit_pow_window_seconds`: recent-history window used for congestion pricing
- `submit_pow_target_tps`: target throughput before congestion surcharges apply
- `submit_pow_bucket_tx`: extra recent transactions required to enter the next congestion bucket
- `submit_pow_bucket_bits`: additional PoW bits charged for each congestion bucket
- `submit_pow_bucket_work_factor`: expected work multiplier for each congestion bucket
- `max_future_skew_seconds`: largest future timestamp skew accepted by validators
- `submit_pow_override_bits`: optional fixed PoW override used by non-production runtimes
- `data_dir`: node data directory
- `total_supply`: total supply constant, in chillar
- `enabled`: whether the managed Tor runtime is enabled
- `mode`: currently `managed`
- `onion_hostname`: onion hostname derived from the node's deterministic Tor identity
- `control_connected`: whether the node currently has a Tor control connection it can query
- `network_health`: high-level Tor network state, such as `connected`, `bootstrapping`, `starting`, `degraded`, or `unavailable`
- `bootstrap_progress`: latest Tor bootstrap percentage reported by the control port
- `bootstrap_tag`: current Tor bootstrap phase tag
- `bootstrap_summary`: current Tor bootstrap summary string
- `bootstrap_warning`: latest Tor bootstrap warning or reason string, if any
- `circuit_established`: whether Tor reports that a client circuit is established
- `control_error`: latest Tor control query error string, or empty if the query succeeded

Example response:

```json
{
  "addresses": ["http://l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad.onion"],
  "software_version": "0.0.3",
  "protocol_version": "1",
  "capabilities": ["sync_v1", "relay_v1"],
  "api_listen": "0.0.0.0:64552",
  "known_node_count": 3,
  "configured_nodes": [
    "http://eyd2lhqvifuqm3ynkix5d22fpp4bwyrsqft2mkt63hmmudqktmsk52id.onion",
    "http://sfn7igfjj4vwat2m3lnkwrv3iu4jqhnlqzzj4lgz6nsvrjwkxq66jsid.onion"
  ],
  "sync_interval_s": 15,
  "last_sync_at": "2026-05-21T16:00:00Z",
  "last_sync_source": "http://seed.example.onion",
  "last_sync_error": "",
  "dag_size": 42,
  "genesis_tx_id": "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
  "tip_count": 6,
  "tips": ["8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2", "2d7e6aef6f1fd3e4b6c96fdb723807b2cfe0a2d8d6c8db3ddcb48bd8f2f0712a"],
  "max_dag_depth": 18,
  "submit_pow_base_bits": 2,
  "submit_pow_window_seconds": 60,
  "submit_pow_target_tps": 1,
  "submit_pow_bucket_tx": 60,
  "submit_pow_bucket_bits": 2,
  "submit_pow_bucket_work_factor": 4,
  "max_future_skew_seconds": 300,
  "data_dir": "/home/sikka/data",
  "total_supply": 2100000000000000000,
  "enabled": true,
  "mode": "managed",
  "onion_hostname": "l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad.onion",
  "control_connected": true,
  "network_health": "connected",
  "bootstrap_progress": 100,
  "bootstrap_tag": "done",
  "bootstrap_summary": "Done",
  "bootstrap_warning": "",
  "circuit_established": true,
  "control_error": ""
}
```

### `GET /v1/tx/{txid}/weight`

Returns cumulative weight and confirmation state for a transaction already in the DAG.

Example response:

```json
{
  "txid": "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
  "weight": 200,
  "confirmed": true
}
```

## Federation And Discovery

### `GET /v1/sync/status`

Returns metadata used to validate announced peers and check whether federation catch-up is needed.

When `dag_size` and `tips_fingerprint` match the client’s local DAG, the client can skip `POST /v1/sync` entirely (relay usually keeps nodes close; sync is often a no-op).

Response fields:

- `addresses`: advertised addresses for this node
- `software_version`, `protocol_version`, `capabilities`
- `configured_nodes`, `known_node_count`
- `dag_size`, `tip_count`, `max_dag_depth`, `tips_fingerprint`
- `genesis_tx_id`, `order` (canonical DAG ordering identifier)

Example response:

```json
{
  "addresses": ["http://l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad.onion"],
  "software_version": "0.0.3",
  "protocol_version": "1",
  "capabilities": ["sync_v1", "relay_v1"],
  "configured_nodes": ["http://eyd2lhqvifuqm3ynkix5d22fpp4bwyrsqft2mkt63hmmudqktmsk52id.onion"],
  "known_node_count": 4,
  "dag_size": 42,
  "tip_count": 1,
  "max_dag_depth": 5,
  "tips_fingerprint": "a1b2c3...",
  "genesis_tx_id": "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
  "order": "dag_depth_timestamp_txid_v1"
}
```

### `GET /v1/discovery/nodes`

Returns known peers in score order (highest first), skipping peers in failure backoff. The node’s own advertised URL is always first when available.

Query parameters:

- `limit` (default **32**, max **64**)
- `after_peer_score` and `after_peer_url` (both required together): resume after the peer given in the previous page’s `page.next.after_peer`

Example response:

```json
{
  "items": [
    "http://l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad.onion",
    "http://eyd2lhqvifuqm3ynkix5d22fpp4bwyrsqft2mkt63hmmudqktmsk52id.onion"
  ],
  "page": {
    "limit": 32,
    "has_more": false
  }
}
```

### `POST /v1/discovery/announce`

Registers one or more node addresses with the receiving node's directory.

Request body:

```json
{
  "addresses": ["http://l5satjgud6gucryazcyvyvhuxhr74u6ygigiuyixe3a6ysis67ororad.onion"]
}
```

Behavior:

- invalid JSON returns `400`
- missing or invalid `addresses` returns `400`
- the receiving node immediately probes submitted addresses through `GET /v1/sync/status`
- the peer is only kept if an announced address responds and matches the local protocol and genesis transaction ID
- accepted announcements are persisted in the local node book for future restarts

Example response:

```json
{
  "status": "accepted",
  "known_node_count": 5
}
```

## Transaction And Address Data

### `GET /v1/tx/{txid}`

Returns a transaction by transaction ID.

Path parameters:

- `txid`: transaction ID

The response is the full DAG transaction object.

Example response:

```json
{
  "id": "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
  "parents": ["5c1a...", "2f8b..."],
  "inputs": [
    {
      "txid": "abcd...",
      "index": 0,
      "witness": {
        "type": "threshold",
        "threshold": {
          "threshold": 1,
          "public_keys": ["3081..."],
          "signatures": ["1c9f..."]
        }
      }
    }
  ],
  "outputs": [
    {
      "address": "sikka1...",
      "value": 125000000
    }
  ],
  "pow_nonce": 9137,
  "pow_bits": 20,
  "timestamp": 1710000000
}
```

### `GET /v1/address/{address}`

Returns the full balance summary and a page of spendable outputs for an address.

Query parameters:

- `limit` (default **100**, max **500**): maximum UTXOs in `items`
- `after_outpoint_txid` and `after_outpoint_index` (both required together): resume after the outpoint from `page.next.after_outpoint`

`meta` fields (always complete, not paginated):

- `address`: requested address
- `balance`: integer balance in chillar across all UTXOs
- `utxo_count`: total number of spendable outputs

`items`: UTXO objects sorted by `dag_depth` ascending.

Example response:

```json
{
  "items": [
    {
      "txid": "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
      "index": 0,
      "address": "sikka1...",
      "value": 125000000,
      "dag_depth": 18
    }
  ],
  "page": {
    "limit": 100,
    "has_more": false
  },
  "meta": {
    "address": "sikka1...",
    "balance": 125000000,
    "utxo_count": 1
  }
}
```

### `POST /v1/tx/submit`

Validates and submits a transaction directly into the DAG.

Behavior:

- invalid JSON returns `400`
- validation failures return `400` with a plain-text error message
- the transaction must include exactly 2 parents
- the transaction must include a non-zero `timestamp`
- the transaction timestamp must be at least the newest parent timestamp and no more than `300` seconds into the future
- inputs and outputs must balance exactly
- the transaction must satisfy the congestion-based PoW requirement before submission
- accepted transactions are relayed to known HTTP nodes with hop-limited forwarding

### `GET /v1/sync/tail` (or POST with body)

Dedicated, low-overhead endpoint for recent transactions in canonical DAG order.

Query / body parameters:

- `limit` (default **100**, max **2000**)
- `addresses` (max **64**): server-side filter — only transactions touching any listed address (outputs or resolved input addresses)
- Unfiltered (no `addresses`):
  - First page: returns the most recent `limit` transactions in chronological order
  - `after_global` (optional): exclusive upper bound global index; omit on the first request, then pass `page.next.after_global` to load older pages
- Filtered (`addresses` set):
  - Newest-first scan; `items` are in chronological order within the page
  - `after_global_index` (optional): resume scanning below this global index
- POST body: omit `after_global` / `after_global_index` on the first request; include them only when continuing from `page.next` (zero is valid once explicitly provided as a resume key)
- When `addresses` is set, use `after_global_index` (not `after_global`) for pagination

`meta.dag_size` is always the current DAG length.

Example (unfiltered tail):

```json
{
  "items": [ { "id": "…", "parents": [], "outputs": [], "timestamp": 1710000000 } ],
  "page": {
    "limit": 100,
    "has_more": true,
    "next": { "after_global": 12299 }
  },
  "meta": { "dag_size": 12345 }
}
```

This is the preferred method for wallet history, explorers, and light clients.

### `POST /v1/sync`

`sync_v1` federation catch-up. The client sends a sparse `have` list of transaction IDs it already knows (most-recent first, with exponential back-spacing from the tip). The server computes the exact set the caller is missing as:

> ancestor closure of the server's current tips **minus** ancestor closures of every recognized `have` anchor

and returns up to `limit` of those transactions in canonical DAG order. Peers advertise this via the `sync_v1` capability.

Request:

```json
{
  "have": ["8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2", "2d7e6aef6f1fd3e4b6c96fdb723807b2cfe0a2d8d6c8db3ddcb48bd8f2f0712a"],
  "limit": 200,
  "cursor": 0
}
```

Request fields:

- `have`: tx IDs the caller knows it has, most-recent first (max **64**)
- `limit` (default **200**, max **200**): transactions per page
- `cursor`: offset into the server-computed missing set for this request (`0` to start a page)

Response:

```json
{
  "common_base": "2d7e6aef6f1fd3e4b6c96fdb723807b2cfe0a2d8d6c8db3ddcb48bd8f2f0712a",
  "items": [ { "id": "…", "parents": [], "outputs": [], "timestamp": 1710000000 } ],
  "want": ["abc123..."],
  "has_more": true,
  "cursor": 200,
  "meta": {
    "dag_size": 12345,
    "order": "dag_depth_timestamp_txid_v1"
  }
}
```

Response fields:

- `common_base`: first recognized `have` ID (most-recent shared anchor; diagnostic only)
- `items`: full transactions the caller is missing, in canonical order
- `want`: `have` IDs the server does not have — a hint for the caller to push those txs back
- `has_more` / `cursor`: pagination offsets into the missing set computed for this request

**Reference client pagination:** call `GET /v1/sync/status` first and skip the loop when already caught up. Each page rebuilds `have` from the updated local DAG, sends `cursor: 0`, imports `items`, and repeats until `items` is empty (or a page imports nothing new). A post-sync status check confirms `dag_size` and `tips_fingerprint` match. If the server returns txs in `want`, the reference client relays them back to the peer.

**Third-party pagination:** keep `have` fixed across pages and pass `cursor` from the previous response while `has_more` is `true`. Do not rebuild `have` mid-pagination — the server recomputes the missing set on every request.

### `POST /v1/txs`

Bulk fetch endpoint to retrieve multiple transactions in a single request (max **1024** IDs per call). Not paginated.

Request body: JSON array of transaction ID strings.

```json
[
  "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2"
]
```

Example response:

```json
{
  "items": [
    {
      "id": "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
      "timestamp": 1710000000
    }
  ],
  "page": { "limit": 1, "has_more": false },
  "meta": { "requested": 1, "found": 1 }
}
```

Missing IDs are omitted from `items`.

### `POST /v1/tx/pow-quote`

Returns the current PoW requirement for a candidate transaction timestamp and parent set.

Request body:

```json
{
  "parents": [
    "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
    "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2"
  ],
  "timestamp": 1710000000
}
```

Example response:

```json
{
  "required_bits": 2,
  "base_bits": 2,
  "recent_count": 1,
  "congestion_buckets": 0,
  "window_seconds": 60,
  "bucket_tx": 60,
  "bucket_bits": 2,
  "parent_pow_hashes": [
    "a1b2c3...64hexpowhashofparent0",
    "d4e5f6...64hexpowhashofparent1"
  ]
}
```

Request body:

```json
{
  "parents": ["5c1a...", "2f8b..."],
  "inputs": [
    {
      "txid": "prevtx...",
      "index": 0,
      "witness": {
        "type": "threshold",
        "threshold": {
          "threshold": 1,
          "public_keys": ["3081..."],
          "signatures": ["1c9f..."]
        }
      }
    }
  ],
  "outputs": [
    {
      "address": "sikka1...",
      "value": 125000000
    }
  ],
  "pow_nonce": 9137,
  "pow_bits": 20,
  "timestamp": 1710000000
}
```

Witness notes:

- the live witness type is `threshold`
- `threshold.public_keys` must be sorted, unique, and match the address being spent
- `threshold.signatures` is parallel to `public_keys`; use an empty string for a listed key that did not sign
- a partially signed transaction is rejected until the threshold is satisfied

Success response:

```json
{
  "txid": "8ae7070941b21041927ec10ab9cfc30dcd399b6619fd7c809ec6e66df90f70d2",
  "status": "accepted"
}
```

## Non-API Routes

### `GET /`

Serves the node homepage from `public/index.html`.
