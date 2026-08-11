# Building a SIKKA wallet

A wallet is a key + JSON-RPC. It holds **no chain history**. Reference
implementation: [`public/wallet.html`](../public/wallet.html).

---

## Keys

| Piece | Size | Notes |
| --- | --- | --- |
| Seed | 32 bytes | short secret; expand with ML-DSA-87 keygen |
| Public key | 2592 bytes | hex, **no** `0x` |
| Private key | 4896 bytes | full ML-DSA-87 secret (what the CLI keystore stores) |
| Address | 32 bytes | `0x` + hex(`SHA3-256(public_key)`) |
| Signature | 4627 bytes | hex, **no** `0x` |

In JS ([`@noble/post-quantum`](https://esm.sh/@noble/post-quantum)):

```js
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { sha3_256 } from "@noble/hashes/sha3.js";

const seed = crypto.getRandomValues(new Uint8Array(32));
const { secretKey, publicKey } = ml_dsa87.keygen(seed);
const address = "0x" + hex(sha3_256(publicKey));
```

Same seed always expands to the same key.

### HD receive (`walletpro.html`)

One **master** 32-byte seed → many receive accounts (no change chain):

```text
child_seed_i = SHA3-256(master ‖ "SIKKA/recv/v1" ‖ u32le(i))
key_i        = ML-DSA-87.keygen(child_seed_i)
```

Restore walks `i = 0,1,…` with `account.get` and stops after **10** consecutive
unused accounts (`exists` / balance / nonce / bond all empty). The browser also
stores `next_index` so unused receive addresses beyond the gap are not lost.
UI: [`/walletpro.html`](../public/walletpro.html).

---

## Talk to a node

`POST {node}/api/rpc`

```json
{ "jsonrpc": "2.0", "id": 1, "method": "account.get",
  "params": { "address": "0x…" } }
```

Useful methods: `chain.info`, `account.get`, `account.proof`, `tx.submit`,
`tx.status`. Amounts on the wire are **CHILLAR** integers
(`1 SIKKA = 10⁹ CHILLAR`). Prefer a BigInt-safe JSON parser — supply can exceed
`Number.MAX_SAFE_INTEGER`.

Full RPC: [`api.md`](api.md).

---

## Sign a transfer

1. `chain.info` → take `chain_id` and `genesis_fingerprint` (exact values; do not invent them).
2. `account.get` → use `next_nonce`.
3. Build signing bytes (matches `Transaction::signing_bytes`):

```text
SIKKA/tx/v1 ‖ str(chain_id) ‖ genesis_fingerprint ‖ kind ‖ from ‖ to ‖ amount ‖ nonce ‖ timestamp ‖ public_key
```

`str(s)` is `u32` little-endian UTF-8 length + UTF-8 bytes (same as the Rust
codec `Writer::str`).  
`genesis_fingerprint`: 32 raw bytes from `chain.info`.  
`kind`: transfer `0`, bond `1`, unbond `2`.  
`from` / `to`: 32 raw address bytes.  
`amount` / `nonce` / `timestamp`: little-endian `u64`.  
`public_key`: raw 2592-byte ML-DSA-87 key (bound into the id and signature).  
`amount` is CHILLAR. Bond/unbond use the zero address as `to`; unbond amount is `0`.

4. Sign with ML-DSA-87 and context **`SIKKA-v1`**:

```js
const signature = ml_dsa87.sign(msg, secretKey, {
  context: new TextEncoder().encode("SIKKA-v1"),
});
```

5. `tx.submit` with:

```json
{
  "kind": "transfer",
  "from": "0x…",
  "to": "0x…",
  "amount": 1000000000,
  "nonce": 0,
  "timestamp": 1720000000,
  "chain_id": "sikka",
  "genesis_fingerprint": "0x…",
  "public_key": "<2592-byte hex>",
  "signature": "<4627-byte hex>"
}
```

`timestamp` is unix seconds; must be within ±5 minutes of the node clock. Each
send burns **1 battery** (regen +1/min, cap 100).

---

## Confirming payment

There is no tx history after finality. Re-read the recipient with `account.get`
(or `account.proof` if you don’t trust the node). `tx.status` only tells you if
something is still in the mempool.

---

## Also available

- Browser wallet on any node: `/wallet.html`
- HD receive wallet: `/walletpro.html`
- CLI inside the container: `docker exec sikka sikka …` — see [`docker.md`](docker.md)
