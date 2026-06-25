# Stake a SIKKA Docker node

Staking on SIKKA is **bonding the node’s own account**. There is no delegation:
the key in `/data/node_key.json` is the validator. The in-container CLI signs
with that key and talks to `http://127.0.0.1:64552` inside the same container.

Run a node first: [`docker.md`](docker.md).

---

## What you get

| | |
| --- | --- |
| Minimum bond | `supply / 100,000` ≈ **200 SIKKA** on the default mint |
| Activation | one checkpoint after the bond is final (`active_from = height + 1`) |
| Rewards | **1.5%/year** inflation, paid to the active set, weighted by bond |
| Unbonding | 7 days; voting and rewards stop immediately; stake stays slashable |
| Slash | equivocation only — downtime never burns stake |

A second `bond` on the same account **adds** to the existing stake (must not
be unbonding or slashed).

---

## 1. Start the node

```bash
docker run -d --name sikka \
  -p 64552:64552 \
  -v sikka-data:/data \
  -e SIKKA_PRIVATE_KEY=<32-byte-seed-hex> \
  ghcr.io/sikkalabs/sikka:latest
```

The same seed is the validator identity **and** the Tor onion. Keep it.

```bash
docker exec sikka sikka address          # this is the account you fund and bond
docker exec sikka sikka info             # advertise = http://….onion
docker exec sikka sikka balance
```

`info` prints `(validator)` next to `node` once this key is in the active set.

---

## 2. Fund it

A new node has no coins. Send at least the minimum bond (plus a little extra)
to the address from step 1.

**Another Docker node** (local mesh / genesis operator):

```bash
docker exec sikka-2 sikka address
docker exec sikka sikka send <joiner-address> 400 --wait
```

**Browser wallet** on any node: open `/wallet.html`, send to the joiner
address. Amounts in the wallet are SIKKA; the CLI `send` / `bond` amounts are
SIKKA too.

Fresh accounts start at **0 battery**. Wait **one minute** after the funding
payment is final, then check:

```bash
docker exec sikka sikka balance
```

You need **1 battery** to submit the bond (regen +1/min, cap 10). Bonding
burns one charge, same as any other transaction.

---

## 3. Bond

```bash
docker exec sikka sikka bond 400
```

The CLI prints a transaction id and:

```text
you become an active validator one checkpoint after this is final
```

Confirm it landed:

```bash
docker exec sikka sikka balance          # liquid down, bond shown
docker exec sikka sikka validators       # your address: pending, then active
docker exec sikka sikka info             # node … (validator)
```

`validators` states:

| State | Meaning |
| --- | --- |
| `pending` | bonded, not yet voting (waiting for the next height) |
| `active` | in the committee; earns inflation; may be proposer |
| `unbonding` | cooldown running; not voting; still slashable |
| `slashed` | equivocated; bond burned; cannot return |

Peers reach you over Tor automatically. You do not set an advertise URL.

---

## 4. Add more stake

```bash
docker exec sikka sikka bond 200
```

The new total must stay ≥ the current minimum (`supply / 100,000`). Rejected
if you are already unbonding or slashed.

---

## 5. Unbond

```bash
docker exec sikka sikka unbond
```

That starts the **7-day** cooldown (`UNBONDING_SECS`). You drop out of the
active set at the next checkpoint: no votes, no inflation. The bond is still
slashable until it is released.

You do not send a second transaction. After seven days, a later checkpoint
credits the bond back to your liquid balance and removes the validator record.

```bash
docker exec sikka sikka validators       # unbonding
docker exec sikka sikka balance          # bond gone, liquid restored — after the cooldown
```

You cannot bond again until the unbond has fully released.

---

## Rules that surprise people

- **No delegation.** Staking a Docker node means bonding *that container’s*
  key. A browser wallet with a different seed is a different account.
- **Battery.** A brand-new funded address cannot bond in the same minute.
- **Minimum tracks supply.** Inflation slowly raises the floor; `bond` uses
  the supply at the checkpoint that includes the transaction.
- **Offline is not slashed.** Repeated full-batch proposer misses (default
  **100**) force a *normal* unbond — stake is returned, not burned. Only two
  conflicting votes at the same `(height, round, kind)` burn the bond.
- **Keep the node up.** The image already runs Tor + `sikka-node`. If Tor
  dies, the container exits so Docker `restart` policies bring both back.

---

## Useful commands

```bash
docker exec sikka sikka address
docker exec sikka sikka balance
docker exec sikka sikka info
docker exec sikka sikka validators
docker exec sikka sikka peers            # onion mesh
docker exec sikka sikka bond 400
docker exec sikka sikka unbond
docker exec sikka sikka status <tx-id>   # still in the mempool?
```

Protocol detail: whitepaper §10 (consensus) and §12 (validator economics).
Ops: [`docker.md`](docker.md).
