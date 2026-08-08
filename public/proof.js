/**
 * Trustless account proof verification for browser wallets.
 *
 * Ports the Rust flow in crates/wallet/src/proof.rs:
 * checkpoint quorum (ML-DSA-87) + SMT path to state_root + account leaf hash.
 *
 * Validator set trust: pass pinned genesis validators out-of-band for full
 * trustlessness, or fetch active validators from the node (weak subjectivity).
 */

import { ml_dsa87 } from "https://esm.sh/@noble/post-quantum@0.6.1/ml-dsa.js";
import { sha3_256 } from "https://esm.sh/@noble/hashes@2.2.0/sha3.js";

const PK_LEN = 2592;
const SIG_LEN = 4627;

const SMT_LEAF_TAG = new TextEncoder().encode("SIKKA/smt-leaf/v1");
const SMT_NODE_TAG = new TextEncoder().encode("SIKKA/smt-node/v1");
const ACCOUNT_LEAF_TAG = new TextEncoder().encode("SIKKA/account-leaf/v1");
const CHECKPOINT_TAG = new TextEncoder().encode("SIKKA/checkpoint/v4");
const VOTE_TAG = new TextEncoder().encode("SIKKA/vote/v5");
const SIGNING_CONTEXT = new TextEncoder().encode("SIKKA-v1");
const EMPTY_HASH = new Uint8Array(32);
const MAX_DEPTH = 256;
const VOTE_PRECOMMIT = 1;

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function u64le(n) {
  const v = BigInt(n);
  if (v < 0n || v > 0xffffffffffffffffn) throw new Error("u64 out of range");
  const out = new Uint8Array(8);
  let x = v;
  for (let i = 0; i < 8; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function u32le(n) {
  const v = Number(n);
  if (!Number.isInteger(v) || v < 0 || v > 0xffffffff) {
    throw new Error("u32 out of range");
  }
  return Uint8Array.of(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
}

function encodeStr(text) {
  const bytes = new TextEncoder().encode(text);
  return concat(u32le(bytes.length), bytes);
}

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function unhex(text) {
  const clean = String(text).trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2) {
    throw new Error("expected even-length hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function normalizeAddress(text) {
  const bytes = unhex(text);
  if (bytes.length !== 32) {
    throw new Error("address must be 32 bytes (64 hex chars)");
  }
  return "0x" + hex(bytes);
}

function normalizeHash(text) {
  const bytes = unhex(text);
  if (bytes.length !== 32) throw new Error("hash must be 32 bytes");
  return bytes;
}

function asBig(v) {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(Math.trunc(v));
  if (typeof v === "string") return BigInt(v);
  return 0n;
}

function digestParts(parts) {
  return sha3_256(concat(...parts));
}

function bit(key, index) {
  const byteIndex = index >> 3;
  return ((key[byteIndex] >> (7 - (index & 7))) & 1) === 1;
}

function smtLeafHash(key, value) {
  return digestParts([SMT_LEAF_TAG, key, value]);
}

function smtNodeHash(left, right) {
  return digestParts([SMT_NODE_TAG, left, right]);
}

/** Account::encode — balance, nonce, battery (u32), last_regen_time. */
function encodeAccount(account) {
  return concat(
    u64le(account.balance),
    u64le(account.nonce),
    u32le(account.battery),
    u64le(account.last_regen_time)
  );
}

/** Account::leaf_hash — binds address and every field. */
export function accountLeafHash(account, addressBytes) {
  const body = concat(addressBytes, encodeAccount(account));
  return digestParts([ACCOUNT_LEAF_TAG, body]);
}

/** CheckpointHeader::encode (SIKKA/checkpoint/v4 — includes genesis fingerprint) */
function encodeCheckpointHeader(header) {
  if (header.genesis_fingerprint == null) {
    throw new Error("checkpoint header missing genesis_fingerprint");
  }
  return concat(
    u64le(header.height),
    normalizeHash(header.prev_hash),
    normalizeHash(header.state_root),
    normalizeHash(header.validator_root),
    normalizeHash(header.tx_root),
    u32le(header.tx_count),
    u64le(header.timestamp),
    unhex(header.proposer),
    u32le(header.round),
    u64le(header.total_supply),
    u64le(header.total_bonded),
    encodeStr(header.chain_id),
    normalizeHash(header.genesis_fingerprint)
  );
}

export function checkpointHash(checkpoint) {
  const header = checkpointHeader(checkpoint);
  return digestParts([CHECKPOINT_TAG, encodeCheckpointHeader(header)]);
}

function checkpointHeader(checkpoint) {
  if (checkpoint.header) return checkpoint.header;
  return checkpoint;
}

/** vote_signing_bytes — SIKKA/vote/v5 binds chain_id + genesis_fingerprint */
export function voteSigningBytes(
  chainId,
  genesisFingerprintBytes,
  height,
  round,
  kindTag,
  checkpointHashBytes
) {
  return concat(
    VOTE_TAG,
    encodeStr(chainId),
    genesisFingerprintBytes,
    u64le(height),
    u32le(round),
    Uint8Array.of(kindTag),
    checkpointHashBytes
  );
}

export function quorumBond(totalActiveBond) {
  const t = BigInt(totalActiveBond);
  if (t === 0n) return 0n;
  const num = 2n * t;
  return (num + 3n - 1n) / 3n;
}

function foldProof(proof, key, start) {
  let current = start;
  const siblings = proof.siblings || [];
  for (let depth = siblings.length - 1; depth >= 0; depth--) {
    const sibling = normalizeHash(siblings[depth]);
    current = bit(key, depth)
      ? smtNodeHash(sibling, current)
      : smtNodeHash(current, sibling);
  }
  return current;
}

/** SMT Proof::verify */
export function verifySmtProof(proof, rootBytes, keyBytes, valueBytes) {
  const siblings = proof.siblings || [];
  if (siblings.length > MAX_DEPTH) return false;
  const leaf = proof.leaf;
  if (!leaf) return false;
  const leafKey = unhex(leaf.key);
  const leafValue = normalizeHash(leaf.value);
  if (hex(leafKey) !== hex(keyBytes)) return false;
  if (hex(leafValue) !== hex(valueBytes)) return false;
  const folded = foldProof(proof, keyBytes, smtLeafHash(keyBytes, valueBytes));
  return hex(folded) === hex(rootBytes);
}

/** SMT Proof::verify_absent */
export function verifySmtAbsent(proof, rootBytes, keyBytes) {
  const siblings = proof.siblings || [];
  if (siblings.length > MAX_DEPTH) return false;
  const leaf = proof.leaf;
  if (!leaf) {
    const folded = foldProof(proof, keyBytes, EMPTY_HASH);
    return hex(folded) === hex(rootBytes);
  }
  const leafKey = unhex(leaf.key);
  if (hex(leafKey) === hex(keyBytes)) return false;
  const sharesPrefix = siblings.every((_, depth) => bit(leafKey, depth) === bit(keyBytes, depth));
  if (!sharesPrefix) return false;
  const leafValue = normalizeHash(leaf.value);
  const folded = foldProof(proof, keyBytes, smtLeafHash(leafKey, leafValue));
  return hex(folded) === hex(rootBytes);
}

/**
 * Build authorized validator tuples from validator.list RPC result.
 * Only active validators participate in quorum.
 */
export function validatorsFromList(list, { activeOnly = true } = {}) {
  if (!Array.isArray(list)) return [];
  return list
    .filter((v) => !activeOnly || v.active)
    .map((v) => ({
      address: normalizeAddress(v.address),
      publicKey: unhex(v.public_key),
      bond: asBig(v.bond),
    }));
}

/**
 * Verify checkpoint validator_signatures against an authorized set.
 * Returns the number of distinct valid signatures.
 */
export function verifyCheckpointSignatures(checkpoint, validators) {
  if (!validators || validators.length === 0) {
    throw new Error("quorum not reached: no trusted validator set (pin genesis validators)");
  }

  const header = checkpointHeader(checkpoint);
  const cpHash = checkpointHash(checkpoint);
  const authorized = new Map();
  let totalBond = 0n;
  for (const v of validators) {
    const addr = normalizeAddress(v.address);
    if (v.publicKey.length !== PK_LEN) {
      throw new Error(`validator ${addr}: public key must be ${PK_LEN} bytes`);
    }
    authorized.set(addr, { publicKey: v.publicKey, bond: BigInt(v.bond) });
    totalBond += BigInt(v.bond);
  }

  const sigs = checkpoint.validator_signatures;
  if (!Array.isArray(sigs) || sigs.length === 0) {
    throw new Error("checkpoint has no validator signatures");
  }

  if (header.genesis_fingerprint == null) {
    throw new Error("checkpoint header missing genesis_fingerprint");
  }
  const genesisFp = normalizeHash(header.genesis_fingerprint);

  const seen = new Set();
  let bonded = 0n;
  const payload = voteSigningBytes(
    header.chain_id,
    genesisFp,
    header.height,
    header.round,
    VOTE_PRECOMMIT,
    cpHash
  );

  for (const sig of sigs) {
    const voter = normalizeAddress(sig.validator);
    if (seen.has(voter)) {
      throw new Error(`duplicate signature from ${voter}`);
    }
    seen.add(voter);

    const entry = authorized.get(voter);
    if (!entry) {
      throw new Error(`unknown voter ${voter}`);
    }

    const pubKey = unhex(sig.public_key);
    if (pubKey.length !== PK_LEN) {
      throw new Error(`invalid public key for ${voter}`);
    }
    if (hex(pubKey) !== hex(entry.publicKey)) {
      throw new Error(`address/key mismatch for ${voter}`);
    }

    const signature = unhex(sig.signature);
    if (signature.length !== SIG_LEN) {
      throw new Error(`invalid signature length for ${voter}`);
    }

    const ok = ml_dsa87.verify(signature, payload, pubKey, {
      context: SIGNING_CONTEXT,
    });
    if (!ok) {
      throw new Error(`invalid signature from ${voter}`);
    }

    bonded += entry.bond;
  }

  const needed = quorumBond(totalBond);
  if (bonded < needed) {
    throw new Error(
      `quorum not reached: bonded ${bonded} < needed ${needed} (of ${totalBond} total)`
    );
  }

  return seen.size;
}

/**
 * Verify an account.proof RPC result.
 *
 * @param {object} proof — account.proof result
 * @param {object} options
 * @param {Array<{address, publicKey, bond}>} [options.pinnedValidators] — genesis set pinned OOB
 * @param {Array<{address, publicKey, bond}>} [options.validators] — active set (e.g. from validator.list)
 * @param {string} [options.genesisFingerprint] — if set, must match chainInfo.genesis_fingerprint
 * @param {object} [options.chainInfo] — chain.info result for genesis cross-check
 * @returns {{ address, account, balance, nonce, height, stateRoot, signatures }}
 */
export function verifyAccountProof(proof, options = {}) {
  if (!proof || typeof proof !== "object") {
    throw new Error("invalid proof");
  }
  if (!proof.checkpoint) {
    throw new Error("proof missing signed checkpoint");
  }

  const header = checkpointHeader(proof.checkpoint);
  const { genesisFingerprint, chainInfo } = options;
  if (genesisFingerprint != null) {
    const expected = normalizeHash(genesisFingerprint);
    if (header.genesis_fingerprint == null) {
      throw new Error("checkpoint missing genesis_fingerprint");
    }
    const fromHeader = normalizeHash(header.genesis_fingerprint);
    if (hex(expected) !== hex(fromHeader)) {
      throw new Error("genesis fingerprint mismatch — wrong chain or untrusted node");
    }
    if (chainInfo?.genesis_fingerprint != null) {
      const fromInfo = normalizeHash(chainInfo.genesis_fingerprint);
      if (hex(expected) !== hex(fromInfo)) {
        throw new Error("chain.info genesis fingerprint mismatch");
      }
    }
  }

  const stateRoot = normalizeHash(proof.state_root);
  const committed = normalizeHash(header.state_root);
  if (hex(stateRoot) !== hex(committed)) {
    throw new Error("proof state_root does not match checkpoint");
  }

  const validators = options.pinnedValidators ?? options.validators;
  const signatures = verifyCheckpointSignatures(proof.checkpoint, validators);

  const address = normalizeAddress(proof.address);
  const key = unhex(address);

  let smtOk;
  if (proof.account != null) {
    const account = {
      balance: asBig(proof.account.balance),
      nonce: asBig(proof.account.nonce),
      battery: Number(proof.account.battery),
      last_regen_time: asBig(proof.account.last_regen_time),
    };
    const leaf = accountLeafHash(account, key);
    smtOk = verifySmtProof(proof.proof, stateRoot, key, leaf);
  } else {
    smtOk = verifySmtAbsent(proof.proof, stateRoot, key);
  }

  if (!smtOk) {
    throw new Error("invalid Merkle proof — account data does not match state root");
  }

  const balance = proof.account != null ? asBig(proof.account.balance) : 0n;
  const nonce = proof.account != null ? asBig(proof.account.nonce) : 0n;

  return {
    address,
    account: proof.account ?? null,
    balance,
    nonce,
    height: asBig(header.height),
    stateRoot: "0x" + hex(stateRoot),
    signatures,
  };
}
