importScripts('/public/wallet-common.js', '/public/wasm_exec.js', '/public/wallet-crypto.js');

self.addEventListener('message', async event => {
  const data = event.data || {};
  if (data.type !== 'buildDraft') {
    return;
  }

  try {
    const result = await buildDraftInWorker(data.id, data.payload || {});
    self.postMessage({ id: data.id, type: 'result', result });
  } catch (error) {
    self.postMessage({
      id: data.id,
      type: 'error',
      error: error && error.message ? error.message : String(error)
    });
  }
});

function reportProgress(id, stage, detail) {
  self.postMessage({
    id,
    type: 'progress',
    progress: {
      stage,
      detail: detail || ''
    }
  });
}

async function buildDraftInWorker(id, payload) {
  reportProgress(id, 'initializing', 'Loading wallet cryptography.');
  await ensureWalletCrypto();

  const parents = Array.isArray(payload.parents) ? payload.parents.map(String) : [];
  const selected = Array.isArray(payload.selected) ? payload.selected.map(normalizeSelectedUTXO) : [];
  const outputs = Array.isArray(payload.outputs) ? payload.outputs.map(normalizeDraftOutput) : [];
  const timestamp = Number(payload.timestamp || 0);
  const seedHex = String(payload.seedHex || '');
  const account = Number(payload.account || 0);
  const nodeUrl = String(payload.nodeUrl || '').replace(/\/$/, '');

  if (!seedHex) {
    throw new Error('Draft worker is missing wallet seed data.');
  }

  const draft = {
    id: '',
    parents,
    pow_nonce: 0,
    pow_bits: 0,
    timestamp,
    inputs: selected.map(utxo => ({ txid: utxo.txid, index: utxo.index, witness: null })),
    outputs
  };

  const pairCache = new Map();
  async function getSpendKeyPair(branch, index) {
    const cacheKey = String(branch) + ':' + String(index);
    const cached = pairCache.get(cacheKey);
    if (cached) {
      return cached;
    }
    const pair = await deriveWalletPathKeyPairFromSeedHex(seedHex, account, branch, index);
    pairCache.set(cacheKey, pair);
    return pair;
  }

  reportProgress(id, 'quoting', 'Requesting the current proof-of-work requirement.');
  const powQuote = await fetchPowQuoteDetails(nodeUrl, {
    parents,
    timestamp
  }, { jsonStringify: JSON.stringify });

  for (let inputIndex = 0; inputIndex < selected.length; inputIndex += 1) {
    reportProgress(id, 'signing', 'Signing input ' + (inputIndex + 1) + ' of ' + selected.length + '.');
    const utxo = selected[inputIndex];
    const pair = await getSpendKeyPair(utxo.branch, utxo.pathIndex);
    draft.inputs[inputIndex].witness = await buildSingleSigWitness(draft, inputIndex, utxo, pair.publicKeyHex, pair.privateKeyHex);
  }

  reportProgress(id, 'mining', 'Mining proof-of-work for the draft transaction.');
  const powResult = await minePowNonceWithQuote(computeTxID(draft), draft, powQuote);
  draft.pow_nonce = powResult.nonce;
  draft.pow_bits = powResult.powBits;
  draft.parent_pow_hashes = resolveParentPowHashesForMining(powQuote, draft);
  draft.id = computeTxID(draft);

  reportProgress(id, 'finalizing', 'Preparing the draft result for the main thread.');

  return {
    draft: serializeDraftForMainThread(draft),
    powQuote
  };
}

function normalizeSelectedUTXO(utxo) {
  return {
    txid: String(utxo.txid || ''),
    index: Number(utxo.index || 0),
    address: String(utxo.address || ''),
    value: toBigIntInteger(utxo.value || '0'),
    branch: Number(utxo.branch || 0),
    pathIndex: Number(utxo.pathIndex || 0)
  };
}

function normalizeDraftOutput(output) {
  return {
    address: String(output.address || ''),
    value: toBigIntInteger(output.value || '0')
  };
}

function serializeDraftForMainThread(tx) {
  return {
    id: String(tx.id || ''),
    parents: Array.isArray(tx.parents) ? tx.parents.map(String) : [],
    parent_pow_hashes: Array.isArray(tx.parent_pow_hashes) ? tx.parent_pow_hashes.map(String) : [],
    inputs: Array.isArray(tx.inputs) ? tx.inputs.map(input => ({
      txid: String(input.txid || ''),
      index: Number(input.index || 0),
      witness: input.witness || null
    })) : [],
    outputs: Array.isArray(tx.outputs) ? tx.outputs.map(output => ({
      address: String(output.address || ''),
      value: toBigIntInteger(output.value || '0').toString()
    })) : [],
    pow_nonce: Number(tx.pow_nonce || 0),
    pow_bits: Number(tx.pow_bits || 0),
    timestamp: Number(tx.timestamp || 0)
  };
}

async function buildSingleSigWitness(tx, inputIndex, spentUTXO, publicKeyHex, privateKeyHex) {
  const payload = buildSigningPayloadBytes(tx, inputIndex, spentUTXO);
  const signed = await signWalletPayloadHex(privateKeyHex, toHex(payload));
  return {
    type: 'threshold',
    threshold: {
      threshold: 1,
      public_keys: [publicKeyHex],
      signatures: [signed.signatureHex]
    }
  };
}

function buildSigningPayloadBytes(tx, inputIndex, spentUTXO) {
  const domain = new TextEncoder().encode('sikka:v2:txinput');
  const txIDRaw = fromHex(sha3HexOfBytes(computeTxIDBytes(tx)));
  const addressBytes = new TextEncoder().encode(spentUTXO.address);
  const parts = [
    domain,
    txIDRaw,
    u64be(inputIndex),
    fromHex(spentUTXO.txid),
    u64be(spentUTXO.index),
    u64be(spentUTXO.value),
    u16be(addressBytes.length),
    addressBytes
  ];
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const buffer = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    buffer.set(part, offset);
    offset += part.length;
  }
  return buffer;
}

function computeTxID(tx) {
  return sha3HexOfBytes(computeTxIDBytes(tx));
}

function computeTxIDBytes(tx) {
  const encoder = new TextEncoder();
  const parts = [];
  parts.push(new Uint8Array([0x02]));
  const parents = Array.isArray(tx.parents) ? tx.parents : [];
  parts.push(u32be(parents.length));
  for (const parent of parents) parts.push(hex32(parent));
  const inputs = Array.isArray(tx.inputs) ? tx.inputs : [];
  parts.push(u32be(inputs.length));
  for (const input of inputs) {
    parts.push(hex32(input.txid || ''));
    parts.push(u32be(input.index >>> 0));
  }
  const outputs = Array.isArray(tx.outputs) ? tx.outputs : [];
  parts.push(u32be(outputs.length));
  for (const output of outputs) {
    const addressBytes = encoder.encode(output.address || '');
    parts.push(u16be(addressBytes.length));
    parts.push(addressBytes);
    parts.push(u64be(output.value || 0));
  }
  parts.push(u64be(tx.timestamp || 0));
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function u16be(value) {
  const buffer = new Uint8Array(2);
  new DataView(buffer.buffer).setUint16(0, value & 0xffff, false);
  return buffer;
}

function u32be(value) {
  const buffer = new Uint8Array(4);
  new DataView(buffer.buffer).setUint32(0, value >>> 0, false);
  return buffer;
}

function u64be(value) {
  const bigint = toBigIntInteger(value);
  const buffer = new Uint8Array(8);
  const view = new DataView(buffer.buffer);
  view.setUint32(0, Number(bigint >> 32n) >>> 0, false);
  view.setUint32(4, Number(bigint & 0xffffffffn) >>> 0, false);
  return buffer;
}

function hex32(value) {
  const cleaned = String(value || '').replace(/^0x/, '').padStart(64, '0').slice(0, 64);
  return fromHex(cleaned);
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer), byte => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
  }
  return bytes;
}

function sha3HexOfBytes(buffer) {
  return sha3WalletPayloadHex(toHex(buffer));
}