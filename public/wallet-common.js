// public/wallet-common.js
// Shared pure utilities for Sikka wallet UIs and the draft worker.
// Loaded via <script src> in HTML pages and importScripts() in workers.
// Exposes functions on globalThis / self for easy use in inline scripts.

(function (global) {
  'use strict';

  const CHILLAR_PER_SIKKA = 10_000_000_000n;
  const MIN_UTXO_MATURITY_SECONDS = 600;

  function toBigIntInteger(value) {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        throw new Error('expected integer number');
      }
      return BigInt(String(value));
    }
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!/^-?\d+$/.test(trimmed)) {
        throw new Error('expected integer string');
      }
      return BigInt(trimmed);
    }
    throw new Error('expected integer value');
  }

  function compareBigIntDesc(left, right) {
    if (left === right) return 0;
    return left > right ? -1 : 1;
  }

  function shortHex(value) {
    if (!value) return '--';
    if (value.length <= 20) return value;
    return value.slice(0, 10) + '...' + value.slice(-8);
  }

  function formatSikka(chillar) {
    const amount = toBigIntInteger(chillar);
    const negative = amount < 0n;
    const abs = negative ? -amount : amount;
    const whole = abs / CHILLAR_PER_SIKKA;
    const frac = abs % CHILLAR_PER_SIKKA;
    return (negative ? '-' : '') + whole.toString() + '.' + frac.toString().padStart(10, '0');
  }

  function formatChillar(chillar) {
    return toBigIntInteger(chillar).toString() + ' chillar';
  }

  function parseChillarAmount(input) {
    const value = String(input || '').trim();
    if (!/^\d+$/.test(value)) {
      throw new Error('Enter a positive whole number of chillar.');
    }
    const chillar = BigInt(value);
    if (chillar <= 0n) {
      throw new Error('Enter a positive whole number of chillar.');
    }
    return chillar;
  }

  function parseSikkaAmount(input) {
    const value = String(input || '').trim();
    if (!/^\d+(\.\d+)?$/.test(value)) {
      throw new Error('Enter a positive SIKKA amount (up to 10 decimal places).');
    }
    const parts = value.split('.');
    const whole = BigInt(parts[0] || '0');
    const fractionRaw = parts[1] || '';
    if (fractionRaw.length > 10) {
      throw new Error('SIKKA amounts support at most 10 decimal places.');
    }
    const fraction = BigInt(fractionRaw.padEnd(10, '0'));
    const chillar = whole * CHILLAR_PER_SIKKA + fraction;
    if (chillar <= 0n) {
      throw new Error('Enter a positive SIKKA amount.');
    }
    return chillar;
  }

  function parseSendAmount(input, unit) {
    return unit === 'sikka' ? parseSikkaAmount(input) : parseChillarAmount(input);
  }

  function parseJSONWithBigInts(text) {
    // Server returns large integers for balance/chillar/amount/value as JSON numbers.
    // This forces them to strings so BigInt(toBigIntInteger()) works safely.
    return JSON.parse(text.replace(/("(?:balance|chillar|amount|value|total_supply)")\s*:\s*(-?\d+)/g, '$1:"$2"'));
  }

  function stringifyExactJSON(value) {
    if (value === null) return 'null';
    if (typeof value === 'bigint') return value.toString();
    if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'string') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(stringifyExactJSON).join(',') + ']';
    if (typeof value === 'object') {
      return '{' + Object.entries(value)
        .filter(([, current]) => current !== undefined)
        .map(([key, current]) => JSON.stringify(key) + ':' + stringifyExactJSON(current))
        .join(',') + '}';
    }
    return 'null';
  }

  function stringifyForDisplay(value) {
    return JSON.stringify(value, (_key, current) => typeof current === 'bigint' ? current.toString() : current, 2);
  }

  function normalizeUTXO(utxo) {
    return {
      ...utxo,
      txid: String(utxo.txid || ''),
      index: Number(utxo.index || 0),
      address: String(utxo.address || ''),
      value: toBigIntInteger(utxo.value || '0'),
      dag_depth: Number(utxo.dag_depth || 0),
      created_at: Number(utxo.created_at || 0)
    };
  }

  function formatMaturityCountdown(seconds) {
    const remaining = Math.max(0, Number(seconds) || 0);
    if (remaining < 60) {
      return 'in ' + remaining + 's';
    }
    const minutes = Math.ceil(remaining / 60);
    if (minutes < 60) {
      return 'in ~' + minutes + ' min';
    }
    const hours = Math.floor(minutes / 60);
    const remMinutes = minutes % 60;
    if (hours < 24) {
      return 'in ~' + hours + 'h' + (remMinutes ? ' ' + remMinutes + 'm' : '');
    }
    return 'at ' + new Date((Math.floor(Date.now() / 1000) + remaining) * 1000).toLocaleString();
  }

  function utxoMaturityInfo(utxo, options) {
    const opts = options && typeof options === 'object' ? options : {};
    const genesisTxId = String(opts.genesisTxId || '');
    const now = Number.isFinite(opts.now) ? opts.now : Math.floor(Date.now() / 1000);
    const txid = String(utxo.txid || '');
    const createdAt = Number(utxo.created_at || 0);

    if (genesisTxId && txid === genesisTxId) {
      return {
        mature: true,
        kind: 'genesis',
        createdAt,
        maturesAt: createdAt,
        secondsRemaining: 0,
        label: 'Mature',
        detail: 'Genesis payout'
      };
    }

    if (!createdAt) {
      return {
        mature: false,
        kind: 'missing',
        createdAt: 0,
        maturesAt: null,
        secondsRemaining: null,
        label: 'Immature',
        detail: 'Missing created_at'
      };
    }

    const maturesAt = createdAt + MIN_UTXO_MATURITY_SECONDS;
    const mature = now >= maturesAt;
    const secondsRemaining = mature ? 0 : maturesAt - now;

    return {
      mature,
      kind: mature ? 'mature' : 'immature',
      createdAt,
      maturesAt,
      secondsRemaining,
      label: mature ? 'Mature' : 'Immature',
      detail: mature ? 'Ready to spend' : 'Matures ' + formatMaturityCountdown(secondsRemaining)
    };
  }

  function utxoMaturityBadgeClass(info) {
    if (!info || !info.mature) {
      return 'maturity-badge maturity-badge-immature';
    }
    return 'maturity-badge maturity-badge-mature';
  }

  // --- Bech32m address handling (used for validation/normalization in sends) ---
  const BECH32M_CONST = 0x2bc830a3;
  const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const ADDRESS_HRP = 'sikka';
  const ADDRESS_VERSION = 1;

  function normalizeAddress(address) {
    const trimmed = String(address || '').trim();
    if (!trimmed) throw new Error('Destination address is required.');
    if (trimmed.toLowerCase() !== trimmed && trimmed.toUpperCase() !== trimmed) {
      throw new Error('Address must use a single letter case.');
    }
    const normalized = trimmed.toLowerCase();
    const decoded = decodeBech32mAddress(normalized);
    if (decoded.hrp !== ADDRESS_HRP) {
      throw new Error('Address must start with ' + ADDRESS_HRP + '1.');
    }
    if (decoded.version !== ADDRESS_VERSION) {
      throw new Error('Address version must be ' + ADDRESS_VERSION + '.');
    }
    if (decoded.program.length !== 32) {
      throw new Error('Address program must be 32 bytes.');
    }
    return normalized;
  }

  function decodeBech32mAddress(address) {
    const separator = address.lastIndexOf('1');
    if (separator <= 0 || separator + 7 > address.length) {
      throw new Error('Invalid bech32m address length.');
    }
    const hrp = address.slice(0, separator);
    const encoded = address.slice(separator + 1);
    const values = Array.from(encoded, character => {
      const index = BECH32_CHARSET.indexOf(character);
      if (index < 0) {
        throw new Error('Invalid bech32m character.');
      }
      return index;
    });
    if (!bech32VerifyChecksum(hrp, values, BECH32M_CONST)) {
      throw new Error('Invalid bech32m checksum.');
    }
    const payload = values.slice(0, -6);
    return {
      hrp,
      version: payload[0],
      program: Uint8Array.from(convertBits(payload.slice(1), 5, 8, false))
    };
  }

  function convertBits(data, fromBits, toBits, pad) {
    let acc = 0;
    let bits = 0;
    const maxValue = (1 << toBits) - 1;
    const maxAcc = (1 << (fromBits + toBits - 1)) - 1;
    const out = [];
    for (const value of data) {
      if ((value >> fromBits) !== 0) {
        throw new Error('Invalid address data range.');
      }
      acc = ((acc << fromBits) | value) & maxAcc;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        out.push((acc >> bits) & maxValue);
      }
    }
    if (pad) {
      if (bits > 0) {
        out.push((acc << (toBits - bits)) & maxValue);
      }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxValue) !== 0) {
      throw new Error('Invalid address padding.');
    }
    return out;
  }

  function bech32VerifyChecksum(hrp, data, constant) {
    return bech32Polymod(bech32HrpExpand(hrp).concat(data)) === constant;
  }

  function bech32HrpExpand(hrp) {
    const out = [];
    for (let index = 0; index < hrp.length; index += 1) {
      out.push(hrp.charCodeAt(index) >> 5);
    }
    out.push(0);
    for (let index = 0; index < hrp.length; index += 1) {
      out.push(hrp.charCodeAt(index) & 31);
    }
    return out;
  }

  function bech32Polymod(values) {
    let chk = 1;
    for (const value of values) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ value;
      if (top & 1) chk ^= 0x3b6a57b2;
      if (top & 2) chk ^= 0x26508e6d;
      if (top & 4) chk ^= 0x1ea119fa;
      if (top & 8) chk ^= 0x3d4233dd;
      if (top & 16) chk ^= 0x2a1462b3;
      chk >>>= 0;
    }
    return chk >>> 0;
  }

  // --- Node / fetch helpers (light versions; pages can wrap) ---
  function defaultNodeUrl() {
    if (global.location && (global.location.protocol === 'http:' || global.location.protocol === 'https:')) {
      return global.location.origin.replace(/\/$/, '');
    }
    return 'http://127.0.0.1:64552';
  }

  function normalizeNodeUrl(raw) {
    const trimmed = String(raw || '').trim();
    if (!trimmed) {
      return defaultNodeUrl();
    }
    const withoutTrailingSlash = trimmed.replace(/\/+$/, '');
    try {
      const parsed = new URL(withoutTrailingSlash);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new Error('unsupported protocol');
      }
      return parsed.origin;
    } catch {
      throw new Error('Enter a valid http:// or https:// node URL.');
    }
  }

  function nodeUrlHostLabel(raw) {
    try {
      return new URL(String(raw || '')).host || 'node';
    } catch {
      const text = String(raw || '');
      if (text.length <= 24) return text || 'node';
      return text.slice(0, 10) + '…' + text.slice(-6);
    }
  }

  function normalizeParentPowHashHex(value) {
    const hex = String(value || '').replace(/^0x/i, '').trim().toLowerCase();
    if (!hex) {
      return '';
    }
    if (hex.length !== 64 || !/^[0-9a-f]{64}$/.test(hex)) {
      throw new Error('Parent PoW hash must be 64 hex characters.');
    }
    return hex;
  }

  function resolveParentPowHashesForMining(powQuote, tx) {
    const raw = (powQuote && Array.isArray(powQuote.parentPowHashes))
      ? powQuote.parentPowHashes
      : (Array.isArray(tx && tx.parent_pow_hashes) ? tx.parent_pow_hashes : []);
    return [
      normalizeParentPowHashHex(raw[0]),
      normalizeParentPowHashHex(raw[1])
    ];
  }

  async function minePowNonceWithQuote(txIDHex, tx, powQuote) {
    const requiredBits = Number(powQuote && powQuote.requiredBits);
    if (!Number.isFinite(requiredBits) || requiredBits < 0) {
      throw new Error('PoW quote returned an invalid requirement.');
    }
    const [parent0Hex, parent1Hex] = resolveParentPowHashesForMining(powQuote, tx);
    if (!parent0Hex || !parent1Hex) {
      throw new Error('PoW quote is missing parent_pow_hashes. Refresh the quote or use a current Sikka node.');
    }
    const miner = global.mineWalletTxPowNonceHex;
    if (typeof miner !== 'function') {
      throw new Error('Wallet cryptography is not loaded.');
    }
    const result = await miner(String(txIDHex || ''), parent0Hex, parent1Hex, requiredBits);
    return {
      nonce: Number(result.nonce || 0),
      powBits: Number(result.powBits || requiredBits)
    };
  }

  async function fetchPowQuoteDetails(nodeUrl, payload, opts = {}) {
    const jsonStringify = opts.jsonStringify || JSON.stringify;
    const response = await fetch(String(nodeUrl || '').replace(/\/$/, '') + '/v1/tx/pow-quote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: jsonStringify({
        parents: Array.isArray(payload && payload.parents) ? payload.parents.map(String) : [],
        timestamp: Number((payload && payload.timestamp) || 0)
      })
    });
    const text = await response.text();
    let data = {};
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }
    if (!response.ok) {
      throw new Error(typeof data === 'string' ? data : 'PoW quote failed.');
    }
    const requiredBits = Number(data.required_bits);
    if (!Number.isFinite(requiredBits) || requiredBits < 0) {
      throw new Error('PoW quote returned an invalid requirement.');
    }
    return {
      requiredBits,
      parentPowHashes: Array.isArray(data.parent_pow_hashes) ? data.parent_pow_hashes.map(String) : [],
      recentCount: Number(data.recent_count ?? NaN),
      congestionBuckets: Number(data.congestion_buckets ?? NaN),
      windowSeconds: Number(data.window_seconds ?? NaN)
    };
  }

  // Expose on global (works for main thread and worker after importScripts)
  const api = {
    CHILLAR_PER_SIKKA,
    toBigIntInteger,
    compareBigIntDesc,
    shortHex,
    formatSikka,
    formatChillar,
    parseChillarAmount,
    parseSikkaAmount,
    parseSendAmount,
    parseJSONWithBigInts,
    stringifyExactJSON,
    stringifyForDisplay,
    MIN_UTXO_MATURITY_SECONDS,
    normalizeUTXO,
    utxoMaturityInfo,
    utxoMaturityBadgeClass,
    formatMaturityCountdown,
    normalizeAddress,
    decodeBech32mAddress,
    defaultNodeUrl,
    normalizeNodeUrl,
    nodeUrlHostLabel,
    fetchPowQuoteDetails,
    minePowNonceWithQuote,
    normalizeParentPowHashHex,
    resolveParentPowHashesForMining,
    // Re-export bech32 primitives if needed by advanced consumers
    bech32: {
      verifyChecksum: bech32VerifyChecksum,
      hrpExpand: bech32HrpExpand,
      polymod: bech32Polymod,
      convertBits
    }
  };

  // Attach to both globalThis and self (worker).
  // Inline Vue scripts should destructure from window — method bodies run in
  // strict mode and cannot rely on bare global lookups.
  Object.assign(global, api);
  global.SikkaWalletCommon = api;
  if (typeof self !== 'undefined' && self !== global) {
    Object.assign(self, api);
    self.SikkaWalletCommon = api;
  }

  // For CommonJS / module environments if ever used
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this));
