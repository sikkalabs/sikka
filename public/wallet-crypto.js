(function () {
  const globalScope = globalThis;
  let walletCryptoPromise = null;

  function toHexString(value) {
    let bytes = value;
    if (value instanceof ArrayBuffer) {
      bytes = new Uint8Array(value);
    } else if (ArrayBuffer.isView(value)) {
      bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }

    if (!(bytes instanceof Uint8Array)) {
      throw new Error('sha3_256 expects bytes.');
    }

    let hex = '';
    for (let index = 0; index < bytes.length; index += 1) {
      hex += bytes[index].toString(16).padStart(2, '0');
    }
    return hex;
  }

  function hasWalletCryptoAPI(api) {
    return !!(
      api &&
      typeof api.generateKeyHex === 'function' &&
      typeof api.generateMnemonic === 'function' &&
      typeof api.deriveKeyPairFromSeedHex === 'function' &&
	      typeof api.deriveKeyPairFromMnemonic === 'function' &&
	      typeof api.sha3Hex === 'function' &&
	      typeof api.mineTxPowNonceHex === 'function'
    );
  }

  function unwrapResult(result, action) {
    if (!result || typeof result !== 'object') {
      throw new Error(action + ' returned an invalid result.');
    }
    if (result.error) {
      throw new Error(String(result.error));
    }
    return result;
  }

  async function loadWalletCrypto() {
    if (hasWalletCryptoAPI(globalScope.sikkaWalletCrypto)) {
      return globalScope.sikkaWalletCrypto;
    }
    if (walletCryptoPromise) {
      return walletCryptoPromise;
    }
    walletCryptoPromise = (async () => {
      if (typeof Go !== 'function') {
        throw new Error('Go WASM runtime is not loaded.');
      }
      if (typeof WebAssembly.instantiateStreaming !== 'function') {
        throw new Error('WebAssembly.instantiateStreaming is required.');
      }
      const go = new Go();
      let wasmUrl = '/public/walletwasm.wasm';
      if (typeof document !== 'undefined') {
        const cs = document.currentScript;
        if (cs && cs.src) {
          wasmUrl = cs.src.replace(/wallet-crypto\.js(\?.*)?$/, 'walletwasm.wasm');
        }
      } else if (typeof self !== 'undefined' && self.location && self.location.href) {
        const href = self.location.href;
        if (/wallet-crypto\.js/.test(href)) {
          wasmUrl = href.replace(/wallet-crypto\.js(\?.*)?$/, 'walletwasm.wasm');
        } else if (/wallet-draft-worker\.js/.test(href)) {
          wasmUrl = href.replace(/wallet-draft-worker\.js(\?.*)?$/, 'walletwasm.wasm');
        }
      }
      const streaming = await WebAssembly.instantiateStreaming(fetch(wasmUrl), go.importObject);
      const instance = streaming.instance;

      go.run(instance);

      const deadline = Date.now() + 5000;
      while (!hasWalletCryptoAPI(globalScope.sikkaWalletCrypto)) {
        if (Date.now() > deadline) {
          throw new Error('wallet crypto module failed to initialize.');
        }
        await new Promise(resolve => setTimeout(resolve, 25));
      }

      return globalScope.sikkaWalletCrypto;
    })().catch(error => {
      walletCryptoPromise = null;
      throw error;
    });
    return walletCryptoPromise;
  }

  async function callWalletCrypto(method, action, ...args) {
    const walletCrypto = await loadWalletCrypto();
    return unwrapResult(walletCrypto[method](...args), action);
  }

  globalScope.ensureWalletCrypto = loadWalletCrypto;
  globalScope.generateWalletKeyPairHex = function () {
    return callWalletCrypto('generateKeyHex', 'generate keypair');
  };
  globalScope.generateWalletMnemonic = function (entropyBits) {
    return callWalletCrypto('generateMnemonic', 'generate mnemonic', entropyBits);
  };
  globalScope.deriveWalletKeyPairFromSeedHex = function (seedHex) {
    return callWalletCrypto('deriveKeyPairFromSeedHex', 'derive keypair from seed', seedHex);
  };
  globalScope.deriveWalletKeyPairFromMnemonic = function (mnemonic, passphrase) {
    return callWalletCrypto('deriveKeyPairFromMnemonic', 'derive keypair from mnemonic', mnemonic, passphrase || '');
  };
  globalScope.deriveWalletPathKeyPairFromSeedHex = function (seedHex, account, branch, index) {
    return callWalletCrypto(
      'derivePathKeyPairFromSeedHex',
      'derive keypair from wallet path',
      seedHex,
      account || 0,
      branch || 0,
      index || 0
    );
  };
  globalScope.deriveWalletPublicKeyHex = function (privateKeyHex) {
    return callWalletCrypto('derivePublicKeyHex', 'derive public key', privateKeyHex);
  };
  globalScope.signWalletPayloadHex = function (privateKeyHex, payloadHex) {
    return callWalletCrypto('signHex', 'sign payload', privateKeyHex, payloadHex);
  };
  globalScope.sha3WalletPayloadHex = function (payloadHex) {
    const walletCrypto = globalScope.sikkaWalletCrypto;
    if (!hasWalletCryptoAPI(walletCrypto)) {
      throw new Error('wallet crypto module is not ready.');
    }
    return unwrapResult(walletCrypto.sha3Hex(payloadHex), 'sha3 hash').digestHex;
  };
  globalScope.sha3_256 = function (payload) {
    return globalScope.sha3WalletPayloadHex(toHexString(payload));
  };
  globalScope.mineWalletTxPowNonceHex = function (txIDHex, arg2, arg3, arg4) {
    // WASM requires (txIDHex, parent0Hex, parent1Hex, requiredBits).
    // Supported JS call shapes:
    //   (txID, parent0, parent1, requiredBits)
    //   (txID, [parent0, parent1], requiredBits)
    let p0 = '';
    let p1 = '';
    let bits = NaN;

    if (Array.isArray(arg2)) {
      if (arg2.length < 2) {
        throw new Error('mineWalletTxPowNonceHex: parentPowHashes array must contain two entries');
      }
      p0 = String(arg2[0] || '');
      p1 = String(arg2[1] || '');
      bits = Number(arg3);
    } else if (typeof arg2 === 'string' && typeof arg3 === 'string' && arg4 !== undefined) {
      p0 = arg2;
      p1 = arg3;
      bits = Number(arg4);
    } else {
      throw new Error('mineWalletTxPowNonceHex requires (txIDHex, parent0Hex, parent1Hex, requiredBits)');
    }

    if (!Number.isFinite(bits) || bits < 0) {
      throw new Error('mineWalletTxPowNonceHex: requiredBits must be a non-negative number');
    }

    return callWalletCrypto('mineTxPowNonceHex', 'mine transaction pow nonce', txIDHex, p0, p1, bits);
  };
})();