// Modernized deps (Phase 3d). Dropped: crypto-js, ethereumjs-util@6,
// elliptic, bitcore-lib, bitcore-mnemonic, scrypt-async.
// Now: @scure/bip39 (mnemonic), @scure/bip32 (HD), @noble/hashes (scrypt KDF,
// keccak, sha256), @noble/curves (secp256k1 pubkey), tweetnacl (kept).
import { generateMnemonic, validateMnemonic, mnemonicToSeedSync, entropyToMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { HDKey } from '@scure/bip32';
import { scrypt } from '@noble/hashes/scrypt.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import Nacl from 'tweetnacl';
import NaclUtil from 'tweetnacl-util';

// Named imports (not `import * as`) — with verbatimModuleSyntax, namespace
// imports used only in type positions get fully erased from the bundle.
import { derivedKey as assertDerivedKey } from './assert';
import { decodeHex, encodeHex } from './encryption';
import { signTx } from './signing';
import { createTx, txToHexString } from './txutils';

// Minimal hex-prefix helpers (replaces ethereumjs-util).
function addHexPrefix(h: string): string {
  return h.startsWith('0x') ? h : '0x' + h;
}
function stripHexPrefix(h: string): string {
  return h.startsWith('0x') ? h.slice(2) : h;
}

function leftPadString(stringToPad: string, padChar: string, length: number): string {
  let repeatedPadChar = '';

  for (let i = 0; i < length; i++) {
    repeatedPadChar += padChar;
  }

  return (repeatedPadChar + stringToPad).slice(-length);
}

export interface EncryptedStringBlob {
  encStr: string;
  nonce: string;
}

export interface EncryptedKeyBlob {
  key: string;
  nonce: string;
}

export class KeyStore {
  salt: string;
  hdPathString: string;
  encSeed: EncryptedStringBlob | undefined;
  encHdRootPriv: EncryptedStringBlob | undefined;
  version: number;
  hdIndex: number;
  encPrivKeys: Record<string, EncryptedKeyBlob>;
  addresses: string[];

  constructor() {
    this.salt = undefined as any;
    this.hdPathString = undefined as any;
    this.encSeed = undefined;
    this.encHdRootPriv = undefined;
    this.version = 3;
    this.hdIndex = 0;
    this.encPrivKeys = {};
    this.addresses = [];
  }

  init(mnemonic: string, pwDerivedKey: Uint8Array, hdPathString: string, salt: string): void {
    this.salt = salt;
    this.hdPathString = hdPathString;
    this.encSeed = undefined;
    this.encHdRootPriv = undefined;
    this.version = 3;
    this.hdIndex = 0;
    this.encPrivKeys = {};
    this.addresses = [];

    if (typeof pwDerivedKey !== 'undefined' && typeof mnemonic !== 'undefined') {
      const words = mnemonic.split(' ');

      if (!KeyStore.isSeedValid(mnemonic) || words.length !== 12) {
        throw new Error('KeyStore: Invalid mnemonic');
      }

      // Pad the seed to length 120 before encrypting
      const paddedSeed = leftPadString(mnemonic, ' ', 120);
      this.encSeed = KeyStore._encryptString(paddedSeed, pwDerivedKey);

      // hdRoot is the relative root from which we derive the keys using generateNewAddress().
      // The derived keys are then `hdRoot/hdIndex`.

      // BIP39 mnemonic -> seed -> BIP32 root -> derive hdPathString.
      // Store the xpriv (scure privateExtendedKey) — same format as legacy's
      // bitcore .xprivkey, so the vault format is unchanged.
      const seed = mnemonicToSeedSync(mnemonic);
      const hdRootKey = HDKey.fromMasterSeed(seed);
      const hdPathKey = hdRootKey.derive(hdPathString);
      const xpriv = hdPathKey.privateExtendedKey;

      this.encHdRootPriv = KeyStore._encryptString(xpriv, pwDerivedKey);
    }
  }

  isDerivedKeyCorrect(pwDerivedKey: Uint8Array): boolean {
    const paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);

    return Boolean(paddedSeed && paddedSeed.length > 0);
  }

  serialize(): string {
    return JSON.stringify({
      encSeed: this.encSeed,
      encHdRootPriv: this.encHdRootPriv,
      addresses: this.addresses,
      encPrivKeys: this.encPrivKeys,
      hdPathString: this.hdPathString,
      salt: this.salt,
      hdIndex: this.hdIndex,
      version: this.version,
    });
  }

  getAddresses(): string[] {
    return this.addresses.map((addr) => addHexPrefix(addr));
  }

  getSeed(pwDerivedKey: Uint8Array): string {
    assertDerivedKey(this, pwDerivedKey);

    const paddedSeed = KeyStore._decryptString(this.encSeed, pwDerivedKey);

    if (!paddedSeed || paddedSeed.length === 0) {
      throw new Error('Provided password derived key is wrong');
    }

    return paddedSeed.trim();
  }

  exportPrivateKey(address: string, pwDerivedKey: Uint8Array): string {
    assertDerivedKey(this, pwDerivedKey);

    const addr = stripHexPrefix(address).toLowerCase();

    if (this.encPrivKeys[addr] === undefined) {
      throw new Error('KeyStore.exportPrivateKey: Address not found in KeyStore');
    }

    const encPrivateKey = this.encPrivKeys[addr];

    return KeyStore._decryptKey(encPrivateKey, pwDerivedKey);
  }

  generateNewAddress(pwDerivedKey: Uint8Array, n?: number): void {
    assertDerivedKey(this, pwDerivedKey);

    if (!this.encSeed) {
      throw new Error('KeyStore.generateNewAddress: No seed set');
    }

    n = n || 1;

    const keys = this._generatePrivKeys(pwDerivedKey, n);

    for (let i = 0; i < n; i++) {
      const keyObj = keys[i];
      const address = KeyStore._computeAddressFromPrivKey(keyObj.privKey);

      this.encPrivKeys[address] = keyObj.encPrivKey;
      this.addresses.push(address);
    }
  }

  keyFromPassword(password: string, callback: (err: unknown, pwDerivedKey?: Uint8Array) => void): void {
    KeyStore.deriveKeyFromPasswordAndSalt(password, this.salt, callback);
  }

  passwordProvider(callback: (err: unknown, password?: string) => void): void {
    const password = prompt('Enter password to continue', 'Enter password');

    // NOTE: prompt() may return null (user cancelled); 4.0.0 passes it
    // through, and the downstream scrypt call then errors — preserved as-is.
    callback(null, password as string);
  }

  hasAddress(address: string, callback: (err: unknown, hasAddr?: boolean) => void): void {
    const addrToCheck = stripHexPrefix(address);

    if (this.encPrivKeys[addrToCheck] === undefined) {
      const err = new Error('Address not found!');
      callback(err, false);
      return;
    }

    callback(null, true);
  }

  signTransaction(txParams: any, callback: (err: unknown, signedTx?: string) => void): void {
    const { gas, ...params } = txParams;
    const txObj = {
      ...params,
      gasLimit: gas,
    };

    const tx = createTx(txObj);
    const rawTx = txToHexString(tx);
    const signingAddress = stripHexPrefix(txParams.from);

    this.passwordProvider((err, password) => {
      if (err) {
        callback(err);
        return;
      }

      this.keyFromPassword(password as string, (err, pwDerivedKey) => {
        if (err) {
          callback(err);
          return;
        }

        const signedTx = signTx(this, pwDerivedKey as Uint8Array, rawTx, signingAddress);

        callback(null, addHexPrefix(signedTx));
      });
    });
  }

  _generatePrivKeys(pwDerivedKey: Uint8Array, n: number): { privKey: string; encPrivKey: EncryptedKeyBlob }[] {
    assertDerivedKey(this, pwDerivedKey);

    const xpriv = KeyStore._decryptString(this.encHdRootPriv, pwDerivedKey);

    if (!xpriv || xpriv.length === 0) {
      throw new Error('Provided password derived key is wrong');
    }

    // Reconstruct the HD root from the stored xpriv.
    const hdRoot = HDKey.fromExtendedKey(xpriv);

    const keys: { privKey: string; encPrivKey: EncryptedKeyBlob }[] = [];

    for (let i = 0; i < n; i++) {
      const child = hdRoot.deriveChild(this.hdIndex++);
      const privateKeyBuf: Uint8Array = child.privateKey!;
      let privateKeyHex = bytesToHex(privateKeyBuf);

      if (privateKeyBuf.length < 16) {
        // Way too small key, something must have gone wrong
        // Halt and catch fire
        throw new Error('Private key suspiciously small: < 16 bytes. Aborting!');
      } else if (privateKeyBuf.length > 32) {
        throw new Error('Private key larger than 32 bytes. Aborting!');
      } else if (privateKeyBuf.length < 32) {
        // Pad private key if too short
        // bitcore has a bug where it sometimes returns
        // truncated keys
        privateKeyHex = leftPadString(bytesToHex(privateKeyBuf), '0', 64);
      }

      const encPrivateKey = KeyStore._encryptKey(privateKeyHex, pwDerivedKey);

      keys[i] = {
        privKey: privateKeyHex,
        encPrivKey: encPrivateKey,
      };
    }

    return keys;
  }

  static createVault(
    opts: { hdPathString?: string; seedPhrase?: string; password: string; salt?: string },
    cb: (err: unknown, ks?: KeyStore) => void,
  ): void {
    const { hdPathString, seedPhrase, password } = opts;
    let salt = opts.salt;

    // Default hdPathString
    if (!hdPathString) {
      const err = new Error(
        "Keystore: Must include hdPathString in createVault inputs. Suggested alternatives are m/0'/0'/0' for previous lightwallet default, or m/44'/60'/0'/0 for BIP44 (used by Jaxx & MetaMask)",
      );
      return cb(err);
    }

    if (!seedPhrase) {
      const err = new Error('Keystore: Must include seedPhrase in createVault inputs.');
      return cb(err);
    }

    if (!salt) {
      salt = KeyStore.generateSalt(32);
    }

    KeyStore.deriveKeyFromPasswordAndSalt(password, salt, (err, pwDerivedKey) => {
      if (err) {
        cb(err);
        return;
      }

      const ks = new KeyStore();

      ks.init(seedPhrase as string, pwDerivedKey as Uint8Array, hdPathString as string, salt as string);

      cb(null, ks);
    });
  }

  static generateSalt(byteCount?: number): string {
    // CSPRNG (Phase 3 §4.3: switched from BitCore.crypto.Random).
    return NaclUtil.encodeBase64(randomBytes(byteCount || 32));
  }

  // Generates a random seed. If the optional string extraEntropy is set,
  //  a random set of entropy is created, then concatenated with extraEntropy
  //  and hashed to produce the entropy that gives the seed.
  // Thus if extraEntropy comes from a high-entropy source (like dice)
  //  it can give some protection from a bad RNG.
  // If extraEntropy is not set, the random number generator is used directly.
  static generateRandomSeed(extraEntropy?: string): string {
    let seed: string;

    if (extraEntropy === undefined) {
      seed = generateMnemonic(wordlist);
    } else if (typeof extraEntropy === 'string') {
      const entBuf = utf8ToBytes(extraEntropy);
      const randBuf = randomBytes(256 / 8);
      const hashedEnt = this._concatAndSha256(randBuf, entBuf).slice(0, 128 / 8);

      seed = entropyToMnemonic(hashedEnt, wordlist);
    } else {
      throw new Error('generateRandomSeed: extraEntropy is set but not a string.');
    }

    return seed;
  }

  static isSeedValid(seed: string): boolean {
    return validateMnemonic(seed, wordlist);
  }

  static deserialize(keystore: string): KeyStore {
    const dataKS = JSON.parse(keystore);
    const { version, salt, encSeed, encHdRootPriv, encPrivKeys, hdIndex, hdPathString, addresses } = dataKS;

    if (version === undefined || version < 3) {
      throw new Error(
        'Old version of serialized keystore. Please use KeyStore.upgradeOldSerialized() to convert it to the latest version.',
      );
    }

    const ks = new KeyStore();

    ks.salt = salt;
    ks.hdPathString = hdPathString;
    ks.encSeed = encSeed;
    ks.encHdRootPriv = encHdRootPriv;
    ks.version = version;
    ks.hdIndex = hdIndex;
    ks.encPrivKeys = encPrivKeys;
    ks.addresses = addresses;

    return ks;
  }

  static deriveKeyFromPasswordAndSalt(
    password: string,
    salt: string | ((err: unknown, derivedKey?: Uint8Array) => void),
    callback?: (err: unknown, derivedKey?: Uint8Array) => void,
  ): void {
    // Do not require salt, and default it to 'lightwalletSalt'
    // (for backwards compatibility)
    if (!callback && typeof salt === 'function') {
      callback = salt;
      salt = KeyStore.DEFAULT_SALT;
    } else if (!salt && typeof callback === 'function') {
      salt = KeyStore.DEFAULT_SALT;
    }

    const N = 2 ** 14; // logN = 14
    const r = 8;
    const p = 1;
    const dkLen = 32;

    // @noble/hashes scrypt is byte-identical to scrypt-async at these params
    // (golden-pinned). Async via setTimeout to preserve the non-blocking
    // contract scrypt-async provided (interruptStep yielded to the event loop).
    setTimeout(() => {
      let err: unknown = null;
      let ui8arr: Uint8Array | undefined;

      try {
        ui8arr = scrypt(password, salt as string, { N, r, p, dkLen });
      } catch (e) {
        err = e;
      }

      (callback as (err: unknown, derivedKey?: Uint8Array) => void)(err, ui8arr);
    }, 0);
  }

  static _encryptString(string: string, pwDerivedKey: Uint8Array): EncryptedStringBlob {
    const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
    const encStr = Nacl.secretbox(NaclUtil.decodeUTF8(string), nonce, pwDerivedKey);

    return {
      encStr: NaclUtil.encodeBase64(encStr),
      nonce: NaclUtil.encodeBase64(nonce),
    };
  }

  static _decryptString(encryptedStr: EncryptedStringBlob | undefined, pwDerivedKey: Uint8Array): string | false {
    // NOTE: undefined input (empty keystore fields) surfaces here as a
    // TypeError in 4.0.0 via decodeBase64(undefined) — behavior preserved;
    // the non-null assertion only documents the runtime invariant.
    const decStr = NaclUtil.decodeBase64(encryptedStr!.encStr);
    const nonce = NaclUtil.decodeBase64(encryptedStr!.nonce);

    const decryptedStr = Nacl.secretbox.open(decStr, nonce, pwDerivedKey);

    if (decryptedStr === null) {
      return false;
    }

    return NaclUtil.encodeUTF8(decryptedStr);
  }

  static _encryptKey(privateKey: string, pwDerivedKey: Uint8Array): EncryptedKeyBlob {
    const nonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);
    const privateKeyArray = decodeHex(privateKey);
    const encKey = Nacl.secretbox(privateKeyArray, nonce, pwDerivedKey);

    return {
      key: NaclUtil.encodeBase64(encKey),
      nonce: NaclUtil.encodeBase64(nonce),
    };
  }

  static _decryptKey(encryptedKey: EncryptedKeyBlob, pwDerivedKey: Uint8Array): string {
    const decKey = NaclUtil.decodeBase64(encryptedKey.key);
    const nonce = NaclUtil.decodeBase64(encryptedKey.nonce);
    const decryptedKey = Nacl.secretbox.open(decKey, nonce, pwDerivedKey);

    if (decryptedKey === null) {
      throw new Error('Decryption failed!');
    }

    return encodeHex(decryptedKey);
  }

  static _computeAddressFromPrivKey(privateKey: string): string {
    // secp256k1 pubkey (uncompressed, drop 0x04) -> keccak256 -> last 20 bytes.
    // noble keccak_256 == crypto-js SHA3 quirk for these inputs (golden-pinned).
    const privBytes = hexToBytes(privateKey.padStart(64, '0'));
    const pubKey = secp256k1.getPublicKey(privBytes, false).slice(1);
    const hash = keccak_256(pubKey);

    return bytesToHex(hash.slice(-20));
  }

  static _computePubkeyFromPrivKey(privKey: string, curve: string): string {
    if (curve !== 'curve25519') {
      throw new Error('KeyStore._computePubkeyFromPrivKey: Only "curve25519" supported.');
    }

    const privateKeyUInt8Array = hexToBytes(privKey);
    const pubKey = Nacl.box.keyPair.fromSecretKey(privateKeyUInt8Array).publicKey;

    return bytesToHex(pubKey);
  }

  // This function is tested using the test vectors here:
  // http://www.di-mgt.com.au/sha_testvectors.html
  static _concatAndSha256(entropyBuf0: Uint8Array, entropyBuf1: Uint8Array): Uint8Array {
    const totalEnt = new Uint8Array(entropyBuf0.length + entropyBuf1.length);
    totalEnt.set(entropyBuf0, 0);
    totalEnt.set(entropyBuf1, entropyBuf0.length);

    return Buffer.from(sha256(totalEnt));
  }

  static DEFAULT_SALT = 'lightwalletSalt';
}
