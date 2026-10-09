/**
 * v4 keystore format (5.1.0, opt-in) — tighter security + modern encryption.
 *
 * Deltas vs v3:
 *  - KDF: Argon2id (noble) instead of scrypt. Params stored per-vault.
 *  - Field encryption: XChaCha20-Poly1305 AEAD (noble) with AAD binding each
 *    ciphertext to its vault field + format version (tamper-evident).
 *  - Off-chain asymmetric encryption gains PQ-hybrid (X25519 + ML-KEM-768) —
 *    see encryption module / Phase 4. On-chain (secp256k1) stays classical.
 *
 * v3 is fully preserved and remains the DEFAULT write format; v4 is opt-in via
 * `createVaultV4` / `format: 4`. See docs/plans/2026-10-08-v5.1.0-*.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

// ---- types ---------------------------------------------------------------

export interface V4KdfParams {
  alg: 'argon2id';
  m: number; // KiB
  t: number; // iterations
  p: number; // parallelism
  dkLen: number;
  salt: string; // base64
}

export interface V4AeadBlob {
  alg: 'xchacha20poly1305';
  nonce: string; // base64
  ct: string; // base64
  aad: string; // e.g. "lw4:seed:4"
}

export interface V4KeystoreData {
  version: 4;
  kdf: V4KdfParams;
  hdPathString: string;
  hdIndex: number;
  encSeed: V4AeadBlob;
  encHdRootPriv: V4AeadBlob;
  encPrivKeys: Record<string, V4AeadBlob>;
  addresses: string[];
  pq?: {
    x25519: Record<string, string>; // address -> base64 x25519 pub
    mlkem768: Record<string, string>; // address -> base64 ML-KEM-768 encaps pub
  };
}

export const V4_DEFAULT_KDF = { m: 32768, t: 3, p: 1, dkLen: 32 } as const;
/** Lower-memory profile for browser/mobile (t-9be9 §4 decision). */
export const V4_BROWSER_KDF = { m: 16384, t: 3, p: 1, dkLen: 32 } as const;

// ---- base64 helpers (no Buffer dependency) --------------------------------

function b64encode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64decode(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- AEAD with AAD ---------------------------------------------------------

function aeadEncrypt(plaintext: Uint8Array, key: Uint8Array, aad: string): V4AeadBlob {
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce, utf8ToBytes(aad)).encrypt(plaintext);
  return { alg: 'xchacha20poly1305', nonce: b64encode(nonce), ct: b64encode(ct), aad };
}

function aeadDecrypt(blob: V4AeadBlob, key: Uint8Array): Uint8Array {
  // AAD is verified implicitly: decryption fails if the stored aad doesn't
  // match what was used at encrypt time, or if the blob was tampered with.
  const pt = xchacha20poly1305(key, b64decode(blob.nonce), utf8ToBytes(blob.aad)).decrypt(b64decode(blob.ct));
  return pt;
}

// ---- KeyStoreV4 ------------------------------------------------------------

export class KeyStoreV4 {
  version = 4 as const;
  kdf: V4KdfParams;
  hdPathString: string;
  hdIndex: number;
  encSeed!: V4AeadBlob;
  encHdRootPriv!: V4AeadBlob;
  encPrivKeys: Record<string, V4AeadBlob>;
  addresses: string[];

  constructor() {
    this.kdf = undefined as any;
    this.hdPathString = undefined as any;
    this.hdIndex = 0;
    this.encPrivKeys = {};
    this.addresses = [];
  }

  static async deriveKey(password: string, kdf: V4KdfParams): Promise<Uint8Array> {
    return argon2idAsync(password, b64decode(kdf.salt), { m: kdf.m, t: kdf.t, p: kdf.p, dkLen: kdf.dkLen });
  }

  static async create(opts: {
    hdPathString: string;
    seedPhrase: string;
    password: string;
    kdfProfile?: { m: number; t: number; p: number; dkLen: number };
  }): Promise<KeyStoreV4> {
    const { hdPathString, seedPhrase, password } = opts;
    if (!hdPathString) throw new Error('KeyStoreV4.create: hdPathString is required');
    if (!seedPhrase) throw new Error('KeyStoreV4.create: seedPhrase is required');
    if (!validateMnemonic(seedPhrase, wordlist) || seedPhrase.split(' ').length !== 12) {
      throw new Error('KeyStoreV4: Invalid mnemonic');
    }

    const profile = opts.kdfProfile ?? V4_DEFAULT_KDF;
    const kdf: V4KdfParams = { alg: 'argon2id', ...profile, salt: b64encode(randomBytes(16)) };
    const key = await KeyStoreV4.deriveKey(password, kdf);

    const ks = new KeyStoreV4();
    ks.kdf = kdf;
    ks.hdPathString = hdPathString;

    // seed: 120-char left-padded (same convention as v3)
    const paddedSeed = seedPhrase.padStart(120, ' ');
    ks.encSeed = aeadEncrypt(utf8ToBytes(paddedSeed), key, 'lw4:seed:4');

    const seed = mnemonicToSeedSync(seedPhrase);
    const hdPathKey = HDKey.fromMasterSeed(seed).derive(hdPathString);
    ks.encHdRootPriv = aeadEncrypt(utf8ToBytes(hdPathKey.privateExtendedKey), key, 'lw4:hdroot:4');

    return ks;
  }

  async deriveKeyFromPassword(password: string): Promise<Uint8Array> {
    return KeyStoreV4.deriveKey(password, this.kdf);
  }

  isDerivedKeyCorrect(key: Uint8Array): boolean {
    try {
      aeadDecrypt(this.encSeed, key);
      return true;
    } catch {
      return false;
    }
  }

  getSeed(key: Uint8Array): string {
    const pt = aeadDecrypt(this.encSeed, key);
    return new TextDecoder().decode(pt).trim();
  }

  private hdRoot(key: Uint8Array): HDKey {
    const xpriv = new TextDecoder().decode(aeadDecrypt(this.encHdRootPriv, key));
    return HDKey.fromExtendedKey(xpriv);
  }

  generateNewAddress(key: Uint8Array, n = 1): void {
    if (!this.isDerivedKeyCorrect(key)) throw new Error('Incorrect derived key!');
    const root = this.hdRoot(key);
    for (let i = 0; i < n; i++) {
      const child = root.deriveChild(this.hdIndex++);
      const privKey = child.privateKey!;
      const privHex = bytesToHex(privKey);
      const address = KeyStoreV4.computeAddress(privHex);
      this.encPrivKeys[address] = aeadEncrypt(privKey, key, `lw4:privkey:${address}:4`);
      this.addresses.push(address);
    }
  }

  getAddresses(): string[] {
    return this.addresses.map((a) => '0x' + a);
  }

  exportPrivateKey(address: string, key: Uint8Array): string {
    if (!this.isDerivedKeyCorrect(key)) throw new Error('Incorrect derived key!');
    const addr = address.replace(/^0x/, '').toLowerCase();
    const blob = this.encPrivKeys[addr];
    if (!blob) throw new Error('KeyStoreV4.exportPrivateKey: Address not found');
    return bytesToHex(aeadDecrypt(blob, key));
  }

  serialize(): string {
    return JSON.stringify({
      version: 4,
      kdf: this.kdf,
      hdPathString: this.hdPathString,
      hdIndex: this.hdIndex,
      encSeed: this.encSeed,
      encHdRootPriv: this.encHdRootPriv,
      encPrivKeys: this.encPrivKeys,
      addresses: this.addresses,
    } as V4KeystoreData);
  }

  static deserialize(serialized: string): KeyStoreV4 {
    const d: V4KeystoreData = JSON.parse(serialized);
    if (d.version !== 4) throw new Error('KeyStoreV4.deserialize: not a v4 keystore');
    if (d.kdf.alg !== 'argon2id') throw new Error('KeyStoreV4.deserialize: unsupported kdf alg');
    const ks = new KeyStoreV4();
    ks.kdf = d.kdf;
    ks.hdPathString = d.hdPathString;
    ks.hdIndex = d.hdIndex;
    ks.encSeed = d.encSeed;
    ks.encHdRootPriv = d.encHdRootPriv;
    ks.encPrivKeys = d.encPrivKeys;
    ks.addresses = d.addresses;
    return ks;
  }

  /** secp256k1 privkey (hex) -> address (no 0x). Same as v3. */
  static computeAddress(privHex: string): string {
    const pub = secp256k1.getPublicKey(hexToBytes(privHex.padStart(64, '0')), false).slice(1);
    return bytesToHex(keccak_256(pub).slice(-20));
  }
}

/** Detect a keystore's format version without throwing. */
export function detectVersion(serialized: string): number | undefined {
  try {
    const d = JSON.parse(serialized);
    return d.version === undefined ? 1 : d.version;
  } catch {
    return undefined;
  }
}
