/**
 * PQ-hybrid asymmetric encryption for v4 keystores (5.1.0, Phase 4).
 *
 * Off-chain (non-Ethereum) message encryption for v4 uses a HYBRID KEM:
 * X25519 (classical) + ML-KEM-768 (FIPS 203, post-quantum), combined so that
 * BOTH must be broken to recover the shared secret
 * (@noble/post-quantum `ml_kem768_x25519`). The shared secret then drives
 * XChaCha20-Poly1305 AEAD for the message.
 *
 * SCOPE: off-chain message encryption ONLY. On-chain Ethereum
 * signing/addresses remain classical secp256k1 (EVM constraint — a PQ
 * signature is not valid on-chain). See plan §5.4.
 *
 * Design: these are pure functions over keypair bytes. Callers (the v4 vault,
 * or application code) are responsible for generating a keypair per address
 * and persisting the secret key (recommendation: encrypt it under the vault's
 * AEAD, alongside the secp256k1 private key). Keeping this module free of any
 * vault/crypto-state coupling avoids a circular dependency with keystore-v4.
 *
 * The v3 `encryption` module (pure nacl.box) is unchanged and remains for
 * backward compatibility; this module is v4-only.
 */
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

// ---- base64 (no Buffer) ----------------------------------------------------

export function b64encode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
export function b64decode(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- hybrid KEM keypair ----------------------------------------------------

/** A v4 PQ-hybrid (X25519 + ML-KEM-768) encryption keypair. */
export interface PqHybridKeypair {
  /** base64 hybrid public key (1216 bytes) — safe to share. */
  publicKey: string;
  /** base64 hybrid secret key (32 bytes) — SENSITIVE; store encrypted. */
  secretKey: string;
}

export function generatePqKeypair(): PqHybridKeypair {
  const seed = randomBytes(ml_kem768_x25519.lengths.seed);
  const kp = ml_kem768_x25519.keygen(seed);
  return { publicKey: b64encode(kp.publicKey), secretKey: b64encode(kp.secretKey) };
}

/** Re-derive a public key from a stored hybrid secret key (avoids storing both). */
export function pqPublicKeyFromSecret(secretKeyB64: string): string {
  return b64encode(ml_kem768_x25519.getPublicKey(b64decode(secretKeyB64)));
}

// ---- encrypt / decrypt ------------------------------------------------------

export interface PqEncryptedMessage {
  alg: 'x25519-mlkem768-hybrid+xchacha20poly1305';
  /** base64 hybrid KEM ciphertext (1120 bytes). */
  kemCt: string;
  /** base64 AEAD nonce (24 bytes). */
  nonce: string;
  /** base64 message ciphertext. */
  ct: string;
}

const PQ_AAD = 'lw4:pqmsg:4';

/** Encrypt a UTF-8 string to a recipient's hybrid public key. */
export function pqEncryptString(theirPublicKeyB64: string, msg: string): PqEncryptedMessage {
  const pub = b64decode(theirPublicKeyB64);
  const { cipherText: kemCt, sharedSecret } = ml_kem768_x25519.encapsulate(pub);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(sharedSecret, nonce, utf8ToBytes(PQ_AAD)).encrypt(utf8ToBytes(msg));
  return {
    alg: 'x25519-mlkem768-hybrid+xchacha20poly1305',
    kemCt: b64encode(kemCt),
    nonce: b64encode(nonce),
    ct: b64encode(ct),
  };
}

/**
 * Decrypt with the recipient's hybrid secret key. Returns false on any
 * authentication/KEM failure (wrong key, tampered ciphertext, AAD mismatch).
 */
export function pqDecryptString(mySecretKeyB64: string, encMsg: PqEncryptedMessage): string | false {
  try {
    if (encMsg.alg !== 'x25519-mlkem768-hybrid+xchacha20poly1305') return false;
    const sharedSecret = ml_kem768_x25519.decapsulate(b64decode(encMsg.kemCt), b64decode(mySecretKeyB64));
    const pt = xchacha20poly1305(sharedSecret, b64decode(encMsg.nonce), utf8ToBytes(PQ_AAD)).decrypt(
      b64decode(encMsg.ct),
    );
    return new TextDecoder().decode(pt);
  } catch {
    return false;
  }
}
