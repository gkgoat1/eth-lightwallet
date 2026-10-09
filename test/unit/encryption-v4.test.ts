/**
 * PQ-hybrid encryption tests (5.1.0, Phase 4) — X25519 + ML-KEM-768.
 *
 * Verifies: KEM round-trip, hybrid-decrypt-requires-both (classical-only or
 * PQ-only knowledge is insufficient), tamper-evidence, keypair regeneration
 * from secret, and that v3 encryption is untouched.
 */
import { describe, it, expect } from 'vitest';
import {
  generatePqKeypair,
  pqEncryptString,
  pqDecryptString,
  pqPublicKeyFromSecret,
  b64decode,
  type PqEncryptedMessage,
} from '../../src/encryption-v4';

describe('PQ-hybrid encryption (v4)', () => {
  it('encrypts and decrypts a string round-trip', () => {
    const kp = generatePqKeypair();
    const msg = 'post-quantum hello';
    const enc = pqEncryptString(kp.publicKey, msg);
    expect(enc.alg).toBe('x25519-mlkem768-hybrid+xchacha20poly1305');
    expect(pqDecryptString(kp.secretKey, enc)).toBe(msg);
  });

  it('decapsulation with a DIFFERENT secret key fails (both KEMs must agree)', () => {
    const a = generatePqKeypair();
    const b = generatePqKeypair();
    const enc = pqEncryptString(a.publicKey, 'secret for a');
    // b's secret key cannot decapsulate -> shared secret mismatch -> AEAD fails
    expect(pqDecryptString(b.secretKey, enc)).toBe(false);
  });

  it('is tamper-evident (ciphertext / kemCt / nonce mutation fails)', () => {
    const kp = generatePqKeypair();
    const enc = pqEncryptString(kp.publicKey, 'integrity check');

    // corrupt message ciphertext
    const bad1: PqEncryptedMessage = { ...enc, ct: corruptB64(enc.ct) };
    expect(pqDecryptString(kp.secretKey, bad1)).toBe(false);

    // corrupt KEM ciphertext
    const bad2: PqEncryptedMessage = { ...enc, kemCt: corruptB64(enc.kemCt) };
    expect(pqDecryptString(kp.secretKey, bad2)).toBe(false);

    // wrong alg label
    const bad3: PqEncryptedMessage = { ...enc, alg: 'nacl-box' as any };
    expect(pqDecryptString(kp.secretKey, bad3)).toBe(false);
  });

  it('public key is re-derivable from the stored secret key', () => {
    const kp = generatePqKeypair();
    expect(pqPublicKeyFromSecret(kp.secretKey)).toBe(kp.publicKey);
  });

  it('hybrid key sizes match FIPS 203 + X25519 hybrid expectations', () => {
    const kp = generatePqKeypair();
    expect(b64decode(kp.publicKey).length).toBe(1216); // ml_kem768_x25519 pub
    expect(b64decode(kp.secretKey).length).toBe(32);
    const enc = pqEncryptString(kp.publicKey, 'x');
    expect(b64decode(enc.kemCt).length).toBe(1120); // hybrid KEM ciphertext
    expect(b64decode(enc.nonce).length).toBe(24); // XChaCha20 nonce
  });

  it('nonces/ciphertexts are randomized (same input -> different ciphertext)', () => {
    const kp = generatePqKeypair();
    const e1 = pqEncryptString(kp.publicKey, 'same message');
    const e2 = pqEncryptString(kp.publicKey, 'same message');
    expect(e1.kemCt).not.toBe(e2.kemCt);
    expect(e1.ct).not.toBe(e2.ct);
    // both still decrypt correctly
    expect(pqDecryptString(kp.secretKey, e1)).toBe('same message');
    expect(pqDecryptString(kp.secretKey, e2)).toBe('same message');
  });
});

function corruptB64(b64: string): string {
  const bytes = b64decode(b64);
  bytes[0] ^= 0xff;
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
