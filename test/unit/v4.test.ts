/**
 * v4 keystore format tests (5.1.0, Phase 3).
 *
 * - v4 create/open round-trip (Argon2id + AEAD)
 * - AAD tamper-evidence (decryption fails on AAD/ciphertext mismatch)
 * - v3 -> v4 migration preserves addresses + private keys byte-for-byte
 * - v3 vaults still open under v3 path (no regression)
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { KeyStoreV4 } from '../../src/keystore-v4';
import { KeyStore } from '../../src/keystore';
import { upgradeV3ToV4Async } from '../../src/upgrade';

const require = createRequire(import.meta.url);
const golden = require('../golden/generated/vault-4.0.0.json');

const VAULT_INPUT = golden.vault.input; // fixed mnemonic + password (v3 salt)
const PASSWORD = VAULT_INPUT.password;
const MNEMONIC = VAULT_INPUT.mnemonic;
const HD_PATH = VAULT_INPUT.hdPathString;

// Use the browser KDF profile to keep tests fast.
const BROWSER = { m: 16384, t: 3, p: 1, dkLen: 32 };

describe('v4 keystore format', () => {
  it('creates and opens a v4 vault (Argon2id + AEAD)', async () => {
    const ks = await KeyStoreV4.create({ hdPathString: HD_PATH, seedPhrase: MNEMONIC, password: PASSWORD, kdfProfile: BROWSER });
    expect(ks.version).toBe(4);
    expect(ks.kdf.alg).toBe('argon2id');

    const key = await ks.deriveKeyFromPassword(PASSWORD);
    expect(key.length).toBe(32);
    expect(ks.isDerivedKeyCorrect(key)).toBe(true);
    expect(ks.getSeed(key)).toBe(MNEMONIC);
  });

  it('derives the same addresses as v3 for the same seed+path', async () => {
    const ks = await KeyStoreV4.create({ hdPathString: HD_PATH, seedPhrase: MNEMONIC, password: PASSWORD, kdfProfile: BROWSER });
    const key = await ks.deriveKeyFromPassword(PASSWORD);
    ks.generateNewAddress(key, 5);
    // golden v3 first-5 addresses must match v4 (same HD derivation)
    expect(ks.getAddresses()).toEqual(golden.firstFiveAddresses);
  });

  it('serialize/deserialize round-trips a v4 vault', async () => {
    const ks = await KeyStoreV4.create({ hdPathString: HD_PATH, seedPhrase: MNEMONIC, password: PASSWORD, kdfProfile: BROWSER });
    const key = await ks.deriveKeyFromPassword(PASSWORD);
    ks.generateNewAddress(key, 3);

    const ser = ks.serialize();
    const parsed = JSON.parse(ser);
    expect(parsed.version).toBe(4);
    expect(parsed.kdf.alg).toBe('argon2id');

    const ks2 = KeyStoreV4.deserialize(ser);
    expect(ks2.getAddresses()).toEqual(ks.getAddresses());
    expect(ks2.getSeed(key)).toBe(MNEMONIC);
    // exported keys match
    const addr = ks.getAddresses()[0];
    expect(ks2.exportPrivateKey(addr, key)).toBe(ks.exportPrivateKey(addr, key));
  });

  it('rejects a wrong password (AEAD auth fails)', async () => {
    const ks = await KeyStoreV4.create({ hdPathString: HD_PATH, seedPhrase: MNEMONIC, password: PASSWORD, kdfProfile: BROWSER });
    const wrongKey = await ks.deriveKeyFromPassword('wrong-password');
    expect(ks.isDerivedKeyCorrect(wrongKey)).toBe(false);
    expect(() => ks.getSeed(wrongKey)).toThrow();
  });

  it('is tamper-evident: corrupted ciphertext fails AEAD', async () => {
    const ks = await KeyStoreV4.create({ hdPathString: HD_PATH, seedPhrase: MNEMONIC, password: PASSWORD, kdfProfile: BROWSER });
    const key = await ks.deriveKeyFromPassword(PASSWORD);
    const parsed = JSON.parse(ks.serialize());
    // corrupt one byte of the seed ciphertext
    const ct = Buffer.from(parsed.encSeed.ct, 'base64');
    ct[0] ^= 0xff;
    parsed.encSeed.ct = ct.toString('base64');
    const tampered = KeyStoreV4.deserialize(JSON.stringify(parsed));
    expect(() => tampered.getSeed(key)).toThrow();
  });

  it('is tamper-evident: swapped AAD fails AEAD', async () => {
    const ks = await KeyStoreV4.create({ hdPathString: HD_PATH, seedPhrase: MNEMONIC, password: PASSWORD, kdfProfile: BROWSER });
    const key = await ks.deriveKeyFromPassword(PASSWORD);
    const parsed = JSON.parse(ks.serialize());
    // swap AAD to a different field label
    parsed.encSeed.aad = 'lw4:hdroot:4';
    const tampered = KeyStoreV4.deserialize(JSON.stringify(parsed));
    expect(() => tampered.getSeed(key)).toThrow();
  });

  it('migrates v3 -> v4 preserving addresses + private keys', async () => {
    // Build a v3 vault (golden seed/path) with 3 addresses
    const v3 = await KeyStore.createVaultAsync({
      password: PASSWORD, seedPhrase: MNEMONIC, salt: VAULT_INPUT.salt, hdPathString: HD_PATH,
    });
    const v3Key = Uint8Array.from(Buffer.from(golden.kdf.pwDerivedKeyHex, 'hex'));
    v3.generateNewAddress(v3Key, 3);
    const v3Addrs = v3.getAddresses();
    const v3Keys = v3Addrs.map((a: string) => v3.exportPrivateKey(a, v3Key));

    // Migrate
    const v4Ser = await upgradeV3ToV4Async(v3.serialize(), PASSWORD, { kdfProfile: BROWSER });
    const v4 = KeyStoreV4.deserialize(v4Ser);
    const v4Key = await v4.deriveKeyFromPassword(PASSWORD);

    expect(v4.version).toBe(4);
    expect(v4.getAddresses()).toEqual(v3Addrs);
    for (let i = 0; i < v3Addrs.length; i++) {
      expect(v4.exportPrivateKey(v3Addrs[i], v4Key)).toBe(v3Keys[i]);
    }
    expect(v4.getSeed(v4Key)).toBe(MNEMONIC);
  });

  it('v3 vault still opens under the v3 path (no regression)', async () => {
    const v3 = await KeyStore.createVaultAsync({
      password: PASSWORD, seedPhrase: MNEMONIC, salt: VAULT_INPUT.salt, hdPathString: HD_PATH,
    });
    const v3Key = Uint8Array.from(Buffer.from(golden.kdf.pwDerivedKeyHex, 'hex'));
    v3.generateNewAddress(v3Key, 2);
    const ser = v3.serialize();
    const re = KeyStore.deserialize(ser);
    expect(re.version).toBe(3);
    expect(re.getAddresses()).toEqual(v3.getAddresses());
  });
});
