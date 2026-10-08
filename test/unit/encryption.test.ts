/**
 * Port of test/encryption.js (mocha/chai) → vitest.
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { KeyStore, Encryption, TARGET } from './target';
import { promisify1 } from './helpers';

const require = createRequire(import.meta.url);
const fixtures = require('../fixtures/keystore.json');

const createVaultProm = promisify1(KeyStore.createVault);

describe(`Encryption [target=${TARGET}]`, () => {
  describe('Asymmetric Encryption', () => {
    it('encrypts and decrypts a string', async () => {
      const fixture = fixtures.valid[0];
      const pw = Uint8Array.from(fixture.pwDerivedKey);

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: "m/0'/0'/2'",
      });
      ks.generateNewAddress(pw, 2);
      const addresses = ks.getAddresses();
      const pubKey0 = Encryption.addressToPublicEncKey(ks, pw, addresses[0]);
      const pubKey1 = Encryption.addressToPublicEncKey(ks, pw, addresses[1]);

      const msg = 'Hello World!';
      const encrypted = Encryption.asymEncryptString(ks, pw, msg, addresses[0], pubKey1);
      const clearText = Encryption.asymDecryptString(ks, pw, encrypted, pubKey0, addresses[1]);
      expect(clearText).toBe(msg);
    });
  });

  describe('Multi-recipient Encryption', () => {
    it('encrypts and decrypts a string to multiple parties', { timeout: 10000 }, async () => {
      const fixture = fixtures.valid[0];
      const pw = Uint8Array.from(fixture.pwDerivedKey);

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: "m/0'/0'/2'",
      });

      ks.generateNewAddress(pw, 6);

      const addresses = ks.getAddresses();
      const pubKeys: string[] = [];
      addresses.map((addr: string) => {
        pubKeys.push(Encryption.addressToPublicEncKey(ks, pw, addr));
      });

      const msg = 'Hello World to multiple people!';
      const encrypted = Encryption.multiEncryptString(ks, pw, msg, addresses[0], pubKeys.slice(0, 4));

      let clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[0]);
      expect(clearText).toBe(msg);
      clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[1]);
      expect(clearText).toBe(msg);
      clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[2]);
      expect(clearText).toBe(msg);
      clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[3]);
      expect(clearText).toBe(msg);
      clearText = Encryption.multiDecryptString(ks, pw, encrypted, pubKeys[0], addresses[4]);
      expect(clearText).toBe(false);
    });
  });
});
