/**
 * Port of test/keystore.js (mocha/chai) → vitest.
 * Assertions kept 1:1; callbacks promisified locally (no bluebird).
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { KeyStore, Upgrade, TARGET } from './target';
import { promisify1, promisify2 } from './helpers';

const require = createRequire(import.meta.url);
const fixtures = require('../fixtures/keystore.json');
const addrPrivKeyVector: { key: string; addr: string }[] = require('../fixtures/addrprivkey100.json');
// Test with 10000 private keys - takes about 40 seconds to run
// const addrPrivKeyVector = require('../fixtures/addrprivkey10000.json');

const createVaultProm = promisify1(KeyStore.createVault);

describe(`Keystore [target=${TARGET}]`, () => {
  describe('createVault constructor', () => {
    it('accepts a variety of options', async () => {
      const fixture = fixtures.valid[0];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      expect(ks.encSeed).not.toBe(undefined);
      const decryptedPaddedSeed = KeyStore._decryptString(
        ks.encSeed,
        Uint8Array.from(fixture.pwDerivedKey),
      );
      // Check padding
      expect(decryptedPaddedSeed.length).toBe(120);
      expect(decryptedPaddedSeed.trim()).toBe(fixture.mnSeed);
    });

    it('generates a random salt for key generation', { timeout: 10000 }, async () => {
      const fixture = fixtures.valid[0];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        hdPathString: fixture.hdPathString,
      });
      const salt0 = ks.salt;
      expect(ks.salt).not.toBe(undefined);
      const derivedKey = await new Promise<Uint8Array>((resolve, reject) => {
        ks.keyFromPassword(fixture.password, (err: unknown, dk?: Uint8Array) =>
          err ? reject(err) : resolve(dk as Uint8Array),
        );
      });
      const decryptedPaddedSeed = KeyStore._decryptString(ks.encSeed, derivedKey);
      expect(decryptedPaddedSeed.length).toBe(120);
      expect(decryptedPaddedSeed.trim()).toBe(fixture.mnSeed);

      const ks1 = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        hdPathString: fixture.hdPathString,
      });
      const salt1 = ks1.salt;
      expect(salt0).not.toBe(salt1);
    });
  });

  // Can't directly test the encrypt/decrypt functions
  // since salt and iv is used.
  describe('_encryptString _decryptString', () => {
    for (const f of fixtures.valid) {
      it(`encrypts the seed then returns same seed decrypted "${f.mnSeed.substring(0, 25)}..."`, () => {
        const encryptedString = KeyStore._encryptString(f.mnSeed, Uint8Array.from(f.pwDerivedKey));
        const decryptedString = KeyStore._decryptString(encryptedString, Uint8Array.from(f.pwDerivedKey));

        expect(decryptedString).toBe(f.mnSeed);
      });
    }
  });

  describe('_encryptKey _decryptKey', () => {
    for (const f of fixtures.valid) {
      it(`encrypts the key then returns same key decrypted "${f.privKeyHex.substring(0, 15)}..."`, () => {
        const encryptedKey = KeyStore._encryptKey(f.privKeyHex, Uint8Array.from(f.pwDerivedKey));
        const decryptedKey = KeyStore._decryptKey(encryptedKey, Uint8Array.from(f.pwDerivedKey));

        expect(decryptedKey).toBe(f.privKeyHex);
      });
    }
  });

  describe('deriveKeyFromPassword', () => {
    it('derives a key correctly from the password', async () => {
      const derKeyProm = promisify2(KeyStore.deriveKeyFromPasswordAndSalt);
      const promArray = fixtures.valid.map((f: { password: string; salt: string }) =>
        derKeyProm(f.password, f.salt),
      );

      const derived = await Promise.all(promArray);
      for (let i = 0; i < derived.length; i++) {
        expect(derived[i]).toEqual(Uint8Array.from(fixtures.valid[i].pwDerivedKey));
      }
    });

    it('checks if a derived key is correct or not', async () => {
      const derKey = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      const derKey1 = Uint8Array.from(fixtures.valid[1].pwDerivedKey);
      const fixture = fixtures.valid[0];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      expect(ks.isDerivedKeyCorrect(derKey)).toBe(true);
      expect(ks.isDerivedKeyCorrect(derKey1)).toBe(false);
    });
  });

  describe('_computeAddressFromPrivKey', () => {
    for (const f of fixtures.valid) {
      it(`generates valid address from private key "${f.privKeyHex.substring(0, 15)}..."`, () => {
        const address = '0x' + KeyStore._computeAddressFromPrivKey(f.privKeyHex);
        expect(address).toBe(f.address);
      });
    }

    for (const f of addrPrivKeyVector) {
      it(`generates valid address from private key "${f.key.substring(0, 15)}..."`, () => {
        const address = KeyStore._computeAddressFromPrivKey(f.key);
        expect(address).toBe(f.addr);
      });
    }
  });

  describe('serialize deserialize', () => {
    it('serializes empty keystore and returns same non-empty keystore when deserialized', async () => {
      const fixture = fixtures.valid[0];

      const origKS = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      const serKS = origKS.serialize();
      const deserKS = KeyStore.deserialize(serKS);

      // Retains all attributes properly
      expect(deserKS).toEqual(origKS);
    });

    it('serializes non-empty keystore and returns same non-empty keystore when deserialized', async () => {
      const fixture = fixtures.valid[0];

      const origKS = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      // Add keys
      origKS.generateNewAddress(Uint8Array.from(fixture.pwDerivedKey), 20);

      const serKS = origKS.serialize();
      const deserKS = KeyStore.deserialize(serKS);

      // Retains all attributes properly
      expect(deserKS).toEqual(origKS);
    });
  });

  describe('generateNewAddress', () => {
    it('returns a new address, next in hd wallet', { timeout: 20000 }, async () => {
      const N = fixtures.valid.length;

      const keystores = await Promise.all(
        fixtures.valid.map((fixture: { password: string; mnSeed: string; salt: string; hdPathString: string }) =>
          createVaultProm({
            password: fixture.password,
            seedPhrase: fixture.mnSeed,
            salt: fixture.salt,
            hdPathString: fixture.hdPathString,
          }),
        ),
      );
      for (let i = 0; i < N; i++) {
        const ks = keystores[i];
        const numAddresses = fixtures.valid[i].hdIndex + 1;
        ks.generateNewAddress(Uint8Array.from(fixtures.valid[i].pwDerivedKey), numAddresses);
        const addresses = ks.getAddresses();
        const addr = addresses[addresses.length - 1];
        const priv = ks.exportPrivateKey(addr, Uint8Array.from(fixtures.valid[i].pwDerivedKey));
        expect(addr).toBe(fixtures.valid[i].address);
        expect(priv).toBe(fixtures.valid[i].privKeyHex);
      }
    });
  });

  describe('getAddresses', () => {
    it("returns the object's address attribute", async () => {
      const fixture = fixtures.valid[0];
      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      const add0x = (addr: string) => '0x' + addr;

      const pwKey = Uint8Array.from(fixture.pwDerivedKey);
      expect(ks.addresses.length).toBe(0);
      expect(ks.getAddresses()).toEqual(ks.addresses);
      ks.generateNewAddress(pwKey);
      expect(ks.addresses.length).toBe(1);
      expect(ks.getAddresses()).toEqual(ks.addresses.map(add0x));
      ks.generateNewAddress(pwKey, 5);
      expect(ks.addresses.length).toBe(6);
      expect(ks.getAddresses()).toEqual(ks.addresses.map(add0x));
    });
  });

  describe('Seed functions', () => {
    it('returns the unencrypted seed', async () => {
      const fixture = fixtures.valid[0];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      const pwKey = Uint8Array.from(fixture.pwDerivedKey);
      expect(ks.getSeed(pwKey)).toBe(fixture.mnSeed);
    });

    it('checks if seed is valid', () => {
      let isValid = KeyStore.isSeedValid(fixtures.valid[0].mnSeed);
      expect(isValid).toBe(true);

      isValid = KeyStore.isSeedValid(fixtures.invalid[0].mnSeed);
      expect(isValid).toBe(false);
    });

    it('concatenates and hashes entropy sources', () => {
      const N = fixtures.sha256Test.length;

      for (let i = 0; i < N; i++) {
        const ent0 = Buffer.from(fixtures.sha256Test[i].ent0);
        const ent1 = Buffer.from(fixtures.sha256Test[i].ent1);
        const outputString = KeyStore._concatAndSha256(ent0, ent1).toString('hex');
        expect(outputString).toBe(fixtures.sha256Test[i].targetHash);
      }
    });
  });

  describe('exportPrivateKey', () => {
    it('exports the private key corresponding to an address', async () => {
      const fixture = fixtures.valid[0];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      const pw = Uint8Array.from(fixture.pwDerivedKey);
      ks.generateNewAddress(pw, 2);
      const addr = ks.getAddresses();

      const exportedPriv0 = ks.exportPrivateKey(addr[0], pw);
      const exportedPriv1 = ks.exportPrivateKey(addr[1], pw);

      const addrFromExported0 = '0x' + KeyStore._computeAddressFromPrivKey(exportedPriv0);
      const addrFromExported1 = '0x' + KeyStore._computeAddressFromPrivKey(exportedPriv1);

      expect(addrFromExported0).toBe(addr[0]);
      expect(addrFromExported1).toBe(addr[1]);
    });
  });

  describe('hooked web3-provider', () => {
    it('implements hasAddress() correctly', async () => {
      const fixture = fixtures.valid[0];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      const pw = Uint8Array.from(fixture.pwDerivedKey);
      ks.generateNewAddress(pw, 5);
      const addr = ks.getAddresses();

      for (let i = 0; i < addr.length; i++) {
        ks.hasAddress(addr[i], (err: unknown, hasAddr?: boolean) => {
          expect(hasAddr).toBe(true);
        });
        ks.hasAddress(addr[i], (err: unknown, hasAddr?: boolean) => {
          expect(hasAddr).toBe(true);
        });
      }

      ks.hasAddress('abcdef0123456', (err: unknown, hasAddr?: boolean) => {
        expect(hasAddr).toBe(false);
      });

      ks.hasAddress('0xabcdef0123456', (err: unknown, hasAddr?: boolean) => {
        expect(hasAddr).toBe(false);
      });
    });

    it('implements signTransaction correctly', async () => {
      const fixture = fixtures.valid[1];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      const pwDerivedKey = await new Promise<Uint8Array>((resolve, reject) => {
        ks.keyFromPassword(fixture.password, (err: unknown, dk?: Uint8Array) =>
          err ? reject(err) : resolve(dk as Uint8Array),
        );
      });

      ks.generateNewAddress(pwDerivedKey, 1);

      // Trivial passwordProvider
      ks.passwordProvider = (callback: (err: unknown, pw?: string) => void) => {
        callback(null, fixture.password);
      };

      const txParams = fixture.web3TxParams;
      const signedTx = await new Promise<string>((resolve, reject) => {
        ks.signTransaction(txParams, (err: unknown, tx?: string) =>
          err ? reject(err) : resolve(tx as string),
        );
      });
      expect(signedTx.slice(2)).toBe(fixture.rawSignedTx);
    });
  });

  describe('upgrade old serialized keystore', () => {
    it('upgrades a keystore older than version 2', { timeout: 10000 }, async () => {
      const oldKS = require('../fixtures/lightwallet.json');
      const oldSerialized = JSON.stringify(oldKS);

      const upgradedKeystore = await new Promise<string>((resolve, reject) => {
        Upgrade.upgradeOldSerialized(oldSerialized, 'test', (err: unknown, ser?: string) =>
          err ? reject(err) : resolve(ser as string),
        );
      });
      const newKS = KeyStore.deserialize(upgradedKeystore);
      expect(newKS.addresses).toEqual(oldKS.addresses);
    });

    it('upgrades a version 2 keystore', { timeout: 10000 }, async () => {
      const oldKS = require('../fixtures/lightwalletv2.json');
      const oldSerialized = JSON.stringify(oldKS);

      const upgradedKeystore = await new Promise<string>((resolve, reject) => {
        Upgrade.upgradeOldSerialized(oldSerialized, 'PHveKjhQ&8dwWEdhu]q6', (err: unknown, ser?: string) =>
          err ? reject(err) : resolve(ser as string),
        );
      });
      const newKS = KeyStore.deserialize(upgradedKeystore);
      expect(newKS.addresses).toEqual(oldKS.ksData[newKS.hdPathString].addresses);
    });
  });
});
