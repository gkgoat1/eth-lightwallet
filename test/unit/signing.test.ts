/**
 * Port of test/signing.js (mocha/chai) → vitest.
 * ethereumjs-tx/ethereumjs-util are devDependencies used only to *construct
 * the unsigned fixture tx*, same as the original suite.
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { KeyStore, Signing, TARGET } from './target';
import { promisify1 } from './helpers';

const require = createRequire(import.meta.url);
const Transaction = require('ethereumjs-tx');
const Util = require('ethereumjs-util');
const fixtures = require('../fixtures/keystore.json');

const createVaultProm = promisify1(KeyStore.createVault);

describe(`Signing [target=${TARGET}]`, () => {
  describe('signTx', () => {
    it('signs a transaction deterministically', async () => {
      const pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
      const fixture = fixtures.valid[0];

      const ks = await createVaultProm({
        password: fixture.password,
        seedPhrase: fixture.mnSeed,
        salt: fixture.salt,
        hdPathString: fixture.hdPathString,
      });
      ks.generateNewAddress(pw);

      const addr = ks.getAddresses()[0];
      expect(addr).toBe(fixture.ethjsTxParams.from);

      const tx = new Transaction(fixture.ethjsTxParams);
      const rawTx = tx.serialize().toString('hex');
      expect(rawTx).toBe(fixture.rawUnsignedTx);

      const signedTx0 = Signing.signTx(ks, pw, rawTx, addr);
      expect(signedTx0).toBe(fixture.rawSignedTx);
    });

    it('correctly handles a 31 byte key from bitcore', async () => {
      const secretSeed =
        'erupt consider beyond twist bike enroll you salute weasel emerge divert hundred';
      const hdPath = "m/44'/60'/0'"; // as defined in SLIP44
      const password = 'test';

      const keystore = await createVaultProm({
        password,
        seedPhrase: secretSeed,
        salt: 'someSalt',
        hdPathString: hdPath,
      });
      const pwDerivedKey = await new Promise<Uint8Array>((resolve, reject) => {
        keystore.keyFromPassword(password, (err: unknown, dk?: Uint8Array) =>
          err ? reject(err) : resolve(dk as Uint8Array),
        );
      });
      keystore.generateNewAddress(pwDerivedKey, 1); // Generate a new address

      const address = keystore.getAddresses()[0];
      const hexSeedETH = keystore.exportPrivateKey(address, pwDerivedKey);
      const addr0 = KeyStore._computeAddressFromPrivKey(hexSeedETH);
      expect(address).toBe('0x' + addr0);

      const tx = new Transaction({
        from: address,
        to: address,
        value: 100000000,
      });
      const rawTx = tx.serialize().toString('hex');
      const signedTx = Signing.signTx(keystore, pwDerivedKey, rawTx, address, hdPath);
      const expectedTx =
        'f861808080945e2abe3de708923e8425348005ee7fdd77e203cb8405f5e100801ca00a9a2486f65cab6c7819c82ee741f72d1acaab005642eef32f303696909fa64ea04e5d5e0e8d5f38704ac04faa1f91a9ee15a3ffcf158de342324d242b6acba819';

      expect(signedTx).toBe(expectedTx);
    });

    describe('signMsg', () => {
      it('signs a message deterministically', async () => {
        const pw = Uint8Array.from(fixtures.valid[0].pwDerivedKey);
        const fixture = fixtures.valid[0];

        const ks = await createVaultProm({
          password: fixture.password,
          seedPhrase: fixture.mnSeed,
          salt: fixture.salt,
          hdPathString: fixture.hdPathString,
        });
        ks.generateNewAddress(pw);

        const addr = ks.getAddresses()[0];
        expect(addr).toBe(fixture.ethjsTxParams.from);

        const msg = 'this is a message';
        const signedMsg = await Signing.signMsg(ks, pw, msg, addr);
        const msgHash = Util.addHexPrefix(Util.keccak(msg).toString('hex'));
        const signedMsgHash = await Signing.signMsgHash(ks, pw, msgHash, addr);

        // signedMsg and signedMsgHash have the same signature
        expect(signedMsg.v).toBe(signedMsgHash.v);
        expect(signedMsg.r.toString()).toBe(signedMsgHash.r.toString());
        expect(signedMsg.s.toString()).toBe(signedMsgHash.s.toString());

        const recoveredAddress = await Signing.recoverAddress(msg, signedMsg.v, signedMsg.r, signedMsg.s);

        expect(addr).toBe('0x' + recoveredAddress.toString('hex'));
        const concatSig = Signing.concatSig(signedMsg);
        const expectedConcatSig =
          '0x7b518ee144b8facf3f21b1f97a6d1f8aea448934d89cf5570e92bcca4d375ab6080f17400eafad3c5808e064ee56cd45321382040fb299fa028ea3cddf3488151c';

        expect(concatSig).toBe(expectedConcatSig);
      });
    });
  });
});
