/**
 * Phase 1 (5.1.0): dual async/callback API — every async canonical method and
 * its callback wrapper must return identical results (and identical errors).
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { KeyStore, Signing, Upgrade, TARGET } from './target';

const require = createRequire(import.meta.url);
const fixtures = require('../fixtures/keystore.json');
const golden = require('../golden/generated/vault-4.0.0.json');

const fx = fixtures.valid[0];
const pw = Uint8Array.from(fx.pwDerivedKey);

const OPTS = {
  password: fx.password,
  seedPhrase: fx.mnSeed,
  salt: fx.salt,
  hdPathString: fx.hdPathString,
};

function cb<T>(): { promise: Promise<T>; callback: (err: unknown, v?: T) => void } {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return {
    promise,
    callback: (err, v) => (err ? reject(err) : resolve(v as T)),
  };
}

describe(`Dual async/callback API [target=${TARGET}]`, () => {
  it('createVault vs createVaultAsync — identical vault', async () => {
    const cbVault = await (() => { const { promise, callback } = cb<any>(); KeyStore.createVault(OPTS, callback); return promise; })();
    const asyncVault = await KeyStore.createVaultAsync(OPTS);

    expect(asyncVault.getSeed(pw)).toBe(cbVault.getSeed(pw));
    expect(asyncVault.hdPathString).toBe(cbVault.hdPathString);
    expect(asyncVault.salt).toBe(cbVault.salt);
  });

  it('keyFromPassword vs keyFromPasswordAsync — identical derived key', async () => {
    const ks = await KeyStore.createVaultAsync(OPTS);
    const cbKey = await (() => { const { promise, callback } = cb<Uint8Array>(); ks.keyFromPassword(fx.password, callback); return promise; })();
    const asyncKey = await ks.keyFromPasswordAsync(fx.password);

    expect(Buffer.from(asyncKey).toString('hex')).toBe(Buffer.from(cbKey).toString('hex'));
    expect(Buffer.from(asyncKey).toString('hex')).toBe(
      Buffer.from(Uint8Array.from(fx.pwDerivedKey)).toString('hex'),
    );
  });

  it('deriveKeyFromPasswordAndSalt vs Async — identical (incl. default-salt overload)', async () => {
    const cbKey = await (() => {
      const { promise, callback } = cb<Uint8Array>();
      KeyStore.deriveKeyFromPasswordAndSalt('pw', 'salt1', callback);
      return promise;
    })();
    const asyncKey = await KeyStore.deriveKeyFromPasswordAndSaltAsync('pw', 'salt1');
    expect(Buffer.from(asyncKey).toString('hex')).toBe(Buffer.from(cbKey).toString('hex'));

    // default-salt overload
    const cbDef = await (() => {
      const { promise, callback } = cb<Uint8Array>();
      KeyStore.deriveKeyFromPasswordAndSalt('pw', callback);
      return promise;
    })();
    const asyncDef = await KeyStore.deriveKeyFromPasswordAndSaltAsync('pw');
    expect(Buffer.from(asyncDef).toString('hex')).toBe(Buffer.from(cbDef).toString('hex'));
  });

  it('hasAddress vs hasAddressAsync — identical (present and absent)', async () => {
    const ks = await KeyStore.createVaultAsync(OPTS);
    ks.generateNewAddress(pw, 1);
    const addr = ks.getAddresses()[0];

    const asyncPresent = await ks.hasAddressAsync(addr);
    const cbPresent = await (() => { const { promise, callback } = cb<boolean>(); ks.hasAddress(addr, callback); return promise; })();
    expect(asyncPresent).toBe(true);
    expect(cbPresent).toBe(true);

    const asyncAbsent = await ks.hasAddressAsync('abcdef0123456');
    expect(asyncAbsent).toBe(false);
    // callback form reports absent via err + false (5.0.0 shape preserved)
    const cbAbsent = await new Promise<{ err: unknown; val?: boolean }>((res) =>
      ks.hasAddress('abcdef0123456', (err: unknown, val?: boolean) => res({ err, val })),
    );
    expect(cbAbsent.val).toBe(false);
    expect(cbAbsent.err).toBeInstanceOf(Error);
  });

  it('signTransaction vs signTransactionAsync — identical signed tx', async () => {
    const mk = async () => {
      const ks = await KeyStore.createVaultAsync(OPTS);
      ks.generateNewAddress(pw, 1);
      ks.passwordProvider = (cbk: (e: unknown, p?: string) => void) => cbk(null, fx.password);
      return ks;
    };
    const ks1 = await mk();
    const ks2 = await mk();
    const txParams = { ...fx.web3TxParams };

    const cbTx = await (() => { const { promise, callback } = cb<string>(); ks1.signTransaction(txParams, callback); return promise; })();
    const asyncTx = await ks2.signTransactionAsync(txParams);
    expect(asyncTx).toBe(cbTx);
    expect(asyncTx.slice(2)).toBe(fx.rawSignedTx);
  });

  it('signMsg / signMsgHash / recoverAddress — callback form matches promise form', async () => {
    const ks = await KeyStore.createVaultAsync(OPTS);
    ks.generateNewAddress(pw, 1);
    const addr = ks.getAddresses()[0];
    const msg = 'dual api message';

    const pSig = await Signing.signMsg(ks, pw, msg, addr);
    const cbSig = await (() => { const { promise, callback } = cb<any>(); Signing.signMsg(ks, pw, msg, addr, callback); return promise; })();
    expect(cbSig.v).toBe(pSig.v);
    expect(cbSig.r.toString()).toBe(pSig.r.toString());
    expect(cbSig.s.toString()).toBe(pSig.s.toString());

    const pRec = await Signing.recoverAddress(msg, pSig.v, pSig.r, pSig.s);
    const cbRec = await (() => { const { promise, callback } = cb<Buffer>(); Signing.recoverAddress(msg, pSig.v, pSig.r, pSig.s, callback); return promise; })();
    expect(cbRec.toString('hex')).toBe(pRec.toString('hex'));
    expect('0x' + pRec.toString('hex')).toBe(addr);
  });

  it('upgradeOldSerialized vs upgradeOldSerializedAsync — identical v2 upgrade', async () => {
    const oldKS = require('../fixtures/lightwalletv2.json');
    const ser = JSON.stringify(oldKS);
    const password = 'PHveKjhQ&8dwWEdhu]q6';

    const cbOut = await (() => { const { promise, callback } = cb<string>(); Upgrade.upgradeOldSerialized(ser, password, callback); return promise; })();
    const asyncOut = await Upgrade.upgradeOldSerializedAsync(ser, password);

    const a = KeyStore.deserialize(cbOut);
    const b = KeyStore.deserialize(asyncOut);
    expect(b.addresses).toEqual(a.addresses);
    expect(b.hdPathString).toBe(a.hdPathString);
  });
});
