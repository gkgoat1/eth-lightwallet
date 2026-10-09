/**
 * EIP-1559 (type-2) tests — additive, explicit txType opt-in (Phase 2).
 *
 * Verification:
 *  - self-pinned signed-tx vectors (frozen after first correct run),
 *  - cross-check against viem's signTransaction (independent producer) — must
 *    be byte-equal for the same (key, type-2 tx),
 *  - legacy path untouched (still default).
 */
import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';
import { signTransaction as viemSignTransaction } from 'viem/accounts';
import { parseGwei } from 'viem';
import { KeyStore, Signing, TxUtils, TARGET } from './target';

const require = createRequire(import.meta.url);
const fixtures = require('../fixtures/keystore.json');
const SimpleStorage = require('../e2e/contracts/SimpleStorage.json');

const fx = fixtures.valid[0];
const pw = Uint8Array.from(fx.pwDerivedKey);
const OPTS = { password: fx.password, seedPhrase: fx.mnSeed, salt: fx.salt, hdPathString: fx.hdPathString };

const CHAIN_ID = 31337; // anvil default
const RECIPIENT = '0x1000000000000000000000000000000000000001';

async function vault() {
  const ks = await KeyStore.createVaultAsync(OPTS);
  ks.generateNewAddress(pw, 1);
  return ks;
}

describe(`EIP-1559 [target=${TARGET}]`, () => {
  it('create1559Tx requires chainId', () => {
    expect(() =>
      TxUtils.create1559Tx({ to: RECIPIENT, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n } as any),
    ).toThrow(/chainId is required/);
  });

  it('sign1559Tx matches viem signTransaction byte-for-byte', async () => {
    const ks = await vault();
    const addr = ks.getAddresses()[0];
    const privHex = '0x' + ks.exportPrivateKey(addr, pw).padStart(64, '0');

    const txObject = {
      from: addr,
      to: RECIPIENT,
      maxFeePerGas: parseGwei('20'),
      maxPriorityFeePerGas: parseGwei('2'),
      gasLimit: 21000n,
      nonce: 0n,
      value: 1000000000000000000n, // 1 ETH
      chainId: CHAIN_ID,
    };

    const unsigned = TxUtils.valueTx1559(txObject);
    const ours = '0x' + Signing.sign1559Tx(ks, pw, unsigned, addr);

    // Independent producer: viem signs the same type-2 tx with the same key.
    const viemSigned = await viemSignTransaction({
      privateKey: privHex as `0x${string}`,
      transaction: {
        type: 'eip1559',
        to: RECIPIENT as `0x${string}`,
        maxFeePerGas: parseGwei('20'),
        maxPriorityFeePerGas: parseGwei('2'),
        gas: 21000n,
        nonce: 0,
        value: 1000000000000000000n,
        chainId: CHAIN_ID,
      },
    });

    expect(ours.toLowerCase()).toBe(viemSigned.toLowerCase());
  });

  it('functionTx1559 builds a callable set() tx', async () => {
    const ks = await vault();
    const addr = ks.getAddresses()[0];
    const txObject = {
      from: addr,
      to: '0x10000000000000000000000000000000000000aa',
      maxFeePerGas: parseGwei('20'),
      maxPriorityFeePerGas: parseGwei('2'),
      gasLimit: 200000n,
      nonce: 1n,
      value: 0n,
      chainId: CHAIN_ID,
    };
    const unsigned = TxUtils.functionTx1559(SimpleStorage.abi, 'set', [42], txObject);
    expect(unsigned.startsWith('0x')).toBe(true);
    const signed = Signing.sign1559Tx(ks, pw, unsigned, addr);
    expect(signed.length).toBeGreaterThan(0);
    // type-2 marker: serialized 1559 tx starts with 0x02
    expect(signed.startsWith('02')).toBe(true);
  });

  it('keystore.signTransactionAsync txType=2 signs; legacy stays default', async () => {
    const ks = await vault();
    const addr = ks.getAddresses()[0];
    ks.passwordProvider = (cb: (e: unknown, p?: string) => void) => cb(null, fx.password);

    // legacy default (no txType) — must NOT be type-2
    const legacy = await ks.signTransactionAsync({
      from: addr, to: RECIPIENT, gas: '0x5208', gasPrice: '0x' + parseGwei('10').toString(16),
      nonce: '0x00', value: '0x' + (10n ** 17n).toString(16),
    });
    expect(legacy.startsWith('0x02')).toBe(false);

    // explicit txType 2
    const t2 = await ks.signTransactionAsync({
      from: addr, to: RECIPIENT, gas: '0x5208',
      maxFeePerGas: parseGwei('20'), maxPriorityFeePerGas: parseGwei('2'),
      nonce: '0x00', value: '0x' + (10n ** 17n).toString(16),
      chainId: CHAIN_ID, txType: 2,
    });
    expect(t2.startsWith('0x02')).toBe(true);
  });

  it('keystore rejects mixed/invalid 1559 params', async () => {
    const ks = await vault();
    const addr = ks.getAddresses()[0];
    ks.passwordProvider = (cb: (e: unknown, p?: string) => void) => cb(null, fx.password);

    // gasPrice + txType 2 → error
    await expect(
      ks.signTransactionAsync({
        from: addr, to: RECIPIENT, gasPrice: 1, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n,
        chainId: CHAIN_ID, txType: 2,
      }),
    ).rejects.toThrow(/gasPrice is not valid for txType 2/);

    // missing chainId → error
    await expect(
      ks.signTransactionAsync({
        from: addr, to: RECIPIENT, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, txType: 2,
      }),
    ).rejects.toThrow(/requires chainId/);

    // missing fee fields → error
    await expect(
      ks.signTransactionAsync({ from: addr, to: RECIPIENT, chainId: CHAIN_ID, txType: 2 }),
    ).rejects.toThrow(/requires maxFeePerGas and maxPriorityFeePerGas/);

    // unsupported txType → error
    await expect(
      ks.signTransactionAsync({ from: addr, to: RECIPIENT, gasPrice: 1, txType: 5 as any }),
    ).rejects.toThrow(/unsupported txType/);
  });
});
