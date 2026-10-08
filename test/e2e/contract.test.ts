/**
 * E2E: contract deployment + call via the modernized stack on Anvil.
 *
 * - createContractTx produces the deploy tx; createdContractAddress must equal
 *   the on-chain receipt.contractAddress (proves the RLP+keccak address
 *   prediction matches reality).
 * - functionTx builds a `set(42)` call; eth_call `get()` must return 42.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRequire } from 'node:module';
import { parseGwei, encodeFunctionData, decodeFunctionResult } from 'viem';
import { startAnvil, stopAnvil, type AnvilCtx } from './anvil-setup';
import { keystore as KeyStore, signing, txutils } from '../../src/index';

const require = createRequire(import.meta.url);
const golden = require('../golden/generated/vault-4.0.0.json');
const SimpleStorage = require('./contracts/SimpleStorage.json');

const VAULT_INPUT = golden.vault.input;
const DEPLOYER = golden.firstFiveAddresses[0] as `0x${string}`;

describe('e2e: contract deploy + call', () => {
  let ctx: AnvilCtx;
  let ks: any;
  let pw: Uint8Array;
  let contractAddress: `0x${string}`;

  beforeAll(async () => {
    ctx = await startAnvil();
    ks = await new Promise((res, rej) =>
      KeyStore.createVault(
        { password: VAULT_INPUT.password, seedPhrase: VAULT_INPUT.mnemonic, salt: VAULT_INPUT.salt, hdPathString: VAULT_INPUT.hdPathString },
        (e: unknown, k?: any) => (e ? rej(e) : res(k)),
      ),
    );
    pw = Uint8Array.from(Buffer.from(golden.kdf.pwDerivedKeyHex, 'hex'));
    ks.generateNewAddress(pw, 1);
    await ctx.testClient.setBalance({ address: DEPLOYER, value: BigInt('10000000000000000000') });
  }, 60000);

  afterAll(async () => {
    await stopAnvil(ctx);
  });

  it('deploys a contract; createdContractAddress == receipt.contractAddress', async () => {
    const txObject = {
      from: DEPLOYER,
      gasPrice: '0x' + parseGwei('10').toString(16),
      gasLimit: '0x' + (500000).toString(16),
      nonce: '0x00',
      value: '0x00',
      data: SimpleStorage.bytecode,
    };

    const { tx, addr } = txutils.createContractTx(DEPLOYER, txObject);
    const signedHex = signing.signTx(ks, pw, tx, DEPLOYER);

    const hash = await ctx.publicClient.sendRawTransaction({ serializedTransaction: `0x${signedHex}` });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

    expect(receipt.status).toBe('success');
    expect(receipt.contractAddress).toBeTruthy();
    // The offline address prediction must match the on-chain address.
    expect(receipt.contractAddress!.toLowerCase()).toBe(addr.toLowerCase());
    contractAddress = receipt.contractAddress!;

    const code = await ctx.publicClient.getBytecode({ address: contractAddress });
    expect(code).toBeTruthy();
    expect(code).not.toBe('0x');
  });

  it('calls set(42) via functionTx, then get() returns 42', async () => {
    const setTxObject = {
      from: DEPLOYER,
      to: contractAddress,
      gasPrice: '0x' + parseGwei('10').toString(16),
      gasLimit: '0x' + (200000).toString(16),
      nonce: '0x01',
      value: '0x00',
    };

    const unsignedCall = txutils.functionTx(SimpleStorage.abi, 'set', [42], setTxObject);
    const signedCall = signing.signTx(ks, pw, unsignedCall, DEPLOYER);

    const hash = await ctx.publicClient.sendRawTransaction({ serializedTransaction: `0x${signedCall}` });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
    expect(receipt.status).toBe('success');

    // eth_call get()
    const data = encodeFunctionData({ abi: SimpleStorage.abi, functionName: 'get' });
    const result = await ctx.publicClient.call({ to: contractAddress, data });
    const value = decodeFunctionResult({ abi: SimpleStorage.abi, functionName: 'get', data: result.data! });
    expect(value).toBe(42n);
  });
});
