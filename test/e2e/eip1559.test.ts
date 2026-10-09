/**
 * E2E: EIP-1559 (type-2) value transfer + contract call via the modernized
 * stack, mined on Anvil. Asserts the tx is actually type-2 on-chain.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRequire } from 'node:module';
import { parseEther, parseGwei } from 'viem';
import { startAnvil, stopAnvil, type AnvilCtx } from './anvil-setup';
import { keystore as KeyStore } from '../../src/index';

const require = createRequire(import.meta.url);
const golden = require('../golden/generated/vault-4.0.0.json');
const SimpleStorage = require('./contracts/SimpleStorage.json');

const VAULT_INPUT = golden.vault.input;
const SENDER = golden.firstFiveAddresses[0] as `0x${string}`;
const RECIPIENT = '0x1000000000000000000000000000000000000003' as `0x${string}`;

describe('e2e: EIP-1559 (type-2)', () => {
  let ctx: AnvilCtx;
  let ks: any;
  let chainId: number;

  beforeAll(async () => {
    ctx = await startAnvil();
    chainId = await ctx.publicClient.getChainId();
    ks = await KeyStore.createVaultAsync({
      password: VAULT_INPUT.password, seedPhrase: VAULT_INPUT.mnemonic,
      salt: VAULT_INPUT.salt, hdPathString: VAULT_INPUT.hdPathString,
    });
    const pw = Uint8Array.from(Buffer.from(golden.kdf.pwDerivedKeyHex, 'hex'));
    ks.generateNewAddress(pw, 1);
    ks.passwordProvider = (cb: (e: unknown, p?: string) => void) => cb(null, VAULT_INPUT.password);
    await ctx.testClient.setBalance({ address: SENDER, value: parseEther('10') });
  }, 60000);

  afterAll(async () => {
    await stopAnvil(ctx);
  });

  it('sends a type-2 value transfer and it mines with type 0x2', async () => {
    const value = parseEther('0.25');
    const signedTx = await ks.signTransactionAsync({
      from: SENDER,
      to: RECIPIENT,
      gas: '0x5208',
      maxFeePerGas: parseGwei('20'),
      maxPriorityFeePerGas: parseGwei('2'),
      nonce: '0x00',
      value: '0x' + value.toString(16),
      chainId,
      txType: 2,
    });
    expect(signedTx.startsWith('0x02')).toBe(true);

    const hash = await ctx.publicClient.sendRawTransaction({ serializedTransaction: signedTx as `0x${string}` });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

    expect(receipt.status).toBe('success');
    expect(receipt.type).toBe('eip1559'); // viem format for type-2
    expect(receipt.from.toLowerCase()).toBe(SENDER.toLowerCase());
    const bal = await ctx.publicClient.getBalance({ address: RECIPIENT });
    expect(bal).toBe(value);
  });

  it('sends a type-2 contract deploy + set(7) and get() returns 7', async () => {
    // Deploy via createContractTx1559 (nonce 1 now)
    const { tx: deployTx, addr: predicted } = (await import('../../src/txutils')).createContractTx1559(SENDER, {
      from: SENDER,
      maxFeePerGas: parseGwei('20'),
      maxPriorityFeePerGas: parseGwei('2'),
      gasLimit: 500000n,
      nonce: 1n,
      value: 0n,
      data: SimpleStorage.bytecode,
      chainId,
    });
    const { sign1559Tx } = await import('../../src/signing');
    const pw = Uint8Array.from(Buffer.from(golden.kdf.pwDerivedKeyHex, 'hex'));
    const signedDeploy = sign1559Tx(ks, pw, deployTx, SENDER);
    const deployHash = await ctx.publicClient.sendRawTransaction({ serializedTransaction: ('0x' + signedDeploy) as `0x${string}` });
    const deployReceipt = await ctx.publicClient.waitForTransactionReceipt({ hash: deployHash });
    expect(deployReceipt.status).toBe('success');
    expect(deployReceipt.contractAddress!.toLowerCase()).toBe(predicted.toLowerCase());

    // set(7) via functionTx1559
    const { functionTx1559 } = await import('../../src/txutils');
    const callTx = functionTx1559(SimpleStorage.abi, 'set', [7], {
      from: SENDER,
      to: deployReceipt.contractAddress!,
      maxFeePerGas: parseGwei('20'),
      maxPriorityFeePerGas: parseGwei('2'),
      gasLimit: 200000n,
      nonce: 2n,
      value: 0n,
      chainId,
    });
    const signedCall = sign1559Tx(ks, pw, callTx, SENDER);
    const callHash = await ctx.publicClient.sendRawTransaction({ serializedTransaction: ('0x' + signedCall) as `0x${string}` });
    const callReceipt = await ctx.publicClient.waitForTransactionReceipt({ hash: callHash });
    expect(callReceipt.status).toBe('success');

    const { encodeFunctionData, decodeFunctionResult } = await import('viem');
    const data = encodeFunctionData({ abi: SimpleStorage.abi, functionName: 'get' });
    const result = await ctx.publicClient.call({ to: deployReceipt.contractAddress!, data });
    const val = decodeFunctionResult({ abi: SimpleStorage.abi, functionName: 'get', data: result.data! });
    expect(val).toBe(7n);
  });
});
