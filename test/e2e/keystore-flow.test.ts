/**
 * E2E: the full keystore.signTransaction flow (web3-style, with an injected
 * passwordProvider) producing a mined tx, plus message-sign recovery.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRequire } from 'node:module';
import { parseEther, parseGwei, recoverAddress as viemRecoverAddress } from 'viem';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { startAnvil, stopAnvil, type AnvilCtx } from './anvil-setup';
import { keystore as KeyStore, signing } from '../../src/index';

const require = createRequire(import.meta.url);
const golden = require('../golden/generated/vault-4.0.0.json');

const VAULT_INPUT = golden.vault.input;
const SENDER = golden.firstFiveAddresses[0] as `0x${string}`;
const RECIPIENT = '0x1000000000000000000000000000000000000002' as `0x${string}`;

describe('e2e: keystore.signTransaction + message recovery', () => {
  let ctx: AnvilCtx;
  let ks: any;
  let pw: Uint8Array;

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
    await ctx.testClient.setBalance({ address: SENDER, value: parseEther('10') });
    // Inject a non-interactive passwordProvider (default uses prompt()).
    ks.passwordProvider = (cb: (e: unknown, p?: string) => void) => cb(null, VAULT_INPUT.password);
  }, 60000);

  afterAll(async () => {
    await stopAnvil(ctx);
  });

  it('keystore.signTransaction produces a mined legacy tx (web3-style gas param)', async () => {
    const txParams = {
      from: SENDER,
      to: RECIPIENT,
      gas: '0x5208', // web3-style "gas" (mapped to gasLimit internally)
      gasPrice: '0x' + parseGwei('10').toString(16),
      nonce: '0x00',
      value: '0x' + parseEther('0.5').toString(16),
    };

    const signedTx = await new Promise<string>((res, rej) =>
      ks.signTransaction(txParams, (e: unknown, tx?: string) => (e ? rej(e) : res(tx as string))),
    );
    expect(signedTx.startsWith('0x')).toBe(true);

    const hash = await ctx.publicClient.sendRawTransaction({ serializedTransaction: signedTx as `0x${string}` });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });
    expect(receipt.status).toBe('success');

    const bal = await ctx.publicClient.getBalance({ address: RECIPIENT });
    expect(bal).toBe(parseEther('0.5'));
  });

  it('signMsgHash + concatSig recovers to the signer', async () => {
    const msg = 'e2e message';
    const msgHashHex = '0x' + bytesToHex(keccak_256(new TextEncoder().encode(msg)));
    const sig = await signing.signMsgHash(ks, pw, msgHashHex, SENDER);
    const concat = signing.concatSig(sig);

    const recovered = await viemRecoverAddress({ hash: msgHashHex as `0x${string}`, signature: concat as `0x${string}` });
    expect(recovered.toLowerCase()).toBe(SENDER.toLowerCase());

    // library recoverAddress agrees
    const libRecovered = await signing.recoverAddress(msg, sig.v, sig.r, sig.s);
    expect('0x' + libRecovered.toString('hex')).toBe(SENDER.toLowerCase());
  });
});
