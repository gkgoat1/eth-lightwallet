/**
 * E2E: fund → build → sign → send a legacy value transfer produced by the
 * modernized keystore/txutils/signing stack, mined on Anvil.
 *
 * Uses the golden vault (mnemonic "abandon ... about", hdPath m/0'/0'/0') whose
 * first address is pinned in test/golden/generated/vault-4.0.0.json.
 * Recipient is 0x1000…0001 (NOT a precompile — see t-9be9's PrecompileOOG note).
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createRequire } from 'node:module';
import { parseEther, parseGwei } from 'viem';
import { startAnvil, stopAnvil, type AnvilCtx } from './anvil-setup';
import { keystore as KeyStore, signing, txutils } from '../../src/index';

const require = createRequire(import.meta.url);
const golden = require('../golden/generated/vault-4.0.0.json');

const VAULT_INPUT = golden.vault.input;
const SENDER = golden.firstFiveAddresses[0] as `0x${string}`;
// NOT 0x01–0x09: those are precompiles and OOG at 21000 gas on Anvil.
const RECIPIENT = '0x1000000000000000000000000000000000000001' as `0x${string}`;

describe('e2e: legacy value transfer (sign + mine)', () => {
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
    expect(ks.getAddresses()[0]).toBe(SENDER);

    // Fund the vault address from Anvil (test-mode setBalance).
    await ctx.testClient.setBalance({ address: SENDER, value: parseEther('10') });
  }, 60000);

  afterAll(async () => {
    await stopAnvil(ctx);
  });

  it('sends a legacy value transfer and it mines', async () => {
    const value = parseEther('1');
    const txObject = {
      from: SENDER,
      to: RECIPIENT,
      gasPrice: '0x' + parseGwei('10').toString(16),
      gasLimit: '0x5208', // 21000
      nonce: '0x00',
      value: '0x' + value.toString(16),
    };

    const unsigned = txutils.valueTx(txObject);
    const signedHex = signing.signTx(ks, pw, unsigned, SENDER);

    const hash = await ctx.publicClient.sendRawTransaction({ serializedTransaction: `0x${signedHex}` });
    const receipt = await ctx.publicClient.waitForTransactionReceipt({ hash });

    expect(receipt.status).toBe('success');
    expect(receipt.from.toLowerCase()).toBe(SENDER.toLowerCase());
    expect(receipt.to?.toLowerCase()).toBe(RECIPIENT.toLowerCase());

    const bal = await ctx.publicClient.getBalance({ address: RECIPIENT });
    expect(bal).toBe(value);

    // Sender spent value + gas (legacy gasPrice × gasUsed)
    const gasCost = receipt.gasUsed * receipt.effectiveGasPrice;
    const senderBal = await ctx.publicClient.getBalance({ address: SENDER });
    expect(senderBal).toBe(parseEther('10') - value - gasCost);
  });
});
