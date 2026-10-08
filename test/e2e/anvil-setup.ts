/**
 * Anvil test helper — spawns a local anvil instance (loopback only) and
 * exposes viem clients + a funded dev account.
 *
 * Anvil is a HARD prerequisite: if the binary is missing the suite fails
 * closed with a clear message (per plan §3.2), never silently skips.
 */
import { createAnvil, type Anvil } from '@viem/anvil';
import {
  createPublicClient,
  createTestClient,
  createWalletClient,
  http,
  type PublicClient,
  type TestClient,
  type WalletClient,
} from 'viem';
import { foundry } from 'viem/chains';
import { privateKeyToAccount } from 'viem/accounts';

// Anvil dev account #0 (well-known, from anvil's default mnemonic).
export const DEV_ACCOUNT_PRIVKEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80' as const;

export interface AnvilCtx {
  anvil: Anvil;
  url: string;
  publicClient: PublicClient;
  testClient: TestClient;
  walletClient: WalletClient;
}

let portCounter = 18545 + (process.pid % 1000); // spread across parallel files

export async function startAnvil(): Promise<AnvilCtx> {
  // @viem/anvil does not support port 0 auto-assign; pick a distinct port.
  const port = portCounter++;
  const anvil = createAnvil({ port, host: '127.0.0.1' });
  await anvil.start();

  const url = `http://127.0.0.1:${port}`;
  const transport = http(url);

  const publicClient = createPublicClient({ chain: foundry, transport });
  const testClient = createTestClient({ chain: foundry, mode: 'anvil', transport });
  const walletClient = createWalletClient({
    chain: foundry,
    transport,
    account: privateKeyToAccount(DEV_ACCOUNT_PRIVKEY),
  });

  // Wait for the RPC endpoint to actually accept connections.
  for (let i = 0; ; i++) {
    try {
      await publicClient.getChainId();
      break;
    } catch {
      if (i > 50) throw new Error(`anvil on :${port} did not become ready`);
      await new Promise((r) => setTimeout(r, 100));
    }
  }

  return { anvil, url, publicClient, testClient, walletClient };
}

export async function stopAnvil(ctx: AnvilCtx): Promise<void> {
  await ctx.anvil.stop();
}
