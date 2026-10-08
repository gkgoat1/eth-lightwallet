/**
 * Test target selector.
 *
 * Phase 1 runs the ported suites against `legacy/` (frozen 4.0.0 code) to
 * prove the vitest port is faithful. Phase 2 flips the default to `src`.
 * Override with `LWT_TARGET=legacy|src`.
 */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const target = process.env.LWT_TARGET ?? 'legacy';

if (target !== 'legacy' && target !== 'src') {
  throw new Error(`LWT_TARGET must be "legacy" or "src", got "${target}"`);
}

// src is real TS resolved by vitest's loader; legacy is frozen CJS and needs
// createRequire (ESM can't require CJS without it here).
import * as srcKeystore from '../../src/keystore';
import * as srcUpgrade from '../../src/upgrade';
import * as srcSigning from '../../src/signing';
import * as srcTxutils from '../../src/txutils';
import * as srcEncryption from '../../src/encryption';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any {
  if (target === 'legacy') {
    return require(`../../legacy/${name}.js`);
  }
  switch (name) {
    case 'keystore':
      return (srcKeystore as any).KeyStore;
    case 'upgrade':
      return srcUpgrade;
    case 'signing':
      return srcSigning;
    case 'txutils':
      return srcTxutils;
    case 'encryption':
      return srcEncryption;
    default:
      throw new Error(`unknown module ${name}`);
  }
}

export const TARGET = target;
export const KeyStore = load('keystore');
export const Upgrade = load('upgrade');
export const Signing = load('signing');
export const TxUtils = load('txutils');
export const Encryption = load('encryption');
