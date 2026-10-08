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

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any {
  return target === 'legacy'
    ? require(`../../legacy/${name}.js`)
    : require(`../../src/${name}.js`); // Phase 2: src exists then
}

export const TARGET = target;
export const KeyStore = load('keystore');
export const Upgrade = load('upgrade');
export const Signing = load('signing');
export const TxUtils = load('txutils');
export const Encryption = load('encryption');
