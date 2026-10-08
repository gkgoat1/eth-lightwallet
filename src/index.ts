/**
 * eth-lightwallet — ESM entry.
 *
 * Named exports map to the 4.0.0 `module.exports` shape; the default export
 * carries the same object for CJS-style `require('eth-lightwallet')`
 * consumers (via the tsdown dual build).
 */
import * as txutils from './txutils';
import * as encryption from './encryption';
import * as signing from './signing';
import { KeyStore as keystore } from './keystore';
import * as upgrade from './upgrade';

export { txutils, encryption, signing, keystore, upgrade };

export default {
  txutils,
  encryption,
  signing,
  keystore,
  upgrade,
};
