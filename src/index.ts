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
import { KeyStoreV4 } from './keystore-v4';
import * as upgrade from './upgrade';

export { txutils, encryption, signing, keystore, upgrade };

/** v4 keystore format (5.1.0, opt-in). */
export { KeyStoreV4, detectVersion } from './keystore-v4';
export type { V4KeystoreData, V4KdfParams, V4AeadBlob } from './keystore-v4';

export type {
  CreateVaultOptions,
  SerializedKeystore,
  TxParams,
  AsymEncryptedMessage,
  MultiEncryptedMessage,
  Callback,
} from './types';

export type { KeyStore } from './keystore';

export default {
  txutils,
  encryption,
  signing,
  keystore,
  upgrade,
  KeyStoreV4,
};
