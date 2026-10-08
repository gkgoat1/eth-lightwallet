/**
 * Public types for eth-lightwallet 5.0.0.
 */

/** Options for `KeyStore.createVault`. */
export interface CreateVaultOptions {
  /** HD derivation path, e.g. "m/0'/0'/0'" (required — no default). */
  hdPathString: string;
  /** 12-word BIP39 mnemonic (required). */
  seedPhrase: string;
  /** Vault password (required). */
  password: string;
  /** Optional fixed salt (a random one is generated otherwise). */
  salt?: string;
}

/** The serialized (JSON) shape of a v3 keystore, from `KeyStore.serialize()`. */
export interface SerializedKeystore {
  encSeed: { encStr: string; nonce: string };
  encHdRootPriv: { encStr: string; nonce: string };
  addresses: string[];
  encPrivKeys: Record<string, { key: string; nonce: string }>;
  hdPathString: string;
  salt: string;
  hdIndex: number;
  version: number;
}

/** Transaction parameters accepted by `KeyStore.signTransaction` (web3-style `gas`). */
export interface TxParams {
  from: string;
  to?: string;
  gas?: string | number;
  gasPrice?: string | number;
  gasLimit?: string | number;
  nonce?: string | number;
  value?: string | number;
  data?: string;
  chainId?: number;
}

/** An nacl.box-encrypted message (asymmetric encryption). */
export interface AsymEncryptedMessage {
  alg: string;
  nonce: string;
  ciphertext: string;
}

/** A multi-recipient encrypted message (symmetric key wrapped per-recipient). */
export interface MultiEncryptedMessage {
  version: number;
  asymAlg: string;
  symAlg: string;
  symNonce: string;
  symEncMessage: string;
  encryptedSymKey: { nonce: string; ciphertext: string }[];
}

/** Callback style used throughout the library: (err, value?). */
export type Callback<T> = (err: unknown, value?: T) => void;
