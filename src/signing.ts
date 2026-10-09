/**
 * signing — modernized (Phase 3c).
 *
 * Dropped: ethereumjs-tx@1, ethereumjs-util@6.
 * Now:
 *  - signTx: @ethereumjs/tx@10 (createLegacyTxFromRLP + sign), byte-exact
 *    with the legacy rawSignedTx goldens (verified over repeated runs).
 *  - signMsg/signMsgHash/concatSig/recoverAddress: viem's account signing +
 *    recovery, which reproduces the legacy message-signature bytes EXACTLY
 *    (verified against the hardcoded expectedConcatSig golden) — viem pins a
 *    noble version whose RFC6979 nonce matches the legacy native binding.
 *    (@noble/curves@2.4.0 standalone has a lowS recovery-bit inconsistency;
 *    viem's path is correct.)
 *
 * Returns {v, r, s} with r/s as Buffer to match the 4.0.0 signature shape
 * (tests call .toString() on them).
 */
import { createLegacyTxFromRLP, type LegacyTx } from '@ethereumjs/tx';
import { createCustomCommon, Hardfork, Mainnet } from '@ethereumjs/common';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { sign as viemSign, type SignParameters } from 'viem/accounts';
import { recoverAddress as viemRecoverAddress } from 'viem';
import { derivedKey as assertDerivedKey } from './assert';

// Legacy signing is pre-EIP-155 (chainId 0 → v = 27/28), matching
// ethereumjs-tx@1's default and the pinned rawSignedTx goldens.
const LEGACY_COMMON = createCustomCommon({ chainId: 0 }, Mainnet, { hardfork: Hardfork.Homestead });

function hexPref(h: string): `0x${string}` {
  return h.startsWith('0x') ? (h as `0x${string}`) : `0x${h}`;
}

function stripHex(h: string): string {
  return h.startsWith('0x') ? h.slice(2) : h;
}

function getPrivateKeyHex(keystore: any, pwDerivedKey: Uint8Array, address: string): `0x${string}` {
  const privateKey = keystore.exportPrivateKey(stripHex(address), pwDerivedKey);
  // Pad to 32 bytes — legacy hex may be short (bitcore truncated-key quirk).
  return hexPref(privateKey.padStart(64, '0'));
}

export function signTx(keystore: any, pwDerivedKey: Uint8Array, rawTx: string, signingAddress: string): string {
  assertDerivedKey(keystore, pwDerivedKey);

  // RLP hex may be odd-length (legacy createTx serializes empty r/s oddly).
  let txHex = stripHex(rawTx);
  if (txHex.length % 2 !== 0) txHex = '0' + txHex;
  const tx: LegacyTx = createLegacyTxFromRLP(hexToBytes(txHex), { common: LEGACY_COMMON });
  const privateKey = getPrivateKeyHex(keystore, pwDerivedKey, signingAddress);

  const signed = tx.sign(hexToBytes(stripHex(privateKey)));

  // 4.0.0 returns UNPREFIXED hex (keystore.signTransaction adds 0x itself).
  // noble bytesToHex is unprefixed already.
  return bytesToHex(signed.serialize());
}

export interface Signature {
  v: number;
  r: Buffer;
  s: Buffer;
}

type SigCb = (err: unknown, sig?: Signature) => void;

// Dual form: returns a Promise; if a trailing callback is supplied it is also
// invoked (5.1.0 async-internals + callback-compat decision).
export function signMsg(
  this: { signMsgHash: typeof signMsgHash },
  keystore: any,
  pwDerivedKey: Uint8Array,
  rawMsg: string,
  signingAddress: string,
  callback?: SigCb,
): Promise<Signature> {
  assertDerivedKey(keystore, pwDerivedKey);

  // Util.keccak(string) hashes the UTF-8 bytes of the string.
  const msgHash = hexPref(bytesToHex(keccak_256(new TextEncoder().encode(rawMsg))));

  const p = this.signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress);
  if (callback) p.then((s) => callback(null, s), (e) => callback(e));
  return p;
}

export function signMsgHash(
  keystore: any,
  pwDerivedKey: Uint8Array,
  msgHash: string,
  signingAddress: string,
  callback?: SigCb,
): Promise<Signature> {
  assertDerivedKey(keystore, pwDerivedKey);

  const p = (async (): Promise<Signature> => {
    let mh = stripHex(msgHash);
    if (mh.length % 2 !== 0) mh = '0' + mh;
    const hashHex = hexPref(mh);
    const privateKey = getPrivateKeyHex(keystore, pwDerivedKey, signingAddress);

    const sig = await viemSign({ hash: hashHex, privateKey } as SignParameters);

    return {
      v: Number(sig.v),
      r: Buffer.from(stripHex(sig.r), 'hex'),
      s: Buffer.from(stripHex(sig.s), 'hex'),
    };
  })();
  if (callback) p.then((s) => callback(null, s), (e) => callback(e));
  return p;
}

export function concatSig(signature: { v: number | bigint; r: Uint8Array; s: Uint8Array }): string {
  const r = bytesToHex(leftPad32(signature.r));
  const s = bytesToHex(leftPad32(signature.s));
  const vHex = Number(signature.v).toString(16);

  return hexPref(`${r}${s}${vHex}`);
}

export function recoverAddress(
  rawMsg: string,
  v: number,
  r: Uint8Array,
  s: Uint8Array,
  callback?: (err: unknown, address?: Buffer) => void,
): Promise<Buffer> {
  const p = (async (): Promise<Buffer> => {
    const msgHash = hexPref(bytesToHex(keccak_256(new TextEncoder().encode(rawMsg))));
    const vHex = Number(v).toString(16).padStart(2, '0');
    const signature = `${bytesToHex(leftPad32(r))}${bytesToHex(leftPad32(s))}${vHex}`;

    const address = await viemRecoverAddress({ hash: msgHash, signature: hexPref(signature) });

    return Buffer.from(stripHex(address), 'hex');
  })();
  if (callback) p.then((a) => callback(null, a), (e) => callback(e));
  return p;
}

function leftPad32(b: Uint8Array): Uint8Array {
  if (b.length >= 32) return b;
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}
