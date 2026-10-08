/**
 * txutils — modernized (Phase 3b).
 *
 * Dropped: web3@0.20 (solidity/coder), ethereumjs-tx@1, ethereumjs-util@6,
 * rlp, crypto-js.
 * Now: @ethereumjs/tx@10 (legacy txs), @ethereumjs/rlp, @noble/hashes
 * (keccak), viem (ABI selector + param encoding).
 *
 * Behavioral pins preserved (verified against legacy/ + txutils.json):
 * - Unsigned legacy txs serialize with v=0x1c (EIP-155 v for chainId 0),
 *   r/s EMPTY — @ethereumjs/tx@10 leaves them undefined (serializes as 0),
 *   so createTx overrides them to match.
 * - createdContractAddress uses keccak_256 (== crypto-js SHA3 quirk for
 *   these inputs), NOT NIST SHA3.
 */
import { createLegacyTx, type LegacyTx } from '@ethereumjs/tx';
import { RLP } from '@ethereumjs/rlp';
import { bytesToHex, hexToBytes } from '@ethereumjs/util';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { encodeAbiParameters, toFunctionSelector } from 'viem';

function hexPref(h: string | undefined): `0x${string}` {
  if (!h) return h as `0x${string}`;
  return h.startsWith('0x') ? (h as `0x${string}`) : `0x${h}`;
}

export interface TxObject {
  from?: string;
  to?: string;
  gasPrice?: string | number | bigint;
  gasLimit?: string | number | bigint;
  nonce?: string | number | bigint;
  value?: string | number | bigint;
  data?: string;
  chainId?: number;
}

export function createTx(txObject: TxObject): LegacyTx {
  const txData: Record<string, unknown> = {};
  if (txObject.from) txData.from = hexPref(txObject.from);
  if (txObject.to) txData.to = hexPref(txObject.to);
  if (txObject.gasPrice !== undefined && txObject.gasPrice !== '') txData.gasPrice = BigInt(txObject.gasPrice);
  if (txObject.gasLimit !== undefined && txObject.gasLimit !== '') txData.gasLimit = BigInt(txObject.gasLimit);
  if (txObject.nonce !== undefined && txObject.nonce !== '') txData.nonce = BigInt(txObject.nonce);
  if (txObject.value !== undefined && txObject.value !== '') txData.value = BigInt(txObject.value);
  if (txObject.data) txData.data = hexPref(txObject.data);
  if (txObject.chainId !== undefined) txData.chainId = BigInt(txObject.chainId);

  // Preserve 4.0.0 unsigned serialization: v=0x1c, r/s empty.
  if (txObject.chainId === undefined) {
    txData.v = 28n;
    txData.r = new Uint8Array(0);
    txData.s = new Uint8Array(0);
  }

  return createLegacyTx(txData as any);
}

export function txToHexString(tx: LegacyTx): string {
  return hexPref(bytesToHex(tx.serialize()));
}

export function _getTypesFromAbi(abi: any[], functionName: string): string[] {
  const funcJson = abi.filter((json: any) => json.type === 'function' && json.name === functionName)[0];

  return funcJson.inputs.map((json: any) => json.type);
}

export function _encodeFunctionTxData(functionName: string, types: string[], args: any[]): string {
  const fullName = `${functionName}(${types.join()})`;
  // viem toFunctionSelector uses keccak_256 — matches the old crypto-js
  // SHA3({outputLength:256}) selector for these inputs.
  const signature = toFunctionSelector(fullName).slice(2);
  const encodeParams = encodeAbiParameters(types.map((t) => ({ type: t })), args).slice(2);

  return hexPref(`${signature}${encodeParams}`);
}

export function functionTx(abi: any[], functionName: string, args: any[], txObject: TxObject): string {
  const types = _getTypesFromAbi(abi, functionName);
  const txData = _encodeFunctionTxData(functionName, types, args);
  const tx = createTx({
    ...txObject,
    data: txData,
  });

  return txToHexString(tx);
}

export function valueTx(txObject: TxObject): string {
  const tx = createTx(txObject);

  return txToHexString(tx);
}

export function createdContractAddress(fromAddress: string, nonce: number): string {
  const addressBuf = hexToBytes(hexPref(fromAddress));
  const rlpEncoded = RLP.encode([addressBuf, nonce]);
  const hash = keccak_256(rlpEncoded);

  return hexPref(bytesToHex(hash.slice(-20)));
}

export function createContractTx(fromAddress: string, txObject: TxObject): { tx: string; addr: string } {
  const tx = createTx(txObject);
  const contractAddress = createdContractAddress(fromAddress, Number(txObject.nonce));

  return {
    tx: txToHexString(tx),
    addr: contractAddress,
  };
}
