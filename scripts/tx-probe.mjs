import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const Legacy = require('../legacy/txutils.js');
const fixtures = require('../test/fixtures/txutils.json');

import { createLegacyTx } from '@ethereumjs/tx';
import { bytesToHex, hexToBytes } from '@ethereumjs/util';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { encodeAbiParameters, toFunctionSelector } from 'viem';

const hexPref = (h) => (h && h.startsWith('0x') ? h : '0x' + h);

// --- createTx/txToHexString parity ---
function createTxNew(txObject) {
  const txData = {};
  if (txObject.from) txData.from = hexPref(txObject.from);
  if (txObject.to) txData.to = hexPref(txObject.to);
  if (txObject.gasPrice) txData.gasPrice = BigInt(txObject.gasPrice);
  if (txObject.gasLimit) txData.gasLimit = BigInt(txObject.gasLimit);
  if (txObject.nonce) txData.nonce = BigInt(txObject.nonce);
  if (txObject.value) txData.value = BigInt(txObject.value);
  if (txObject.data) txData.data = hexPref(txObject.data);
  // legacy (ethereumjs-tx@1) serializes unsigned v/r/s as EMPTY bytes;
  // @ethereumjs/tx@10 defaults them to 0x00, so override to match.
  // legacy (ethereumjs-tx@1, chainId=0) defaults v=0x1c (EIP-155 v=27+1),
  // r/s EMPTY. @ethereumjs/tx@10 leaves them undefined -> serializes as 0.
  // Match the legacy default for unsigned-tx hex parity.
  txData.v = 28n;
  txData.r = new Uint8Array(0);
  txData.s = new Uint8Array(0);
  return createLegacyTx(txData);
}

let allOk = true;
for (const f of fixtures.valid) {
  // unsigned tx hex
  const legacyHex = Legacy.txToHexString(Legacy.createTx(f.txObject));
  const newTx = createTxNew(f.txObject);
  const newHex = hexPref(bytesToHex(newTx.serialize()));
  const unsignedMatch = legacyHex === newHex;

  // functionTx (ABI encode) — selector via viem, params via viem encodeAbiParameters
  const types = f.types;
  const fullName = `${f.func}(${types.join()})`;
  const selector = toFunctionSelector(fullName).slice(2);
  const legacySelector = Legacy._encodeFunctionTxData(f.func, f.types, f.args).slice(2, 10);
  const selectorMatch = selector === legacySelector;

  const legacyFnTx = Legacy.functionTx(f.abi, f.func, f.args, f.txObject);
  const params = encodeAbiParameters(
    f.abi.find((j) => j.type === 'function' && j.name === f.func).inputs,
    f.args,
  ).slice(2);
  const newData = '0x' + selector + params;
  const newFnTx = hexPref(bytesToHex(createTxNew({ ...f.txObject, data: newData }).serialize()));
  const fnMatch = legacyFnTx === newFnTx;

  // createdContractAddress via noble keccak + ethereumjs rlp
  const legacyAddr = Legacy.createdContractAddress(f.fromAddress, f.txObject.nonce);
  const addrBuf = hexToBytes(hexPref(f.fromAddress));
  const { RLP } = require('@ethereumjs/rlp');
  const rlpEnc = RLP.encode([addrBuf, f.txObject.nonce]);
  const newAddr = hexPref(bytesToHex(keccak_256(rlpEnc).slice(-20)));
  const addrMatch = legacyAddr.toLowerCase() === newAddr.toLowerCase();

  console.log(`${f.func}: unsigned=${unsignedMatch} selector=${selectorMatch} fnTx=${fnMatch} addr=${addrMatch}`);
  if (!(unsignedMatch && selectorMatch && fnMatch && addrMatch)) {
    allOk = false;
    if (!unsignedMatch) console.log('  legacy:', legacyHex, '\n  new   :', newHex);
    if (!selectorMatch) console.log('  legacy sel:', legacySelector, 'new sel:', selector);
    if (!fnMatch) console.log('  legacy fnTx:', legacyFnTx, '\n  new    fnTx:', newFnTx);
    if (!addrMatch) console.log('  legacy addr:', legacyAddr, 'new addr:', newAddr);
  }
}
console.log(allOk ? 'TX PARITY: PASS' : 'TX PARITY: FAIL');
process.exit(allOk ? 0 : 1);
