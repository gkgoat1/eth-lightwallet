import Transaction from 'ethereumjs-tx';
import Util from 'ethereumjs-util';
// NOTE: explicit .js extension — Node ESM resolves subpaths exactly, unlike
// CJS require. (web3 0.20 is dropped entirely in Phase 3b.)
import Coder from 'web3/lib/solidity/coder.js';
import Rlp from 'rlp';
import CryptoJS from 'crypto-js';

export function createTx(txObject: any): any {
  return new Transaction({
    ...(txObject.from && { from: Util.addHexPrefix(txObject.from) }),
    ...(txObject.to && { to: Util.addHexPrefix(txObject.to) }),
    ...(txObject.gasPrice && { gasPrice: Util.addHexPrefix(txObject.gasPrice) }),
    ...(txObject.gasLimit && { gasLimit: Util.addHexPrefix(txObject.gasLimit) }),
    ...(txObject.nonce && { nonce: Util.addHexPrefix(txObject.nonce) }),
    ...(txObject.value && { value: Util.addHexPrefix(txObject.value) }),
    ...(txObject.data && { data: Util.addHexPrefix(txObject.data) }),
  });
}

export function txToHexString(tx: any): string {
  return Util.addHexPrefix(tx.serialize().toString('hex'));
}

export function _getTypesFromAbi(abi: any[], functionName: string): string[] {
  const funcJson = abi.filter((json: any) => json.type === 'function' && json.name === functionName)[0];

  return funcJson.inputs.map((json: any) => json.type);
}

export function _encodeFunctionTxData(functionName: string, types: string[], args: any[]): string {
  const fullName = `${functionName}(${types.join()})`;
  const signature = CryptoJS.SHA3(fullName, { outputLength: 256 }).toString(CryptoJS.enc.Hex).slice(0, 8);
  const encodeParams = Coder.encodeParams(types, args);
  const dataHex = Util.addHexPrefix(`${signature}${encodeParams}`);

  return dataHex;
}

export function functionTx(abi: any[], functionName: string, args: any[], txObject: any): string {
  const types = _getTypesFromAbi(abi, functionName);
  const txData = _encodeFunctionTxData(functionName, types, args);
  const tx = createTx({
    ...txObject,
    data: txData,
  });

  return txToHexString(tx);
}

export function valueTx(txObject: any): string {
  const tx = createTx(txObject);

  return txToHexString(tx);
}

export function createdContractAddress(fromAddress: string, nonce: number): string {
  const addressBuf = Buffer.from(Util.stripHexPrefix(fromAddress), 'hex');
  const rlpEncodedHex = Rlp.encode([addressBuf, nonce]).toString('hex');
  const rlpEncodedWordArray = CryptoJS.enc.Hex.parse(rlpEncodedHex);
  const hash = CryptoJS.SHA3(rlpEncodedWordArray, { outputLength: 256 }).toString(CryptoJS.enc.Hex);

  return Util.addHexPrefix(hash.slice(24));
}

export function createContractTx(fromAddress: string, txObject: any): { tx: string; addr: string } {
  const tx = createTx(txObject);
  const contractAddress = createdContractAddress(fromAddress, txObject.nonce);

  return {
    tx: txToHexString(tx),
    addr: contractAddress,
  };
}
