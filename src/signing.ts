import Transaction from 'ethereumjs-tx';
import Util from 'ethereumjs-util';
import * as Assert from './assert';

function getPrivateKeyBuff(keystore: any, pwDerivedKey: Uint8Array, address: string): Buffer {
  const privateKey = keystore.exportPrivateKey(Util.stripHexPrefix(address), pwDerivedKey);

  return Buffer.from(privateKey, 'hex');
}

export function signTx(keystore: any, pwDerivedKey: Uint8Array, rawTx: string, signingAddress: string): string {
  Assert.derivedKey(keystore, pwDerivedKey);

  const tx = new Transaction(Buffer.from(Util.stripHexPrefix(rawTx), 'hex'));
  const privateKeyBuff = getPrivateKeyBuff(keystore, pwDerivedKey, signingAddress);

  tx.sign(privateKeyBuff);

  return tx.serialize().toString('hex');
}

// NOTE: 4.0.0 uses `this.signMsgHash` here, which works because consumers
// call it as a method of the module namespace object. Preserved verbatim;
// `this` is typed as the module shape for noImplicitThis.
export function signMsg(
  this: { signMsgHash: typeof signMsgHash },
  keystore: any,
  pwDerivedKey: Uint8Array,
  rawMsg: string,
  signingAddress: string,
): any {
  Assert.derivedKey(keystore, pwDerivedKey);

  const msgHash = Util.addHexPrefix(Util.keccak(rawMsg).toString('hex'));

  return this.signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress);
}

export function signMsgHash(
  keystore: any,
  pwDerivedKey: Uint8Array,
  msgHash: string,
  signingAddress: string,
): any {
  Assert.derivedKey(keystore, pwDerivedKey);

  const msgBuff = Buffer.from(Util.stripHexPrefix(msgHash), 'hex');
  const privateKeyBuff = getPrivateKeyBuff(keystore, pwDerivedKey, signingAddress);

  return Util.ecsign(msgBuff, privateKeyBuff);
}

export function concatSig(signature: any): string {
  let v = signature.v;
  let r = signature.r;
  let s = signature.s;

  r = Util.fromSigned(r);
  s = Util.fromSigned(s);
  v = Util.bufferToInt(v);

  r = Util.setLengthLeft(Util.toUnsigned(r), 32).toString('hex');
  s = Util.setLengthLeft(Util.toUnsigned(s), 32).toString('hex');
  v = Util.stripHexPrefix(Util.intToHex(v));

  return Util.addHexPrefix(r.concat(s, v).toString('hex'));
}

export function recoverAddress(rawMsg: string, v: number, r: Buffer, s: Buffer): Buffer {
  const msgHash = Util.keccak(rawMsg);

  return Util.pubToAddress(Util.ecrecover(msgHash, v, r, s));
}
