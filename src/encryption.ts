import Nacl from 'tweetnacl';
import NaclUtil from 'tweetnacl-util';
import * as Assert from './assert';

// noble hex utils — browser-safe, no Buffer dependency.
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

export function encodeHex(msgUInt8Arr: Uint8Array): string {
  return bytesToHex(msgUInt8Arr);
}

export function decodeHex(msgHex: string): Uint8Array {
  return hexToBytes(msgHex);
}

export function asymEncryptRaw(
  keystore: any,
  pwDerivedKey: Uint8Array,
  msgUint8Array: Uint8Array,
  myAddress: string,
  theirPubKey: string,
): { alg: string; nonce: string; ciphertext: string } {
  Assert.derivedKey(keystore, pwDerivedKey);

  const privateKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  const privateKeyUInt8Array = decodeHex(privateKey);
  const pubKeyUInt8Array = decodeHex(theirPubKey);
  const nonce = Nacl.randomBytes(Nacl.box.nonceLength);
  const encryptedMessage = Nacl.box(msgUint8Array, nonce, pubKeyUInt8Array, privateKeyUInt8Array);

  return {
    alg: 'curve25519-xsalsa20-poly1305',
    nonce: NaclUtil.encodeBase64(nonce),
    ciphertext: NaclUtil.encodeBase64(encryptedMessage),
  };
}

export function asymDecryptRaw(
  keystore: any,
  pwDerivedKey: Uint8Array,
  encMsg: { nonce: string; ciphertext: string },
  theirPubKey: string,
  myAddress: string,
): Uint8Array | null {
  Assert.derivedKey(keystore, pwDerivedKey);

  const privateKey = keystore.exportPrivateKey(myAddress, pwDerivedKey);
  const privateKeyUInt8Array = decodeHex(privateKey);
  const pubKeyUInt8Array = decodeHex(theirPubKey);

  const nonce = NaclUtil.decodeBase64(encMsg.nonce);
  const cipherText = NaclUtil.decodeBase64(encMsg.ciphertext);
  const clearText = Nacl.box.open(cipherText, nonce, pubKeyUInt8Array, privateKeyUInt8Array);

  return clearText;
}

export function asymEncryptString(
  keystore: any,
  pwDerivedKey: Uint8Array,
  msg: string,
  myAddress: string,
  theirPubKey: string,
): { alg: string; nonce: string; ciphertext: string } {
  Assert.derivedKey(keystore, pwDerivedKey);

  const messageUInt8Array = NaclUtil.decodeUTF8(msg);

  return asymEncryptRaw(keystore, pwDerivedKey, messageUInt8Array, myAddress, theirPubKey);
}

export function asymDecryptString(
  keystore: any,
  pwDerivedKey: Uint8Array,
  encMsg: { nonce: string; ciphertext: string },
  theirPubKey: string,
  myAddress: string,
): string | false {
  Assert.derivedKey(keystore, pwDerivedKey);

  const clearText = asymDecryptRaw(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress);

  if (clearText === null) {
    return false;
  }

  return NaclUtil.encodeUTF8(clearText);
}

export function multiEncryptString(
  keystore: any,
  pwDerivedKey: Uint8Array,
  msg: string,
  myAddress: string,
  theirPubKeyArray: string[],
): any {
  Assert.derivedKey(keystore, pwDerivedKey);

  const messageUInt8Array = NaclUtil.decodeUTF8(msg);
  const symEncryptionKey = Nacl.randomBytes(Nacl.secretbox.keyLength);
  const symNonce = Nacl.randomBytes(Nacl.secretbox.nonceLength);

  const symEncMessage = Nacl.secretbox(messageUInt8Array, symNonce, symEncryptionKey);

  if (theirPubKeyArray.length < 1) {
    throw new Error('Found no pubkeys to encrypt to.');
  }

  const encryptedSymKey = theirPubKeyArray.map((theirPubKey) => {
    const { alg: _alg, ...props } = asymEncryptRaw(keystore, pwDerivedKey, symEncryptionKey, myAddress, theirPubKey);

    return {
      ...props,
    };
  });

  return {
    version: 1,
    asymAlg: 'curve25519-xsalsa20-poly1305',
    symAlg: 'xsalsa20-poly1305',
    symNonce: NaclUtil.encodeBase64(symNonce),
    symEncMessage: NaclUtil.encodeBase64(symEncMessage),
    encryptedSymKey,
  };
}

export function multiDecryptString(
  keystore: any,
  pwDerivedKey: Uint8Array,
  encMsg: any,
  theirPubKey: string,
  myAddress: string,
): string | false {
  Assert.derivedKey(keystore, pwDerivedKey);

  let symKey: Uint8Array | null = null;

  for (let i = 0; i < encMsg.encryptedSymKey.length; i++) {
    const result = asymDecryptRaw(keystore, pwDerivedKey, encMsg.encryptedSymKey[i], theirPubKey, myAddress);

    if (result !== null) {
      symKey = result;
      break;
    }
  }

  if (symKey === null) {
    return false;
  }

  const symNonce = NaclUtil.decodeBase64(encMsg.symNonce);
  const symEncMessage = NaclUtil.decodeBase64(encMsg.symEncMessage);
  const msg = Nacl.secretbox.open(symEncMessage, symNonce, symKey);

  if (msg === null) {
    return false;
  }

  return NaclUtil.encodeUTF8(msg);
}

export function addressToPublicEncKey(keystore: any, pwDerivedKey: Uint8Array, address: string): string {
  Assert.derivedKey(keystore, pwDerivedKey);

  const privateKey = keystore.exportPrivateKey(address, pwDerivedKey);
  const privateKeyUInt8Array = decodeHex(privateKey);
  const pubKeyUInt8Array = Nacl.box.keyPair.fromSecretKey(privateKeyUInt8Array).publicKey;

  return encodeHex(pubKeyUInt8Array);
}
