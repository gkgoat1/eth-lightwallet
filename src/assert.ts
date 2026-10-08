export function derivedKey(keystore: any, pwDerivedKey: Uint8Array): void {
  if (!keystore.isDerivedKeyCorrect(pwDerivedKey)) {
    throw new Error('Incorrect derived key!');
  }
}
