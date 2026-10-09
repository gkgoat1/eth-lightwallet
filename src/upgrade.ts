// crypto-js retained ONLY for the v1 AES-CBC decrypt (EVP_BytesToKey quirk;
// reimplementing it on @noble is security-sensitive and not worth owning for a
// legacy-upgrade-only path — plan §3e). PBKDF2 + keyHash moved to @noble
// because crypto-js@4 changed PBKDF2 WordArray-salt handling.
import CryptoJS from 'crypto-js';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { keccak_512 } from '@noble/hashes/sha3.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { KeyStore } from './keystore';

const HD_PATH_STRING = "m/0'/0'/0'";

// CryptoJS WordArray {words, sigBytes} (big-endian) -> bytes.
function wordArrayToBytes(wa: { words: number[]; sigBytes: number }): Uint8Array {
  const out = new Uint8Array(wa.sigBytes);
  for (let i = 0; i < wa.sigBytes; i++) {
    out[i] = (wa.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return out;
}

// v1 KDF: PBKDF2-HMAC-SHA1, 150 iters, 512-bit key, returned as hex string.
function legacyGenerateEncKey(password: string, salt: any): string {
  const saltBytes = typeof salt === 'string' ? utf8ToBytes(salt) : wordArrayToBytes(salt);
  return bytesToHex(pbkdf2(sha1, utf8ToBytes(password), saltBytes, { c: 150, dkLen: 64 }));
}

// v1 keyHash: keccak-512 of the derived-key hex STRING.
function legacyKeyHash(derivedKeyHex: string): string {
  return bytesToHex(keccak_512(utf8ToBytes(derivedKeyHex)));
}

function legacyDecryptString(encryptedStr: any, password: string): string {
  const { encStr, iv, salt } = encryptedStr;
  const decryptedStr = CryptoJS.AES.decrypt(encStr, password, { iv, salt });

  return decryptedStr.toString(CryptoJS.enc.Latin1);
}

function upgradeVersion1(oldKS: any, password: string, callback: (err: unknown, serialized?: string) => void): void {
  const { salt, keyHash, encSeed, hdIndex } = oldKS;
  const derivedKey = legacyGenerateEncKey(password, salt);

  const hash = legacyKeyHash(derivedKey);

  if (keyHash !== hash) {
    callback(new Error('Keystore Upgrade: Invalid Password!'));
    return;
  }

  const seedPhrase = legacyDecryptString(encSeed, derivedKey);

  KeyStore.createVault(
    {
      password,
      seedPhrase,
      salt: KeyStore.DEFAULT_SALT,
      hdPathString: HD_PATH_STRING,
    },
    (err, newKeyStore) => {
      if (err) {
        callback(err);
        return;
      }

      (newKeyStore as KeyStore).keyFromPassword(password, (err, pwDerivedKey) => {
        if (err) {
          callback(err);
          return;
        }

        (newKeyStore as KeyStore).generateNewAddress(pwDerivedKey as Uint8Array, hdIndex);

        callback(null, (newKeyStore as KeyStore).serialize());
      });
    },
  );
}

function upgradeVersion2(oldKS: any, password: string, callback: (err: unknown, serialized?: string) => void): void {
  const { salt = KeyStore.DEFAULT_SALT, encSeed, ksData } = oldKS;

  KeyStore.deriveKeyFromPasswordAndSalt(password, salt, (err, pwKey) => {
    if (err) {
      callback(err);
      return;
    }

    let seedPhrase = KeyStore._decryptString(encSeed, pwKey as Uint8Array);

    if (seedPhrase) {
      seedPhrase = seedPhrase.trim();
    }

    if (!seedPhrase || !KeyStore.isSeedValid(seedPhrase)) {
      callback(new Error('Keystore Upgrade: Invalid provided password.'));
      return;
    }

    const hdPaths = Object.keys(ksData);

    let hdPathString = HD_PATH_STRING;

    if (hdPaths.length > 0) {
      hdPathString = hdPaths[0];
    }

    KeyStore.createVault(
      {
        password,
        seedPhrase,
        salt,
        hdPathString,
      },
      (err, newKeyStore) => {
        if (err) {
          callback(err);
          return;
        }

        (newKeyStore as KeyStore).keyFromPassword(password, (err, pwDerivedKey) => {
          if (err) {
            callback(err);
            return;
          }

          const hdIndex = ksData[hdPathString].hdIndex;
          (newKeyStore as KeyStore).generateNewAddress(pwDerivedKey as Uint8Array, hdIndex);

          callback(null, (newKeyStore as KeyStore).serialize());
        });
      },
    );
  });
}

export function upgradeOldSerialized(
  oldSerialized: string,
  password: string,
  callback: (err: unknown, serialized?: string) => void,
): void {
  const oldKS = JSON.parse(oldSerialized);
  const { version } = oldKS;

  if (version === undefined || version === 1) {
    upgradeVersion1(oldKS, password, callback);
  } else if (version === 2) {
    upgradeVersion2(oldKS, password, callback);
  } else if (version === 3) {
    callback(null, oldSerialized);
  } else {
    throw new Error('Keystore is not of correct version.');
  }
}

/** Canonical async form of upgradeOldSerialized (5.1.0). */
export function upgradeOldSerializedAsync(oldSerialized: string, password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    try {
      upgradeOldSerialized(oldSerialized, password, (err, ser) =>
        err ? reject(err) : resolve(ser as string),
      );
    } catch (e) {
      // upgradeOldSerialized throws synchronously on an unknown version.
      reject(e);
    }
  });
}
