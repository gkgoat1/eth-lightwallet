import CryptoJS from 'crypto-js';
import { KeyStore } from './keystore';

const HD_PATH_STRING = "m/0'/0'/0'";

function legacyGenerateEncKey(password: string, salt: string): string {
  return CryptoJS.PBKDF2(password, salt, {
    keySize: 512 / 32,
    iterations: 150,
  }).toString();
}

function legacyDecryptString(encryptedStr: any, password: string): string {
  const { encStr, iv, salt } = encryptedStr;
  const decryptedStr = CryptoJS.AES.decrypt(encStr, password, { iv, salt });

  return decryptedStr.toString(CryptoJS.enc.Latin1);
}

function upgradeVersion1(oldKS: any, password: string, callback: (err: unknown, serialized?: string) => void): void {
  const { salt, keyHash, encSeed, hdIndex } = oldKS;
  const derivedKey = legacyGenerateEncKey(password, salt);

  const hash = CryptoJS.SHA3(derivedKey).toString();

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
