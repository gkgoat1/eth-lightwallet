import { HDKey } from '@scure/bip32';
import { mnemonicToSeedSync } from '@scure/bip39';
import { bytesToHex } from '@noble/hashes/utils.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

// bitcore side
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const BitCore = require('bitcore-lib');
const Mnemonic = require('bitcore-mnemonic');

const golden = JSON.parse(
  require('node:fs').readFileSync(new URL('../test/golden/generated/vault-4.0.0.json', import.meta.url), 'utf8'),
);
const mnemonic = golden.vault.input.mnemonic;
const hdPath = golden.vault.input.hdPathString; // m/0'/0'/0'

// scure path: root = mnemonicToSeed -> HDKey.fromMasterSeed; derive path; then children 0..4
const seed = mnemonicToSeedSync(mnemonic); // no passphrase — matches Mnemonic.toHDPrivateKey()
const root = HDKey.fromMasterSeed(seed);
const hdRoot = root.derive(hdPath);
const scureKeys = [];
for (let i = 0; i < 5; i++) scureKeys.push(bytesToHex(hdRoot.deriveChild(i).privateKey));

// bitcore path (legacy/ parity): xpriv of Mnemonic->HDPrivateKey->derive(path), then derive(index)
const bRoot = new Mnemonic(mnemonic).toHDPrivateKey().xprivkey;
const bPathKey = new BitCore.HDPrivateKey(new BitCore.HDPrivateKey(bRoot).derive(hdPath).xprivkey);
const bitcoreKeys = [];
for (let i = 0; i < 5; i++) {
  let hex = new BitCore.HDPrivateKey(bPathKey.xprivkey).derive(i).privateKey.toBuffer().toString('hex');
  if (hex.length < 64) hex = hex.padStart(64, '0'); // the short-key quirk
  bitcoreKeys.push(hex);
}

const addrOf = (privHex) => {
  const privBytes = Uint8Array.from(Buffer.from(privHex, 'hex'));
  const pub = secp256k1.getPublicKey(privBytes, false).slice(1);
  return bytesToHex(keccak_256(pub).slice(-20));
};

let ok = true;
for (let i = 0; i < 5; i++) {
  const match = scureKeys[i] === bitcoreKeys[i];
  const goldenAddrMatch = addrOf(scureKeys[i]) === golden.firstFiveAddresses[i].replace('0x','');
  console.log(`[${i}] scure==bitcore: ${match}  scure->golden addr: ${goldenAddrMatch}`);
  if (!match || !goldenAddrMatch) ok = false;
}
console.log(ok ? 'HD PARITY: PASS' : 'HD PARITY: FAIL');
process.exit(ok ? 0 : 1);
