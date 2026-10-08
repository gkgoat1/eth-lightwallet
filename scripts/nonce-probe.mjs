import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const Util = require('ethereumjs-util');
const LegacyKeystore = require('../legacy/keystore.js');
const LegacySigning = require('../legacy/signing.js');
const fixtures = require('../test/fixtures/keystore.json');

const fx = fixtures.valid[0];
const pw = Uint8Array.from(fx.pwDerivedKey);
const ks = await new Promise((res, rej) => LegacyKeystore.createVault(
  { password: fx.password, seedPhrase: fx.mnSeed, salt: fx.salt, hdPathString: fx.hdPathString },
  (e, k) => (e ? rej(e) : res(k)),
));
ks.generateNewAddress(pw);
const addr = ks.getAddresses()[0];
const privHex = ks.exportPrivateKey(addr, pw).padStart(64, '0');
const priv = hexToBytes(privHex);

// Legacy message sig
const legacySig = LegacySigning.signMsg(ks, pw, 'this is a message', addr);
const L = { r: legacySig.r.toString('hex'), s: legacySig.s.toString('hex'), v: legacySig.v };
console.log('legacy  r:', L.r);

// Noble: sign the SAME 32-byte hash legacy used (Util.keccak of the raw string)
const msgHash = new Uint8Array(Util.keccak('this is a message'));
const sig = secp256k1.sign(msgHash, priv, { format: 'recovered', lowS: true });
const N = { r: bytesToHex(sig.slice(1, 33)), s: bytesToHex(sig.slice(33, 65)), recid: sig[0] };
console.log('noble   r:', N.r);
console.log('r match:', L.r === N.r, '| s match:', L.s === N.s, '| v:', L.v, 'vs 27+', N.recid);

// CONTROL: noble sign of a KNOWN vector to confirm noble RFC6979 correctness.
// privkey=1, msg=keccak(0x00)... compare against ethereumjs-util@6
const one = new Uint8Array(32); one[31] = 1;
const h = new Uint8Array(Util.keccak(new Uint8Array([0])));
const legC = Util.ecsign(Buffer.from(h), Buffer.from(one));
const nobC = secp256k1.sign(h, one, { format: 'recovered', lowS: true });
console.log('CONTROL priv=1: legacy r', legC.r.toString('hex').slice(0,16), '| noble r', bytesToHex(nobC.slice(1,33)).slice(0,16), '| match:', legC.r.toString('hex')===bytesToHex(nobC.slice(1,33)));
