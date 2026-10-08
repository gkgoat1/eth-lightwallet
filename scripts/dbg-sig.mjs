import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const LegacyKeystore = require('../legacy/keystore.js');
const fixtures = require('../test/fixtures/keystore.json');
const { signMsgHash, recoverAddress, concatSig } = await import('../src/signing.ts').catch(()=>({}));
// src is TS — use vitest? no. Just test the signing via a TS loader is hard.
// Instead replicate: build the sig via viem and print r/s buffer lengths.
const { sign } = await import('viem/accounts');
const { keccak_256 } = await import('@noble/hashes/sha3.js');
const { bytesToHex } = await import('@noble/hashes/utils.js');
const fx = fixtures.valid[0]; const pw = Uint8Array.from(fx.pwDerivedKey);
const ks = await new Promise((res,rej)=>LegacyKeystore.createVault({password:fx.password,seedPhrase:fx.mnSeed,salt:fx.salt,hdPathString:fx.hdPathString},(e,k)=>e?rej(e):res(k)));
ks.generateNewAddress(pw);
const addr = ks.getAddresses()[0];
const priv = '0x'+ks.exportPrivateKey(addr, pw).padStart(64,'0');
const msgHash = '0x'+bytesToHex(keccak_256(new TextEncoder().encode('this is a message')));
const sig = await sign({ hash: msgHash, privateKey: priv });
const r = Buffer.from(sig.r.slice(2), 'hex');
const s = Buffer.from(sig.s.slice(2), 'hex');
console.log('r len:', r.length, 's len:', s.length, 'v:', sig.v);
const assembled = '0x'+r.toString('hex')+s.toString('hex')+Number(sig.v).toString(16).padStart(2,'0');
console.log('assembled len (hex chars):', assembled.length-2, '(expect 130)');
console.log('assembled:', assembled);
