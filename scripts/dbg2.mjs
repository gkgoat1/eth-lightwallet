import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
// Replicate signing.ts recoverAddress exactly
const { recoverAddress } = await import('viem');
const { keccak_256 } = await import('@noble/hashes/sha3.js');
const { bytesToHex, hexToBytes } = await import('@noble/hashes/utils.js');

const LegacyKeystore = require('../legacy/keystore.js');
const LegacySigning = require('../legacy/signing.js');
const fixtures = require('../test/fixtures/keystore.json');
const fx = fixtures.valid[0]; const pw = Uint8Array.from(fx.pwDerivedKey);
const ks = await new Promise((res,rej)=>LegacyKeystore.createVault({password:fx.password,seedPhrase:fx.mnSeed,salt:fx.salt,hdPathString:fx.hdPathString},(e,k)=>e?rej(e):res(k)));
ks.generateNewAddress(pw);
const addr = ks.getAddresses()[0];
const msg='this is a message';
// legacy sig (r,s are Buffers)
const leg = LegacySigning.signMsg(ks, pw, msg, addr);
console.log('leg r len:', leg.r.length, 's len:', leg.s.length, 'v:', leg.v);
const lp = (b)=>{ if(b.length>=32) return b; const o=new Uint8Array(32); o.set(b,32-b.length); return o; };
const vHex = Number(leg.v).toString(16).padStart(2,'0');
const signature = `${bytesToHex(lp(leg.r))}${bytesToHex(lp(leg.s))}${vHex}`;
console.log('sig hex chars:', signature.length);
const msgHash = '0x'+bytesToHex(keccak_256(new TextEncoder().encode(msg)));
const rec = await recoverAddress({ hash: msgHash, signature: '0x'+signature });
console.log('recovered:', rec, 'expected:', addr);
