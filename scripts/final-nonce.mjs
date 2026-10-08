import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const Util = require('ethereumjs-util');

const priv = hexToBytes('7627f5655d3f103f0be5c90064bd3557995604e6208590986de4e1230425c1ae');
const sighash = hexToBytes('cab27757164ff00b5704cca68bb720382d82313c059416238e48f6e0f5ab505b');
const goldenR = '8de63b51b4b9cc5bc09f7f9610d707f43c5840b37dffe655d0073b270032511b';

const show = (label, recBytes) => bytesToHex(recBytes).slice(0,24);

// noble ee=true x3
console.log('noble ee=true x3:');
for (let i=0;i<3;i++){ const r=secp256k1.sign(sighash,priv,{format:'recovered',lowS:true,extraEntropy:true}); console.log(' ', show('', r.slice(1,33))); }
// noble ee=false x3
console.log('noble ee=false x3:');
for (let i=0;i<3;i++){ const r=secp256k1.sign(sighash,priv,{format:'recovered',lowS:true,extraEntropy:false}); console.log(' ', show('', r.slice(1,33))); }
// noble default x3
console.log('noble default x3:');
for (let i=0;i<3;i++){ const r=secp256k1.sign(sighash,priv,{format:'recovered',lowS:true}); console.log(' ', show('', r.slice(1,33))); }
// native x3
console.log('native x3:');
for (let i=0;i<3;i++){ const s=Util.ecsign(Buffer.from(sighash), Buffer.from(priv)); console.log(' ', s.r.toString('hex').slice(0,24)); }
console.log('goldenR:', goldenR.slice(0,24));
