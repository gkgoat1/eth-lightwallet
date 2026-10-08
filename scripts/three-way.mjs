import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { createLegacyTx } from '@ethereumjs/tx';
import { createCustomCommon, Hardfork, Mainnet } from '@ethereumjs/common';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const Util = require('ethereumjs-util');
const LegacyKeystore = require('../legacy/keystore.js');
const fixtures = require('../test/fixtures/keystore.json');

const fx = fixtures.valid[0];
const pw = Uint8Array.from(fx.pwDerivedKey);
const ks = await new Promise((res, rej) => LegacyKeystore.createVault(
  { password: fx.password, seedPhrase: fx.mnSeed, salt: fx.salt, hdPathString: fx.hdPathString },
  (e, k) => (e ? rej(e) : res(k)),
));
ks.generateNewAddress(pw);
const privHex = ks.exportPrivateKey(ks.getAddresses()[0], pw);
const privPad = privHex.padStart(64, '0');
const privBytes = hexToBytes(privPad);
console.log('privHex (raw, len ' + privHex.length + '):', privHex);
console.log('privHex padded:', privPad);

// The tx sighash from @ethereumjs/tx (unsigned legacy, chainId 0)
const common = createCustomCommon({ chainId: 0 }, Mainnet, { hardfork: Hardfork.Homestead });
const p = fx.ethjsTxParams;
const unsigned = createLegacyTx({
  to: p.to, gasPrice: BigInt(p.gasPrice), gasLimit: BigInt(p.gasLimit), nonce: BigInt(p.nonce),
  value: BigInt(p.value), data: p.data, v: 28n, r: new Uint8Array(0), s: new Uint8Array(0),
}, { common });
const sighash = unsigned.getHashedMessageToSign();
console.log('\nsighash:', bytesToHex(sighash));

// 1) noble sign of sighash
const n = secp256k1.sign(sighash, privBytes, { format: 'recovered', lowS: true });
console.log('noble    r:', bytesToHex(n.slice(1, 33)).slice(0, 24), 's:', bytesToHex(n.slice(33, 65)).slice(0, 24), 'recid:', n[0]);

// 2) native binding (legacy ecsign) of sighash
const leg = Util.ecsign(Buffer.from(sighash), Buffer.from(privBytes));
console.log('native   r:', leg.r.toString('hex').slice(0, 24), 's:', leg.s.toString('hex').slice(0, 24), 'v:', leg.v);

// 3) @ethereumjs/tx sign (uses noble internally)
const signed = unsigned.sign(privBytes);
console.log('ethjs10  r:', signed.r.toString(16).padStart(64, '0').slice(0, 24), 's:', signed.s.toString(16).padStart(64, '0').slice(0, 24), 'v:', signed.v);

// golden
console.log('\ngolden rawSignedTx r/s (extract):');
console.log('golden r:', fx.rawSignedTx.slice(-140, -76).slice(0, 24));
