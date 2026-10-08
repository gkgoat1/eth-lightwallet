/**
 * Golden fixture generator — runs against `legacy/` (frozen 4.0.0 code).
 *
 * Output: test/golden/generated/vault-4.0.0.json
 *
 * All values are either fully deterministic (addresses, scrypt key, signed
 * txs, upgrade outputs) or produced with a FIXED salt so the serialized vault
 * is stable except for nacl nonces (encryption is randomized by design; the
 * pwDerivedKey + seed + addresses are what pin compatibility).
 *
 * Provenance: legacy/ == tag pre-modernization (d21df74) == ConsenSys
 * upstream master, verified byte-identical by eth-hot-wallet's session.
 */
const fs = require('fs');
const path = require('path');
const lw = require('../legacy/index.js');

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'golden-test-password-1';
const SALT = 'golden-fixed-salt-1';
const HD_PATH = "m/0'/0'/0'";

function hex(u8) { return Buffer.from(u8).toString('hex'); }

lw.keystore.deriveKeyFromPasswordAndSalt(PASSWORD, SALT, (err, pwDerivedKey) => {
  if (err) throw err;

  lw.keystore.createVault(
    { password: PASSWORD, seedPhrase: MNEMONIC, salt: SALT, hdPathString: HD_PATH },
    (err, ks) => {
      if (err) throw err;

      ks.generateNewAddress(pwDerivedKey, 5);
      const addresses = ks.getAddresses();
      const privKeys = addresses.map(a => ks.exportPrivateKey(a, pwDerivedKey));

      // Sign 3 legacy txs: plain ETH transfer, contract-call (ERC20-shaped),
      // and a value+data tx.
      const baseTx = {
        from: addresses[0],
        gasPrice: '0x4a817c800', // 20 gwei
        gasLimit: '0x5208',
        nonce: '0x00',
      };
      const signed = [];
      const txCases = [
        { ...baseTx, to: '0x3535353535353535353535353535353535353535', value: '0x0de0b6b3a7640000', data: '0x' },
        {
          ...baseTx, to: '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', value: '0x00', nonce: '0x01',
          data: '0xa9059cbb000000000000000000000000353535353535353535353535353535353535353500000000000000000000000000000000000000000000000000000000000f4240',
        },
        { ...baseTx, to: '0x1111111111111111111111111111111111111111', value: '0x01', nonce: '0x02', data: '0xdeadbeef' },
      ];
      for (const txObj of txCases) {
        const tx = lw.txutils.createTx(txObj);
        const rawUnsigned = lw.txutils.txToHexString(tx);
        const rawSigned = lw.signing.signTx(ks, pwDerivedKey, rawUnsigned, addresses[0]);
        signed.push({ txObject: txObj, rawUnsigned, rawSigned });
      }

      // v1 and v2 upgrade outputs (deterministic given fixed salt inside the
      // upgraded vault — upgrade passes the same password through createVault
      // with a generated salt, so serialized ciphertext varies per run; the
      // addresses + seed are the stable goldens).
      const v1 = JSON.parse(fs.readFileSync(path.join(__dirname, '../test/fixtures/lightwallet.json'), 'utf8'));
      const v2 = JSON.parse(fs.readFileSync(path.join(__dirname, '../test/fixtures/lightwalletv2.json'), 'utf8'));

      lw.upgrade.upgradeOldSerialized(JSON.stringify(v1), 'test', (err, upgradedV1Ser) => {
        if (err) throw err;
        const up1 = lw.keystore.deserialize(upgradedV1Ser);

        lw.upgrade.upgradeOldSerialized(JSON.stringify(v2), 'PHveKjhQ&8dwWEdhu]q6', (err, upgradedV2Ser) => {
          if (err) throw err;
          const up2 = lw.keystore.deserialize(upgradedV2Ser);

          const golden = {
            provenance: {
              generator: 'legacy/ == eth-lightwallet@4.0.0 (tag pre-modernization, d21df74 == ConsenSys upstream)',
              generatedAt: '2026-10-08',
              node: process.version,
            },
            kdf: {
              algorithm: 'scrypt',
              params: { logN: 14, r: 8, p: 1, dkLen: 32 },
              password: PASSWORD,
              salt: SALT,
              pwDerivedKeyHex: hex(pwDerivedKey),
            },
            vault: {
              input: { mnemonic: MNEMONIC, password: PASSWORD, salt: SALT, hdPathString: HD_PATH },
              serialized: ks.serialize(), // ciphertext nonce-random; see kdf + addresses for deterministic pins
              decryptedSeed: ks.getSeed(pwDerivedKey),
              hdIndexAfter: ks.hdIndex,
            },
            firstFiveAddresses: addresses,
            firstFivePrivateKeys: privKeys,
            signedLegacyTxs: signed,
            upgrades: {
              v1: { password: 'test', addresses: up1.getAddresses(), hdPathString: up1.hdPathString, hdIndex: up1.hdIndex },
              v2: { password: 'PHveKjhQ&8dwWEdhu]q6', addresses: up2.getAddresses(), hdPathString: up2.hdPathString, hdIndex: up2.hdIndex },
            },
          };

          const out = path.join(__dirname, '../test/golden/generated/vault-4.0.0.json');
          fs.mkdirSync(path.dirname(out), { recursive: true });
          fs.writeFileSync(out, JSON.stringify(golden, null, 2) + '\n');
          console.log('wrote', out);
          console.log('pwDerivedKey:', hex(pwDerivedKey));
          console.log('addresses:', addresses.join(' '));
          console.log('signedTx0 v tail:', signed[0].rawSigned.slice(-4));
        });
      });
    }
  );
});
