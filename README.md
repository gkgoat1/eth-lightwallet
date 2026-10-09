# LightWallet

A minimal ethereum javascript wallet.

> **5.0.0 (this branch):** TypeScript rewrite, ESM-first with a CommonJS build,
> modern audited dependencies (`@scure/*`, `@noble/*`, `@ethereumjs/*`, `viem`).
> **Behavior is preserved** — same addresses, same signed transactions, same
> keystore format, cross-compatible encryption — verified by golden fixtures and
> a comparison suite against the frozen 4.0.0 code. See
> [Migrating to 5.0.0](#migrating-to-500) and `RELEASE-NOTES.md`.

## Migrating to 5.0.0

**Install & import** — dual ESM/CJS, both work:

```js
// ESM
import lightwallet, { keystore, signing, txutils, encryption, upgrade } from '@gkgo/eth-lightwallet';

// CommonJS
const lightwallet = require('@gkgo/eth-lightwallet');
const { keystore } = require('@gkgo/eth-lightwallet');
```

TypeScript types are included (`dist/index.d.ts` / `index.d.cts`) and resolve
under both `moduleResolution: node16` and `bundler`.

**Breaking changes (packaging-level only):**

- **Node >= 18** required.
- The checked-in **browser bundle** (`dist/lightwallet.min.js`, browserify
  global) is **removed**. Bundle the ESM build yourself (vite/rollup/esbuild
  webpack all consume it). The default export and named exports map to the old
  `module.exports` shape, so `lightwallet.keystore` etc. are unchanged.
- **`signMsg`, `signMsgHash`, and `recoverAddress` are now async** (return
  Promises) because the underlying signer is async. `await` them. All other
  methods keep their callback signatures (`createVault`, `keyFromPassword`,
  `generateNewAddress`, `signTransaction`, …).
- Message signatures are still **byte-identical** to 4.0.0 (the `signMsg`
  golden passes unchanged); only the call is now awaited.

**What did NOT change:**

- Keystore serialization format (v3) — old vaults deserialize and decrypt.
- HD derivation, address generation, private keys (verified against the
  `addrprivkey100` + golden vectors).
- scrypt KDF params (`logN=14, r=8, p=1, dkLen=32`) — byte-identical derived keys.
- Legacy (pre-EIP-1559) transaction signing; `v = 27/28` unless you pass `chainId`.
- tweetnacl secretbox/box encryption — cross-compatible with 4.0.0 ciphertexts.
- v1/v2 → v3 keystore upgrades (byte-exact against the committed fixtures).

**Security note:** the 4.0.0 dependency tree had **31 known vulnerabilities**
(7 critical) — `npm audit` on the 5.0.0/5.1.0 runtime dependencies reports **0**.

## What's new in 5.1.0

All **backwards-compatible** and opt-in (v3 vaults + legacy txs unchanged):

- **EIP-1559 (type-2) transactions** — `txutils.create1559Tx` /
  `valueTx1559` / `functionTx1559` / `createContractTx1559`,
  `signing.sign1559Tx`, and `keystore.signTransaction{,Async}` with explicit
  **`txType: 2`** (never inferred from fee fields). Legacy (type-0) is the
  default.
- **v4 keystore format** (opt-in) — Argon2id KDF + XChaCha20-Poly1305 AEAD with
  AAD (tamper-evident). `KeyStoreV4`, `detectVersion`, and
  `upgrade.upgradeV3ToV4{,Async}` (preserves addresses/keys). v3 is still the
  default write format.
- **Post-quantum off-chain encryption** — `encryptionV4`: X25519 + ML-KEM-768
  hybrid (both must be broken) + AEAD. **Off-chain messages only;** on-chain
  signing stays classical secp256k1 (EVM constraint).
- **Async internals + dual API** — canonical `*Async` promise methods plus
  callback wrappers: `createVaultAsync`, `keyFromPasswordAsync`,
  `hasAddressAsync`, `signTransactionAsync`, `deriveKeyFromPasswordAndSaltAsync`,
  `upgradeOldSerializedAsync`, `upgradeV3ToV4Async`. `signMsg`/`signMsgHash`/
  `recoverAddress` also accept an optional trailing callback.

```js
// async/await
const ks = await keystore.createVaultAsync({ password, seedPhrase, hdPathString });
const pwDerivedKey = await ks.keyFromPasswordAsync(password);
const signedTx = await ks.signTransactionAsync({ from, to, value, gas, gasPrice, nonce });

// callbacks (unchanged)
keystore.createVault({ password, seedPhrase, hdPathString }, (err, ks) => { /* ... */ });
```

## About

LightWallet is a HD wallet that can store your private keys encrypted in the browser to allow you to run Ethereum dapps even if you're not running a local Ethereum node. It uses [BIP32][] and [BIP39][] to generate an HD tree of addresses from a randomly generated 12-word seed.

LightWallet is primarily intended to be a signing provider for the [Hooked Web3 provider](https://github.com/ConsenSys/hooked-web3-provider) through the `keystore` module. This allows you to have full control over your private keys while still connecting to a remote node to relay signed transactions. Moreover, the `txutils` functions can be used to construct transactions when offline, for use in e.g. air-gapped coldwallet implementations.

The default BIP32 HD derivation path has been `m/0'/0'/0'/i`, but any HD path can be chosen.

## Security

Please note that LightWallet has not been through a comprehensive security review at this point. It is still experimental software, intended for small amounts of Ether to be used for interacting with smart contracts on the Ethereum blockchain. Do not rely on it to store larger amounts of Ether yet.

## Get Started

```
npm install @gkgo/eth-lightwallet
```

As of 5.0.0 there is no pre-built browser bundle. Consume the ESM build
(`dist/index.js`) through your own bundler (vite/rollup/esbuild/webpack):

```js
import lightwallet from '@gkgo/eth-lightwallet';
// lightwallet.keystore, lightwallet.txutils, lightwallet.signing, ...
```

Sample recommended usage with hooked web3 provider:

```js
// the seed is stored encrypted by a user-defined password
var password = prompt('Enter password for encryption', 'password');

keyStore.createVault({
  password: password,
  // seedPhrase: seedPhrase, // Optionally provide a 12-word seed phrase
  // salt: fixture.salt,     // Optionally provide a salt.
                             // A unique salt will be generated otherwise.
  // hdPathString: hdPath    // Optional custom HD Path String
}, function (err, ks) {

  // Some methods will require providing the `pwDerivedKey`,
  // Allowing you to only decrypt private keys on an as-needed basis.
  // You can generate that value with this convenient method:
  ks.keyFromPassword(password, function (err, pwDerivedKey) {
    if (err) throw err;

    // generate five new address/private key pairs
    // the corresponding private keys are also encrypted
    ks.generateNewAddress(pwDerivedKey, 5);
    var addr = ks.getAddresses();

    ks.passwordProvider = function (callback) {
      var pw = prompt("Please enter password", "Password");
      callback(null, pw);
    };

    // Now set ks as transaction_signer in the hooked web3 provider
    // and you can start using web3 using the keys/addresses in ks!
  });
});
```

Sample old-style usage with hooked web3 provider (still works, but less secure because uses fixed salts).

```js
// generate a new BIP32 12-word seed
var secretSeed = lightwallet.keystore.generateRandomSeed();

// the seed is stored encrypted by a user-defined password
var password = prompt('Enter password for encryption', 'password');
lightwallet.keystore.deriveKeyFromPassword(password, function (err, pwDerivedKey) {

var ks = new lightwallet.keystore(secretSeed, pwDerivedKey);

// generate five new address/private key pairs
// the corresponding private keys are also encrypted
ks.generateNewAddress(pwDerivedKey, 5);
var addr = ks.getAddresses();

// Create a custom passwordProvider to prompt the user to enter their
// password whenever the hooked web3 provider issues a sendTransaction
// call.
ks.passwordProvider = function (callback) {
  var pw = prompt("Please enter password", "Password");
  callback(null, pw);
};

// Now set ks as transaction_signer in the hooked web3 provider
// and you can start using web3 using the keys/addresses in ks!
});
```

## `keystore` Function definitions

These are the interface functions for the keystore object. The keystore object holds a 12-word seed according to [BIP39][] spec. From this seed you can generate addresses and private keys, and use the private keys to sign transactions.

Note: Addresses and RLP encoded data are in the form of hex-strings. Hex-strings start with `0x`.

### `keystore.createVault(options, callback)`

This is the interface to create a new lightwallet keystore.

#### Options

* password: (mandatory) A string used to encrypt the vault when serialized.
* seedPhrase: (mandatory) A twelve-word mnemonic used to generate all accounts.
* salt: (optional) The user may supply the salt used to encrypt & decrypt the vault, otherwise a random salt will be generated.
* hdPathString (mandatory): The user must provide a `BIP39` compliant HD Path String. Previously the default has been `m/0'/0'/0'`, another popular one is the BIP44 path string `m/44'/60'/0'/0`.

### `keystore.keyFromPassword(password, callback)`

This instance method uses any internally-configured salt to return the appropriate `pwDerivedKey`.

Takes the user's password as input and generates a symmetric key of type `Uint8Array` that is used to encrypt/decrypt the keystore.

### `keystore.isDerivedKeyCorrect(pwDerivedKey)`

Returns `true` if the derived key can decrypt the seed, and returns `false` otherwise.

### `keystore.generateRandomSeed([extraEntropy])`

Generates a string consisting of a random 12-word seed and returns it. If the optional argument string `extraEntropy` is present the random data from the Javascript RNG will be concatenated with `extraEntropy` and then hashed to produce the final seed. The string `extraEntropy` can be something like entropy from mouse movements or keyboard presses, or a string representing dice throws.

### `keystore.isSeedValid(seed)`

Checks if `seed` is a valid 12-word seed according to the [BIP39][] specification.

### `keystore.generateNewAddress(pwDerivedKey, [num])`

Allows the vault to generate additional internal address/private key pairs.

The simplest usage is `ks.generateNewAddress(pwDerivedKey)`.

Generates `num` new address/private key pairs (defaults to 1) in the keystore from the seed phrase, which will be returned with calls to `ks.getAddresses()`.

### `keystore.deserialize(serialized_keystore)`

Takes a serialized keystore string `serialized_keystore` and returns a new keystore object.

### `keystore.serialize()`

Serializes the current keystore object into a JSON-encoded string and returns that string.

### `keystore.getAddresses()`

Returns a list of hex-string addresses currently stored in the keystore.

### `keystore.getSeed(pwDerivedKey)`

Given the pwDerivedKey, decrypts and returns the users 12-word seed.

### `keystore.exportPrivateKey(address, pwDerivedKey)`

Given the derived key, decrypts and returns the private key corresponding to `address`. This should be done sparingly as the recommended practice is for the `keystore` to sign transactions using `signing.signTx`, so there is normally no need to export private keys.

## `upgrade` Function definitions

### `keystore.upgradeOldSerialized(oldSerialized, password, callback)`

Takes a serialized keystore in an old format and a password. The callback takes the upgraded serialized keystore as its second argument.

## `signing` Function definitions

### `signing.signTx(keystore, pwDerivedKey, rawTx, signingAddress, hdPathString)`

Signs a transaction with the private key corresponding to `signingAddress`.

#### Inputs

* `keystore`: An instance of the keystore with which to sign the TX with.
* `pwDerivedKey`: the users password derived key (Uint8Array)
* `rawTx`: Hex-string defining an RLP-encoded raw transaction.
* `signingAddress`: hex-string defining the address to send the transaction from.
* `hdPathString`: (Optional) A path at which to create the encryption keys.

#### Return value

Hex-string corresponding to the RLP-encoded raw transaction.

### `signing.signMsg(keystore, pwDerivedKey, rawMsg, signingAddress, hdPathString)`

Creates and signs a sha3 hash of a message with the private key corresponding to `signingAddress`.

#### Inputs

* `keystore`: An instance of the keystore with which to sign the TX with.
* `pwDerivedKey`: the users password derived key (Uint8Array)
* `rawMsg`: Message to be signed
* `signingAddress`: hex-string defining the address corresponding to the signing private key.
* `hdPathString`: (Optional) A path at which to create the encryption keys.

#### Return value

Signed hash as signature object with v, r and s values.

### `signing.signMsgHash(keystore, pwDerivedKey, msgHash, signingAddress, hdPathString)`

Signs a sha3 message hash with the private key corresponding to `signingAddress`.

#### Inputs

* `keystore`: An instance of the keystore with which to sign the TX with.
* `pwDerivedKey`: the users password derived key (Uint8Array)
* `msgHash`: SHA3 hash to be signed
* `signingAddress`: hex-string defining the address corresponding to the signing private key.
* `hdPathString`: (Optional) A path at which to create the encryption keys.

#### Return value

Signed hash as signature object with v, r and s values.

### `signing.concatSig(signature)`

Concatenates signature object to return signature as hex-string in the same format as `eth_sign` does.

#### Inputs

* `signature`: Signature object as returned from `signMsg` or ``signMsgHash`.

#### Return value

Concatenated signature object as hex-string.

### `signing.recoverAddress(rawMsg, v, r, s)`

Recovers the signing address from the message `rawMsg` and the signature `v, r, s`.


## `encryption` Function definitions

### `encryption.multiEncryptString(keystore, pwDerivedKey, msg, myAddress, theirPubKeyArray)`

**NOTE:** The format of encrypted messages has not been finalized and may change at any time, so only use this for ephemeral messages that do not need to be stored encrypted for a long time.

Encrypts the string `msg` with a randomly generated symmetric key, then encrypts that symmetric key assymetrically to each of the pubkeys in `theirPubKeyArray`. The encrypted message can then be read only by sender and the holders of the private keys corresponding to the public keys in `theirPubKeyArray`. The returned object has the following form, where nonces and ciphertexts are encoded in base64:

```js
{ version: 1,
  asymAlg: 'curve25519-xsalsa20-poly1305',
  symAlg: 'xsalsa20-poly1305',
  symNonce: 'SLmxcH3/CPMCCJ7orkI7iSjetRlMmzQH',
  symEncMessage: 'iN4+/b5InlsVo5Bc7GTmaBh8SgWV8OBMHKHMVf7aq5O9eqwnIzVXeX4yzUWbw2w=',
  encryptedSymKey:
   [ { nonce: 'qcNCtKqiooYLlRuIrNlNVtF8zftoT5Cb',
       ciphertext: 'L8c12EJsFYM1K7udgHDRrdHhQ7ng+VMkzOdVFTjWu0jmUzpehFeqyoEyg8cROBmm' },
     { nonce: 'puD2x3wmQKu3OIyxgJq2kG2Hz01+dxXs',
       ciphertext: 'gLYtYpJbeFKXL/WAK0hyyGEelaL5Ddq9BU3249+hdZZ7xgTAZVL8tw+fIVcvpgaZ' },
     { nonce: '1g8VbftPnjc+1NG3zCGwZS8KO73yjucu',
       ciphertext: 'pftERJOPDV2dfP+C2vOwPWT43Q89V74Nfu1arNQeTMphSHqVuUXItbyCMizISTxG' },
     { nonce: 'KAH+cCxbFGSDjHDOBzDhMboQdFWepvBw',
       ciphertext: 'XWmmBmxLEyLTUmUBiWy2wDqedubsa0KTcufhKM7YfJn/eHWhDDptMxYDvaKisFmn' } ] }
```

Note that no padding is applied to `msg`, so it's possible to deduce the length of the string `msg` from the ciphertext. If you don't want this information to be known, please apply padding to `msg` before calling this function.

### `encryption.multiDecryptString(keystore, pwDerivedKey, encMsg, theirPubKey, myAddress)`

Decrypt a message `encMsg` created with the function
`multiEncryptString()`. If successful, returns the original message
string. If not successful, returns `false`.

### `encryption.addressToPublicEncKey(keystore, pwDerivedKey, address)`

Gets the public encryption key corresponding to the private key of `address` in the `keystore`.

## `txutils` Function definitions

These are the interface functions for the `txutils` module. These functions will create RLP encoded raw unsigned transactions which can be signed using the `keystore.signTx()` command.

### `txutils.createContractTx(fromAddress, txObject)`

Using the data in `txObject`, creates an RLP-encoded transaction that will create the contract with compiled bytecode defined by `txObject.data`. Also computes the address of the created contract.

#### Inputs

* `fromAddress`: Address to send the transaction from
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Endowment (optional)
* `txObject.nonce`: Nonce of `fromAddress`
* `txObject.data`: Compiled code of the contract

#### Output

Object `obj` with fields

* `obj.tx`: RLP encoded transaction (hex string)
* `obj.addr`: Address of the created contract

### `txutils.functionTx(abi, functionName, args, txObject)`

Creates a transaction calling a function with name `functionName`, with arguments `args` conforming to `abi`. The function is defined in a contract with address `txObject.to`.

#### Inputs

* `abi`: Json-formatted ABI as returned from the `solc` compiler
* `functionName`: string with the function name
* `args`: Array with the arguments to the function
* `txObject.to`: Address of the contract
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Value to send
* `txObject.nonce`: Nonce of sending address

#### Output

RLP-encoded hex string defining the transaction.


### `txutils.valueTx(txObject)`

Creates a transaction sending value to `txObject.to`.

#### Inputs

* `txObject.to`: Address to send to
* `txObject.gasLimit`: Gas limit
* `txObject.gasPrice`: Gas price
* `txObject.value`: Value to send
* `txObject.nonce`: Nonce of sending address

#### Output

RLP-encoded hex string defining the transaction.

## Examples

See the file `example_usage.js` for usage of `keystore` and `txutils` in node.

See the file `example_web.html` for an example of how to use the LightWallet keystore together with the Hooked Web3 Provider in the browser.

## Tests

Run all tests:

```
npm run test
npm run coverage
```

[BIP39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
[BIP32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

## License

MIT License.
