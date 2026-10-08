# Release Notes #

## Version 5.0.0 - 2026-10-08 ##

TypeScript rewrite with modern audited dependencies, ESM-first dual build.
**Behavior preserved** — verified against the frozen 4.0.0 code via golden
fixtures, a live comparison suite (`legacy/` vs `src/`), and Anvil end-to-end
tests.

### Breaking (packaging-level only)

* **Node >= 18** required.
* Removed the checked-in browserify bundle (`dist/lightwallet.min.js`). The
  package now ships `dist/index.js` (ESM) + `dist/index.cjs` (CJS) +
  `dist/index.d.ts`/`index.d.cts`. Bundle the ESM build for browsers yourself.
* `signMsg`, `signMsgHash`, `recoverAddress` are now **async** (return
  Promises). All other methods keep their callback signatures.
* `hdPathString` remains **required** in `createVault` (unchanged from 4.0.0).

### Behavior preserved (verified)

* Keystore v3 serialization format — old vaults deserialize + decrypt.
* HD derivation / addresses / private keys (golden + `addrprivkey100` vectors).
* scrypt KDF (`logN=14, r=8, p=1, dkLen=32`) — byte-identical derived keys.
* Legacy pre-EIP-1559 tx signing, `v = 27/28` unless `chainId` is passed —
  the pinned `rawSignedTx` fixtures are byte-exact.
* **Message signatures are byte-identical** to 4.0.0 (the `expectedConcatSig`
  golden passes unchanged) — only the call is now awaited.
* tweetnacl secretbox/box encryption — cross-compatible with 4.0.0 ciphertexts.
* v1/v2 → v3 keystore upgrades (byte-exact vs committed fixtures).

### Dependencies

* Dropped: `web3@0.20`, `ethereumjs-tx@1`, `ethereumjs-util@6`, `bitcore-lib`,
  `bitcore-mnemonic`, `elliptic`, `scrypt-async`, `rlp` (old), `crypto-js@3`.
* Added: `@scure/bip39`, `@scure/bip32`, `@noble/hashes`, `@noble/curves`,
  `@ethereumjs/tx`, `@ethereumjs/rlp`, `@ethereumjs/util`, `@ethereumjs/common`,
  `viem`, `crypto-js@4` (v1-upgrade AES-CBC only, off the default path).
* Kept: `tweetnacl`, `tweetnacl-util` (stable, pure-JS, isomorphic).
* **Security:** 4.0.0's dependency tree had **31 known vulnerabilities**
  (7 critical, 6 high). `npm audit --omit=dev` on 5.0.0's runtime deps reports
  **0**.

### Build

* Bundler: **tsdown** (rolldown). Dual ESM+CJS + per-condition `.d.ts`/`.d.cts`.
* `exports` map: `import` → `dist/index.js` (+`index.d.ts`), `require` →
  `dist/index.cjs` (+`index.d.cts`). `prepare` script self-builds for git deps.

### Internal

* The 4.0.0 source is frozen under `legacy/` as the comparison-test oracle.
* Tests: vitest (unit + golden + comparison + Anvil e2e), plus the original
  mocha suite redirected at `legacy/` as a regression floor.

## Version 4.0.0 - 2019-03-26 ##

* Major cleanup - backwards compatible!
* Updated all dependencies
* Code optimizations
* Migrated to ES6

## Version 3.0.1 - 2017-11-14 ##

* Fixed an issue with `signing.concatSig` where the `r` and `s` were not left padded, and the resulting signature was invalid.
* Removed dist files from git.

## Version 3.0.0 - 2017-11-01 ##

* Major cleanup - not backwards compatible!

* Remove legacy constructor - now only `createVault` is supported. Also `createVault` now require seed and hd path as inputs.

* Remove `deriveKeyFromPassword` function in favor of `keyFromPassword` function.

* Remove special handling of encryption keys in the keystore. You can still use keystore keys to encrypt, but they no longer use pubkeys to index. To get the pubkey corresponding to an address, please use the function `encryption.addressToPublicEncKey`.

* Make the keystore and interfaces simpler by only allowing one `hdPathString`. If you need to derive from more HD paths you need to create more keystores.

* Add `0x` prefix for all addresses and transaction hex data.

* Remove unneeded `bitcore-lib` package dependency. Thanks to [Srirangan](https://github.com/Srirangan).

## Version 2.5.6 - 2017-06-24 ##

* Switch back to using npm version of `web3.js`, since version `0.19.1` is now fixed.

## Version 2.5.5 - 2017-06-23 ##

* Remove redundant dependency on `bignumber.js` library which has stopped working. Temporarily use a fork of `web3.js` since this library also breaks because of the issues with the `bignumber.js` library. 

## Version 2.5.4 - 2017-03-16 ##

* Upgrade bitcore-lib and explicitly increase version of bitcore-mnemonic. By [roderik](https://github.com/roderik).

* Upgrade ethereumjs-util and add needed babel plugins.

* Update dist files

## Version 2.5.3 - 2016-11-05 ##

* Make sure the deprecation warning doesn't show up when we are using the new constructor. By [flyswatter](https://github.com/flyswatter).

## Version 2.5.2 - 2016-09-08 ##

* Fixed a bug that caused the dist files to fail in browsers.

* Update dist files.

## Version 2.5.1 - 2016-09-07 ##

* Update dist files.

## Version 2.5.0 - 2016-09-07 ##

* Introduced a new constructor function that introduces a random seed in key derivation, which protects against rainbow attacks. By [flyswatter](https://github.com/flyswatter).

## Version 2.4.4 - 2016-08-17 ##

* Fixed an issue that caused lightwallet to fail in Firefox 48+. By [miladmostavi](https://github.com/miladmostavi).

## Version 2.4.3 - 2016-06-20 ##

* Update README.

## Version 2.4.2 - 2016-06-20 ##

* Add more safety checks for valid password derived keys.

## Version 2.4.1 - 2016-06-08 ##

* Add correct deserialization of default HD path. By [johnmcdowall](https://github.com/johnmcdowall).

* Fix a bug where the default HD path was not set correctly in the constructor.

## Version 2.4.0 - 2016-06-08 ##

* Add new message signing function `signMsgHash()`. By [Georgi87](https://github.com/Georgi87).

## Version 2.3.3 - 2016-05-26 ##

* Fixed a bug which would create random addresses if the wrong
  pwDerivedKey was used.

## Version 2.3.2 - 2016-04-06 ##

* Add "var" statements for function declarations. Thanks to [dalexj](https://github.com/dalexj) and [pipermerriam](https://github.com/pipermerriam).

## Version 2.3.1 - 2016-04-06 ##

* Add missing built files. Thanks to [area](https://github.com/area).

## Version 2.3.0 - 2016-03-31 ##

* Add functions `signMsg` and `recoverAddress` for signing messages and recovering the signing address. Thanks to [ckeenan](https://github.com/ckeenan) and [Georgi87](https://github.com/Georgi87).

## Version 2.2.5 - 2016-03-16 ##

* Fixed a bug where there uglify would cause an infinite loop in the elliptic library. Thanks to [pelle](https://github.com/pelle) for the fix.

## Version 2.2.4 - 2016-03-16 ##

* Update dependencies

## Version 2.2.3 - 2016-03-03 ##

* Fixed bug in serialization
* Add non-minified distributable

## Version 2.2.2 - 2016-02-26 ##

* Update distributable.

## Version 2.2.1 - 2016-02-25 ##

* Handle bug from bitcore where leading zeros are stripped. We do this by padding the private key to 32 bytes in the `keystore._generatePrivKeys()` function.

* Remove unsupported `string.repeat()` function. H/T [chrisforrester](https://github.com/chrisforrester).

* Change `Uint8Array.from()` to `new Uint8Array` in key derivation. H/T [chrisforrester](https://github.com/chrisforrester).

* Update `ethereumjs-tx` library dependency.

* Hardened dependency on `bignumber.js` to specific commit.

## Version 2.2.0 - 2016-02-14 ##

* Change order of parameters in `encryption` module.

* Add function `keystore.isDerivedKeyCorrect()`.

* Removed redundant data members `keyHash, salt` of the keystore. 

## Version 2.1.0 - 2016-02-14 ##

* Refactoring by [cubedro](https://github.com/cubedro) - move functions out to separate modules (signing, encryption) in order to make the core keystore object less cluttered.

## Version 2.0.0 - 2016-02-09 ##

* Big refactoring of password handling. Key derivation is now moved out into an asyncronous function allowing for more secure password-based key derivation or user-supplied keys. A helper function is provided with Scrypt key derivation.

* Change from using AES for keystore encryption to using xsalsa20 (in the form of `nacl.secretbox`). This provides a simpler interface for the symmetric encryption.

* Updated tests with the new password handling and correct usage of `done()`.

## Version 1.0.1 - 2016-01-19 ##

* Formatting changes in documentation.

## Version 1.0.0 - 2015-12-09 ##

* Ability to have multiple HD derivation paths - allowing multiple Personas from one wallet seed

* The ability to designate that keys from a derivation path should be used for asymmetric encryption using Curve25519

* Ability to encrypt messages using keys in the lightwallet: messages can be encrypted to multiple recipients, allowing selective disclosure of Persona attributes as well as things like encrypted group chats between Personas

* A massive test of the private key —> address functionality using a file with 10000 pseudorandomly generated private keys.

* Fixed issues with nested `bitcore-lib` packages that would cause the build to fail with NPM3
