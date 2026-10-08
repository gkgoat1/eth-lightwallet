# Plan: Modernize eth-lightwallet — TS, tsdown, ESM+CJS, modern deps

- **Status:** In progress — Phase 0 complete (2026-10-08)
- **Date:** 2026-10-08
- **Branch:** `modernize` (consumed by `eth-hot-wallet` as commit-pinned git dep `eth-lightwallet-next` — see §10)
- **Repo:** `eth-lightwallet` (fork `gkgoat1/eth-lightwallet`, upstream `ConsenSys/eth-lightwallet`, last release 4.0.0)
- **Target release:** 5.0.0 (semver-major; breaking changes are packaging-level, not behavioral)

## 1. Goal

Port the library to TypeScript, build it with `tsdown`, ship dual ESM + CommonJS
with proper `exports` maps and generated `.d.ts`, and replace
abandoned/vulnerable dependencies (`web3@0.20`, `ethereumjs-tx@1`, `bitcore-*`,
`scrypt-async`, `crypto-js`, `browserify`/`babelify`/`uglify`) with maintained
ones — **without changing observable behavior**: identical addresses, identical
serialized transactions and signatures, cross-compatible encryption, and
cross-compatible keystore upgrade paths.

CommonJS consumers (`require('eth-lightwallet')`) must keep working.

## 2. Non-goals

- No API redesign. The callback-style API (`createVault(opts, cb)`,
  `keyFromPassword(pw, cb)`, `signTransaction(params, cb)`, …) is preserved
  as-is. Promise wrappers are a possible 5.x addition, out of scope here.
- No support for post-EIP-1559 typed transactions (EIP-1559/2930/4844). The
  library builds legacy transactions today; it keeps building legacy
  transactions. (Anvil accepts and mines them on any gas config.)
- No browser bundle rewrite. `dist/lightwallet.min.js` (browserify global) is
  dropped; bundlers consume the ESM build directly. A standalone IIFE build can
  be re-added later via tsdown if anyone asks.
- No change to default scrypt parameters (logN=14, r=8, dkLen=32) or
  `DEFAULT_SALT` semantics.
- `example/` HTML demos are updated to the new import surface but not redesigned.

## 3. Current state (baseline)

| Area | Today |
|---|---|
| Modules | `index.js` + `lib/{keystore,signing,txutils,encryption,upgrade,assert}.js` (~860 LoC) |
| Module format | CommonJS only (`main: index.js`) |
| Build | browserify + babelify + uglify → `dist/` (checked into git, to be gitignored) |
| Tests | mocha 6 + chai, 4 suites, JSON fixtures incl. `addrprivkey100.json` and v1/v2 keystore fixtures |
| Crypto deps | `crypto-js` (keccak-256! AES/PBKDF2), `elliptic` (secp256k1), `tweetnacl` (secretbox/box), `scrypt-async` (KDF) |
| Ethereum deps | `ethereumjs-tx@1.3.7`, `ethereumjs-util@6.1.0`, `rlp`, `web3@0.20.7` (only `lib/solidity/coder` for ABI encoding) |
| HD/BIP39 | `bitcore-lib@8.1.1` + `bitcore-mnemonic@8.1.1` (abandoned, heavy) |
| Node | Untested on modern Node; `new Buffer(...)` deprecations throughout |

### Known behavioral quirks that MUST be preserved

1. **SHA3 ≠ keccak.** `crypto-js`'s `SHA3(..., {outputLength: 256})` with
   pre-NIST padding is used for addresses (`_computeAddressFromPrivKey`),
   function selectors (`_encodeFunctionTxData`), and contract addresses
   (`createdContractAddress`). It happens to match Ethereum keccak-256 for
   these inputs as used, and all fixtures depend on it. Replacement: real
   `keccak_256` (viem / `@noble/hashes`), verified against every fixture.
2. **Left-padded seed.** The mnemonic is space-padded to 120 chars before
   secretbox encryption; `getSeed` trims. Fixtures assert `length === 120`.
3. **Short-key padding.** bitcore occasionally returns <32-byte private keys;
   `_generatePrivKeys` left-pads hex to 64 chars. `addrprivkey100.json` was
   generated through this path.
4. **Pre-EIP-155 signatures by default.** `ethereumjs-tx@1` signs with
   `v = recid + 27` unless a chainId is given. Golden `rawSignedTx` fixtures
   pin this.
5. **`signMsg` hashes without the Ethereum message prefix** — historical,
   non-standard, must stay.
6. **nacl box misuse-as-symmetric.** Asymmetric encryption reuses the
   secp256k1 private key bytes as a curve25519 secret key
   (`Nacl.box.keyPair.fromSecretKey`). Preserve exactly; both sides of a
   conversation use the same convention.
7. **`deriveKeyFromPasswordAndSalt` salt-optional overload** (defaults to
   `'lightwalletSalt'`) and callback error shape (`err, Uint8Array`).
8. **Upgrade paths v1→v3 and v2→v3**, including CryptoJS PBKDF2/AES
   (EVP_BytesToKey-style) legacy decryption for v1 keystores, and
   `hdIndex` replay via `generateNewAddress`.

## 4. Target architecture

```
src/
  index.ts        — named exports { keystore, signing, txutils, encryption, upgrade } + default
  keystore.ts     — class KeyStore (was prototype object; keep statics)
  signing.ts
  txutils.ts
  encryption.ts
  upgrade.ts
  internal/
    assert.ts     — derivedKey check
    hex.ts        — addHexPrefix/stripHexPrefix helpers (tiny, local)
legacy/           — frozen copy of current lib/ + index.js, DEV-ONLY (excluded from `files`)
test/
  unit/           — ported mocha suites → vitest, against src/
  golden/         — fixture-driven vectors (existing fixtures, unchanged)
  comparison/     — legacy/ vs src/ equivalence
  e2e/            — Anvil-backed end-to-end
  fixtures/       — unchanged
docs/plans/…      — this document
```

### 4.1 Build & packaging

- **Bundler:** `tsdown` (rolldown-based), entry `src/index.ts`, outputs:
  - `dist/index.js` (ESM) + `dist/index.d.ts`
  - `dist/index.cjs` (CJS) + `dist/index.d.cts`
- **package.json** sketch:

```jsonc
{
  "version": "5.0.0",
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "types": "./dist/index.d.ts",
      "import": "./dist/index.js",
      "require": "./dist/index.cjs"
    },
    "./package.json": "./package.json"
  },
  "files": ["dist"],
  "sideEffects": false,
  "engines": { "node": ">=18" },
  "scripts": {
    "build": "tsdown",
    "test": "vitest run",
    "test:e2e": "vitest run --project e2e",
    "typecheck": "tsc --noEmit",
    "prepublishOnly": "npm run typecheck && npm run build && npm test"
  }
}
```

- **CJS usability contract (verified by smoke tests, not just config):**
  - `const lw = require('eth-lightwallet')` → `lw.keystore`, `lw.signing`, …
  - `import lw from 'eth-lightwallet'` and
    `import { keystore } from 'eth-lightwallet'` both work.
  - Subpath imports are *not* provided in 5.0.0 (keeps surface small; add
    `./keystore` etc. later if wanted).

### 4.2 Dependency mapping

| Old (drop) | Replacement | Used for | Verification |
|---|---|---|---|
| `bitcore-lib`, `bitcore-mnemonic` | `viem` (`mnemonicToAccount` / `HDKey` from `@scure/bip39` + `@scure/bip32`, re-exported) | BIP39 validate, HD derive, `generateRandomSeed` | `addrprivkey100.json` golden + comparison vs legacy on 3 HD paths |
| `ethereumjs-tx@1` | `@ethereumjs/tx@^5` (`createLegacyTx`, `sign`) | legacy tx build/sign/serialize | golden `rawUnsignedTx`/`rawSignedTx` + comparison |
| `ethereumjs-util@6` | `viem` + `@noble/curves` (`secp256k1`) | hex prefixing, `ecsign`/`ecrecover`, `pubToAddress`, `keccak` | golden signing vectors + comparison |
| `web3@0.20` (`solidity/coder`) | `viem` (`encodeFunctionData`, `encodeFunctionSignature` semantics) | ABI encoding in `functionTx` | `txutils.json` fixtures + comparison |
| `rlp` | `@ethereumjs/rlp` (or viem `toRlp`) | `createdContractAddress` | fixture + comparison + Anvil `receipt.contractAddress` |
| `crypto-js` (keccak) | `@noble/hashes` `keccak_256` (via viem) | addresses, selectors | every address/selector fixture |
| `crypto-js` (PBKDF2/AES, v1 upgrade only) | `node:crypto` PBKDF2 + manual EVP_BytesToKey AES-256-CBC, **or** keep `crypto-js@^4` | v1 keystore upgrade | v1 fixture (`lightwallet.json`) upgrade test — decide in Phase 3 |
| `scrypt-async` | `scrypt-js@^3` (async, pure JS, same params) | password KDF | byte-equal derived keys vs legacy on fixture vectors |
| `elliptic` | `@noble/curves` `secp256k1` | pubkey from privkey | address fixtures |
| `tweetnacl`, `tweetnacl-util` | **keep** (`tweetnacl@^1` is stable, pure JS, ships its own types; maintained-enough) | secretbox/box encryption | cross-decrypt comparison |
| `new Buffer(...)` | `Buffer.from` / `Uint8Array` + `viem` hex utils | — | whole suite |
| browserify/babelify/uglify/istanbul/bluebird/async | **delete** | — | — |

Runtime deps after migration: `viem`, `@ethereumjs/tx`, `@ethereumjs/rlp`
(or fold into viem), `@noble/curves`, `@noble/hashes`, `scrypt-js`,
`tweetnacl`, `tweetnacl-util` (+ maybe `crypto-js` for v1 upgrade only).

Dev deps: `typescript`, `tsdown`, `vitest`, `@viem/anvil`, the **legacy dep
set** (pinned old versions, needed only so `legacy/` keeps running for
comparison tests), `@types/node`.

### 4.3 RNG decision (flag)

`generateSalt` uses `BitCore.crypto.Random`, which on modern Node falls back to
`crypto.randomBytes` anyway; bitcore's browser RNG is the weak path.
**Recommendation:** switch salt/nonce generation to `crypto.getRandomValues` /
`node:crypto`. This is invisible to golden fixtures (they pin
salt/ciphertexts) and to comparison tests (which cross-decrypt rather than
compare ciphertexts). If strict bit-for-bit legacy RNG behavior is ever
required, that requirement is a bug, not a feature. **Decide in Phase 3;
default = CSPRNG.**

## 5. Testing strategy

### 5.1 Golden fixtures (regression floor)

All existing fixtures are reused untouched:

- `keystore.json` — pwDerivedKey, seed, addresses, `rawUnsignedTx`,
  `rawSignedTx`, sig vectors.
- `addrprivkey100.json` — 100 address/privkey pairs through the HD path
  (incl. the short-key padding quirk).
- `txutils.json` — ABI types, function tx hex, contract addresses.
- `lightwallet.json` (v1), `lightwalletv2.json` (v2) — upgrade vectors.

These alone catch most crypto drift. They are necessary but **not sufficient**
(randomized paths like fresh `createVault` salts, encryption nonces, and
scrypt KDF aren't fully pinned).

### 5.2 Comparison tests vs the original code

The current `lib/` + `index.js` is copied verbatim into `legacy/` **before any
edits** (Phase 0), with its old runtime deps pinned as devDependencies.
`test/comparison/` imports both `legacy/` and `src/` and asserts:

1. **HD parity:** for each fixture mnemonic × {`m/0'/0'/0'`,
   `m/44'/60'/0'/0`, `m/0'/0'/2'`} × 10 addresses — equal addresses and equal
   exported private keys.
2. **scrypt parity:** `deriveKeyFromPasswordAndSalt` byte-equal outputs for 3
   (password, salt) pairs, incl. the default-salt overload.
3. **Encryption cross-compat:** ciphertext produced by *either* side decrypts
   on the other — `asym`, `multi` (2 recipients), `_encryptString/_encryptKey`
   round-trips, `addressToPublicEncKey` equality.
4. **Keystore cross-compat:** a vault serialized by legacy deserializes in new
   code (and vice versa) and derives the same next address; `isDerivedKeyCorrect`,
   `getSeed`, `exportPrivateKey` agree.
5. **Tx parity:** `createTx`/`valueTx`/`functionTx`/`createContractTx`/
   `createdContractAddress` hex-equal on `txutils.json` inputs.
6. **Signing parity:** `signTx`, `signMsgHash`+`concatSig`, `recoverAddress`
   equal on fixture vectors.
7. **Upgrade parity:** v1 and v2 fixtures upgraded by both sides yield equal
   seed + address sets (ciphertexts differ by RNG — compare decrypted content).

**Contingency (the "if not compromised" clause):** if the legacy code or its
pinned deps cannot run on the CI Node version (e.g. bitcore build breakage),
the comparison suite is gated (`describe.skip` + loud warning), the failure is
documented in RELEASE-NOTES, and golden fixtures become the sole regression
floor. This must be a visible, deliberate degradation — never silent.

### 5.3 Anvil end-to-end tests (`test/e2e/`)

Anvil is installed (`anvil 1.8.3`). Drive it with `@viem/anvil`
(`createAnvil({ port })` in `beforeAll`, `stop()` in `afterAll`; loopback only,
no external network — LuLu-friendly).

1. **Funded legacy value transfer:** vault from fixture mnemonic → derive
   address → fund it from an Anvil dev account → `txutils.valueTx` →
   `signing.signTx` → `sendRawTransaction` → receipt `status: 'success'` and
   recipient balance delta matches.
2. **Contract deployment:** `createContractTx` with pinned SimpleStorage-style
   bytecode (bytecode + ABI + source + solc version recorded in the fixture
   file, compiled once, checked in) → sign → send → assert
   `receipt.contractAddress === createdContractAddress(from, nonce)`.
3. **Contract call:** `functionTx(abi, 'set', [42], …)` → sign → send →
   `eth_call` `get()` returns 42.
4. **Full keystore flow:** `createVault` → `keyFromPassword` →
   `generateNewAddress` → `signTransaction` (with injected
   `passwordProvider`, since the default uses `prompt()`) → mined.
5. **Signature recovery on-chain:** `signMsgHash` + `concatSig` → recover via
   Anvil/`ecrecover` precompile test contract or viem `recoverAddress` →
   equals signer.

These prove the modernized stack interoperates with a real EVM, which fixture
tests cannot.

### 5.4 Packaging smoke tests

A tiny script (run in CI after `npm pack`):

- `node -e "const lw=require('./pkg'); …"` — CJS surface.
- `node --input-type=module -e "import lw from './pkg/dist/index.js'; …"` — ESM.
- `tsc` consumer fixture importing the packed tarball — types resolve under
  both `moduleResolution: node16` and `bundler`.

## 6. Phases & tasks

### Phase 0 — Baseline & freeze (½ day) — **DONE 2026-10-08**

- [x] Tag `pre-modernization` on current HEAD (`d21df74`).
- [x] Run the existing mocha suite on the current Node: **all 144 tests pass
      on Node v26.10.0** (only fix needed: drop the
      `hooked-web3-provider` devDependency — its git repo
      `christianlundkvist/hooked-web3-provider#updates_web3_14` is deleted
      from GitHub, so `npm install` hard-failed with it present; it is unused
      by `lib/` and `test/`). → **Comparison tests are the primary
      verification mechanism** (contingency in §5.2 not triggered).
- [x] Copied `lib/*.js` + `index.js` into `legacy/` (byte-identical,
      verified by diff), plus `legacy/README.md`. Only edit vs the freeze:
      `legacy/index.js` require paths flattened (`./lib/x` → `./x`) since the
      copy is flat. Full mocha suite redirected at `legacy/`:
      **144/144 passing**, so the freeze is faithful.
- [x] Gitignored `dist/`, removed checked-in bundles.
- [x] Baseline `npm audit` snapshot at `docs/audit/npm-audit-4.0.0-baseline.json`:
      **31 vulnerabilities (7 critical, 6 high, 9 moderate, 9 low), 653 deps.**
- [x] Branch `modernize` created (Phase 0 work committed here).

**Exit:** met. Legacy oracle confirmed runnable on the modern toolchain.

### Phase 1 — Harness & CI (½ day) — **DONE 2026-10-08**

- [x] Toolchain: vitest 5.0.3, typescript 7.0.2, tsdown 0.23.0 (devDeps,
      exact-pinned via new `.npmrc save-exact=true`), `@types/node`.
- [x] Ported the 4 mocha suites to `test/unit/*.test.ts` (vitest, assertions
      1:1, bluebird-promisify replaced by local `promisify1/2`, `new Buffer`
      → `Buffer.from`). Target selector `test/unit/target.ts`
      (`LWT_TARGET=legacy|src`) — **144/144 pass against `legacy/`**, proving
      the port faithful. `tsc --noEmit` clean.
- [x] `package.json` scripts: `build` (tsdown), `typecheck`, `test`
      (vitest unit), `test:legacy-harness` (original mocha, regression floor),
      `coverage`, `gen:goldens`. browserify/prepublish scripts removed.
- [x] GitHub Actions: `.github/workflows/ci.yml`, Node 18/20/22/24 matrix —
      install (ignore-scripts), typecheck, vitest unit, mocha regression.
      Anvil e2e job lands with Phase 4.
- [x] npm audit snapshot (done in Phase 0, `docs/audit/`).

**Exit:** met — new harness green locally on old code; CI file committed
(verified on push).

### Phase 2 — TS + tsdown scaffold, zero dependency swaps (1 day) — **DONE 2026-10-08**

- [x] `src/*.ts` straight port of `lib/*.js` (same legacy deps; minimal
      ambient shims in `src/legacy-deps.d.ts`, typed blobs
      `EncryptedStringBlob`/`EncryptedKeyBlob` where free). `KeyStore` is now
      a class (prototype semantics preserved, incl. instance-overwritable
      `passwordProvider`). Behavior-verified 1:1.
- [x] tsdown dual build: `dist/index.js` (ESM) + `dist/index.cjs` +
      `index.d.ts`/`index.d.cts`; `outputOptions.exports='named'` hoists
      default-export props so `require('eth-lightwallet').keystore` works.
- [x] package.json: `"type":"module"`, exports map with **per-condition
      types** (`import`→index.d.ts, `require`→index.d.cts — a single
      top-level `types` breaks CJS consumers under node16, found by smoke),
      `files:["dist"]`, version bumped to `5.0.0-alpha.0`.
- [x] `LWT_TARGET` default flipped to `src`; **144/144 unit + 7/7 golden
      green against src**. Original mocha harness kept green via
      `test/package.json`+`lib/package.json` `{"type":"commonjs"}` markers.
- [x] `test/golden/vault-4.0.0.test.ts` — pins scrypt key, vault round-trip,
      addresses+privkeys, 3 signed legacy txs, v1/v2 upgrade outputs.
- [x] `scripts/smoke-pack.cjs` — packs the tarball and verifies CJS require,
      ESM named+default, functional golden pin, and type resolution under
      `node16`+`bundler` for both `.mts` and `.cts` consumers. Wired as
      `npm run smoke` + CI step.

**Exit:** met — dual ESM/CJS package building from TS, behavior identical
(still on legacy deps), golden suite green, packed artifact smoke-tested.

**Notable gotchas hit (recorded for Phase 3+):**
- `verbatimModuleSyntax` silently erases `import * as X` namespaces used only
  in value-via-property positions → use named imports in src (fixed).
- Node CJS-named-export detection misses `elliptic`'s `ec` → default import +
  property access in ESM source.
- Node ESM resolves `web3/lib/solidity/coder` only with the explicit `.js`.
- `"type":"module"` flips `test/*.js`/`lib/*.js` to ESM → per-dir
  `{"type":"commonjs"}` markers keep the legacy mocha harness alive.

### Phase 3 — Dependency swap, module by module (2–3 days)

Order chosen so each step is independently verifiable:

- [ ] **3a. `encryption.ts`:** Buffer → Uint8Array; keep tweetnacl. Comparison
      cross-decrypt tests green.
- [ ] **3b. `txutils.ts`:** drop `web3`, `ethereumjs-tx`, `ethereumjs-util`,
      `rlp`, `crypto-js` → viem + `@ethereumjs/tx` + `@ethereumjs/rlp` +
      `@noble/hashes`. Golden `txutils.json` + comparison green.
- [ ] **3c. `signing.ts`:** `@noble/curves` for ecsign/ecrecover; legacy tx
      sign via `@ethereumjs/tx`. Golden signing vectors + comparison green.
      **Watch:** v-value semantics (recid+27, no chainId) must match
      fixtures exactly.
- [ ] **3d. `keystore.ts`:** bitcore → viem/HDKey; scrypt-async → scrypt-js;
      elliptic → noble; crypto-js keccak → noble. Golden `addrprivkey100` +
      keystore fixtures + comparison green. RNG decision (§4.3) implemented.
- [ ] **3e. `upgrade.ts`:** v1 CryptoJS PBKDF2/AES path — reimplement with
      `node:crypto` or keep `crypto-js@^4` (decide by diff size; EVP_BytesToKey
      reimplementation is ~20 lines but security-sensitive — keeping
      `crypto-js` for this one legacy path is acceptable). v1/v2 fixture
      upgrade tests + comparison green.
- [ ] Remove all dropped deps from `dependencies`; `npm audit` clean or
      documented.

**Exit:** `legacy/` deps remain only as devDependencies for comparison tests;
runtime tree is the modern set; every suite green on all CI Node versions.

### Phase 3 results (DONE 2026-10-08)

All five module swaps landed, each golden+comparison verified:
- **3a encryption:** Buffer → @noble/hashes hex; tweetnacl kept.
- **3b txutils:** web3/ethereumjs-tx@1/ethereumjs-util@6/rlp/crypto-js dropped →
  @ethereumjs/tx@10 + @ethereumjs/rlp + noble keccak + viem ABI. **Key pin:**
  unsigned legacy txs serialize v=0x1c, r/s empty (@ethereumjs/tx@10 defaults
  differ; createTx overrides).
- **3c signing:** signTx via @ethereumjs/tx@10 (byte-exact w/ rawSignedTx
  goldens, chainId-0 common). signMsg/concatSig/recoverAddress via **viem** —
  reproduces the legacy message-sig bytes EXACTLY (hardcoded expectedConcatSig
  golden passes UNCHANGED; no behavioral delta needed). Found: @noble/curves@2.4.0
  standalone has a lowS recovery-bit inconsistency (sig verifies, recovers wrong
  addr); viem's pinned noble path is correct. signMsg/recoverAddress now async.
  Gotcha: @ethereumjs/util@10 bytesToHex is 0x-prefixed, noble's isn't —
  standardized on noble.
- **3d keystore:** bitcore-lib/bitcore-mnemonic/elliptic/crypto-js/scrypt-async
  dropped → @scure/bip39+bip32 (xpriv format preserved via privateExtendedKey),
  noble scrypt (logN=14/r=8/p=1/dkLen=32, byte-exact), noble keccak/sha256,
  noble secp256k1. RNG → CSPRNG (plan §4.3). addrprivkey100 + KDF goldens pass.
- **3e upgrade:** v1 KDF/hash → noble (PBKDF2-HMAC-SHA1 150it byte-exact;
  keyHash = keccak_512 of dkHex). crypto-js kept @^4 for v1 AES-CBC only —
  crypto-js@4 changed PBKDF2 WordArray-salt handling, so noble does the KDF
  (resolves §3e open question: hybrid, noble KDF + crypto-js AES).

**Cleanup:** legacy deps → devDependencies (oracle only); dropped
micro-eth-signer + @noble/ciphers (unused); deleted src/legacy-deps.d.ts (real
types). **Runtime deps: 12, npm audit --omit=dev: 0 vulns** (baseline 31).

**Comparison suite** (`test/comparison/legacy-vs-src.test.ts`, 8 tests):
legacy/ vs src/ equivalence live. **Oracle limitation documented:** legacy
v1-upgrade breaks under crypto-js@4 (PBKDF2 drift) — env artifact, not a src
regression; src v1-upgrade verified byte-exact vs fixtures.

**160/160 vitest (unit+golden+comparison), 144/144→143+1-env-fail legacy mocha,
SMOKE PASS.**

### Phase 4 — Anvil e2e (1 day) — **DONE 2026-10-08**

- [x] `@viem/anvil` helper (`test/e2e/anvil-setup.ts`): explicit distinct port
      (port-0 unsupported), loopback only, RPC-readiness wait. Hard fail if the
      anvil binary is absent (per §3.2 — never silent skip).
- [x] Contract fixture: `test/e2e/contracts/SimpleStorage.{sol,json}`
      (set/get, compiled forge 1.8.3 / solc 0.8.30, provenance recorded).
- [x] 5 e2e tests, all green on Anvil:
      1. legacy value transfer (fund→valueTx→signTx→mine; balance + gas-cost delta exact)
      2. contract deploy — **createdContractAddress == receipt.contractAddress**
      3. contract call — functionTx `set(42)`, eth_call `get()` == 42
      4. keystore.signTransaction full flow (web3-style `gas` param, injected passwordProvider)
      5. signMsgHash + concatSig → recovers to signer (viem + lib agree)
- [x] Recipients use 0x1000…-style addresses (t-9be9's PrecompileOOG tip —
      0x01–0x09 OOG at 21000 gas).
- [x] CI: `foundry-rs/foundry-toolchain@v1` step + `npm run test:e2e`.
      `test:e2e` and `test:all` scripts added.

**Exit:** met — raw txs produced/signed by the modernized stack mine on Anvil;
contract-address prediction matches on-chain reality; signature recovery
round-trips. **Full suite: 165/165 (9 files) + SMOKE PASS.**

Note: legacy mocha harness is 143/144 — the 1 failure is the documented
crypto-js@4 PBKDF2 env-drift in the frozen oracle's v1-upgrade path (NOT a src
regression; src v1-upgrade is verified byte-exact by golden+unit tests).

### Phase 5 — Hardening & release (1 day) — **MOSTLY DONE 2026-10-08**

- [x] Public TS types: `src/types.ts` (`CreateVaultOptions`,
      `SerializedKeystore`, `TxParams`, `AsymEncryptedMessage`,
      `MultiEncryptedMessage`, `Callback`) exported from `index.ts`;
      `createVault`/`signTransaction` typed. Verified in `dist/index.d.ts`.
- [x] README: "Migrating to 5.0.0" section (ESM/CJS imports, async
      signMsg/recoverAddress, removed browser bundle, Node>=18) + preserved-
      behavior list; stale browserify-bundle Get Started block updated;
      security section notes the 31→0 audit delta.
- [x] RELEASE-NOTES 5.0.0: breaking changes, verified-preservation list, dep
      swap summary, audit delta, build notes, comparison-oracle status.
- [x] `example/`: marked outdated (references removed bundle + web3@0.20);
      `example/README.md` points to README migration + test suites. Full
      example rewrite deferred (out of scope, non-blocking).
- [x] **Bonus:** restored the full comparison oracle — vendored crypto-js@3.1.8
      for `legacy/` (gitignored), so the frozen 4.0.0 oracle is 144/144 green
      again (incl. v1-upgrade). Mocha harness redirected lib/ → legacy/.
- [x] **Publish name decided:** `@gkgo/eth-lightwallet` (scoped, public).
      package.json updated + `publishConfig.access=public`; smoke test packs
      and verifies the scoped name. Publishing itself needs `npm login` as the
      scope owner — user's step.
- [ ] Decide fate of `legacy/` (recommend: keep through 5.x).
- [x] `npm pack` + smoke tests (done each phase via `npm run smoke`).

**Status:** library is functionally complete + consumer-validated (t-9be9's
golden gate 20/20 green against a1d16c9). Awaiting publish decision.

## 7. Risks & mitigations

| Risk | Likelihood | Mitigation |
|---|---|---|
| crypto-js SHA3 vs real keccak divergence on some input shape | Low–Med | Golden fixtures + comparison tests on *every* callsite before removing crypto-js |
| `@ethereumjs/tx` v5 defaults (chainId/EIP-155) change v values | Med | Explicit `common`/chain config; golden `rawSignedTx` pins it |
| viem HD derivation ≠ bitcore for edge paths (e.g. non-hardened child of hardened root) | Low | 3-path × 10-address comparison + 100-vector golden |
| Legacy deps won't install/run on CI Node → comparison suite dead | Med | Phase 0 decides; contingency is documented skip, not silent drop (§5.2) |
| scrypt-js output mismatch | Very low | Byte-equal KDF comparison test first |
| tweetnacl types/ESM interop quirks under `require()` | Low | CJS smoke test in CI |
| Anvil unavailable in some env | Low | e2e project gated: `test:e2e` separate from default `test` |

## 8. Open questions

1. Keep `crypto-js` for the v1-upgrade path only, or reimplement
   EVP_BytesToKey with `node:crypto`? (Phase 3e)
2. CSPRNG switch confirmed for `generateSalt`/nonces? (§4.3 — default yes)
3. Ship subpath exports (`eth-lightwallet/keystore`, …) in 5.0.0 or defer?
4. ~~Publish name/scope~~ → **DECIDED: `@gkgo/eth-lightwallet`** (scoped,
   public access). Name is available on npm (404/unpublished); publishing
   requires owning the `@gkgo` npm scope (user's step).
5. Keep `legacy/` in-repo for how long (5.x cycle, or drop at 5.0.0)?

## 11. Progress log

| Date | Step | Result |
| --- | --- | --- |
| 2026-10-08 | Tag `pre-modernization` @ d21df74 | done |
| 2026-10-08 | Baseline mocha suite on Node 26.10.0 | **144/144 pass** (after removing dead `hooked-web3-provider` git devDep) |
| 2026-10-08 | `legacy/` freeze + redirected suite | 144/144 pass against `legacy/` |
| 2026-10-08 | `dist/` gitignored + removed from git | done |
| 2026-10-08 | npm audit baseline | 31 vulns (7 crit / 6 high) — `docs/audit/npm-audit-4.0.0-baseline.json` |
| 2026-10-08 | Contract exchange with t-9be9 (eth-hot-wallet) | 4 corrections accepted; strict hdPathString confirmed; goldens to be shared bidirectionally |
| 2026-10-08 | Goldens generated from legacy/ (vault, kdf pin, 5 addrs, 3 signed legacy txs, v1/v2 upgrades) | `test/golden/generated/vault-4.0.0.json`, cross-checked vs existing fixtures |
| 2026-10-08 | Phase 1: vitest 5 + TS 7 + tsdown 0.23 harness; 4 suites ported | 144/144 vs `legacy/`; tsc clean; CI matrix Node 18–24 |
| 2026-10-08 | Phase 2: src/ TS straight-port (legacy deps), tsdown dual build, exports map w/ per-condition types, golden suite, smoke-pack | 151/151 (unit+golden) vs src; CJS+ESM+types verified on packed tarball; v5.0.0-alpha.0 |
| 2026-10-08 | Phase 3a–e: all dep swaps (encryption/txutils/signing/keystore/upgrade), comparison suite, dep cleanup | **160/160** (unit+golden+comparison); runtime audit 0 vulns (was 31); signMsg byte-exact via viem; a1d16c9 |
| 2026-10-08 | Phase 4: Anvil e2e (transfer, deploy+addr-prediction, call, signTransaction flow, msg recovery) | **165/165** all projects; deploy addr == receipt; foundry-toolchain CI; `prepare` script added |

## 10. Consumer contract — `eth-hot-wallet` (link session t-9be9, 2026-10-08)

`eth-hot-wallet` will consume this repo as a **commit-pinned git dependency**
aliased `eth-lightwallet-next` (keeping npm `eth-lightwallet@3.0.1` until a
golden+Anvil gate passes). Their plan:
`~/Code/gorks/eth-hot-wallet/docs/plans/2026-02-11-modernization-plan.md`
(§5.1 is the contract on us).

**Accepted:**
- Public API preserved for all modules; ESM-first with named+default exports
  mapping to the 4.0.0 `module.exports` shape.
- tsdown → `dist/index.js` (ESM) + `dist/index.cjs` (require-able, no
  top-level await) + `dist/index.d.ts`; `"type": "module"` + exports map
  exactly as they specified.
- Browser-safe default path (noble/scure/tweetnacl are isomorphic).
- Goldens shared bidirectionally: their `test/goldens/**` gets copied into
  this repo (`test/golden-external/` + provenance note) once generated; our
  goldens are sent their way.
- Work lands on branch `modernize`, shas provided for pinning.

**Corrections sent to t-9be9 (factual errors in their plan):**
1. No AES-128-CTR in lightwallet 4.0.0 vaults — v3 encryption is pure
   tweetnacl secretbox/box; crypto-js only exists in the v1 upgrade path
   (PBKDF2-HMAC-SHA1 150 iters + AES-256-CBC EVP_BytesToKey). tweetnacl is
   kept. Their "@noble/ciphers AES-CTR" requirement has no target.
2. scrypt params are **logN=14 (n=16384), r=8, p=1, dklen=32** — their plan
   says n=1024, which would produce incompatible vaults. Confirmed in source
   and pinned by `test/fixtures/keystore.json` pwDerivedKey vectors.
3. Default signing is **pre-EIP-155** (v = recid + 27, no chainId);
   EIP-155 only when caller passes chainId (ethereumjs-tx@1 semantics).
4. 4.0.0 makes `hdPathString` REQUIRED in createVault (3.0.1 defaulted it to
   `m/0'/0'/0'`). Keeping strict 4.0.0 behavior unless they object (question
   pending, non-blocking).

**Dep-map delta vs §4.2:** HD derivation may use `@scure/bip39` +
`@scure/bip32` directly (their preference, audited packages) instead of going
through viem — final pick in Phase 3d, goldens decide either way.

## 9. Effort estimate

≈ 5–7 focused days total, with Phases 3b–3d carrying most of the risk.
