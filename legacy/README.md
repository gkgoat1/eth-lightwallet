# legacy/ — frozen pre-modernization code

**DO NOT EDIT.** This is a verbatim copy of `index.js` + `lib/*.js` from tag
`pre-modernization` (commit `d21df74`, v4.0.0), frozen on 2026-10-08 as the
reference implementation for the comparison test suite
(`test/comparison/`, planned in Phase 3 of
`docs/plans/2026-10-08-modernize-ts-tsdown-esm.md`).

These files run on the legacy dependency set (bitcore-lib 8.1.1,
ethereumjs-tx 1.3.7, web3 0.20.7, crypto-js 3.1.8, scrypt-async 2.0.1,
tweetnacl 1.0.1, elliptic 6.4.1, rlp 2.2.3), which is retained in
`devDependencies` for exactly this purpose.

- `legacy/index.js` re-exports the same shape as the published 4.x package
  root: `{ txutils, encryption, signing, keystore, upgrade }`.
- Internal `require('./x')` paths resolve inside this directory.
- This directory is excluded from the published package (`files: ["dist"]`).

If the legacy dependency set can no longer be installed or executed on the CI
Node version, the comparison suite must be skipped loudly (never silently),
the failure recorded in RELEASE-NOTES, and golden fixtures become the sole
regression floor. See plan §5.2 "Contingency".

Removal: planned for the 5.x cycle, once the modernized stack has shipped and
the comparison suite has served its purpose (plan §6 Phase 5).
