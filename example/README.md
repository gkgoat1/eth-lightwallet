# Examples — ⚠️ outdated (pre-5.0.0)

These examples target **eth-lightwallet 4.0.0**: they load the removed
browserify bundle (`dist/lightwallet.min.js`) and `web3@0.20`, which are no
longer part of the package. They are kept for reference only and will not run
as-is against 5.0.0.

For 5.0.0 usage see the [README migration section](../README.md#migrating-to-500)
and the passing test suites:

- `test/unit/` — keystore, signing, txutils, encryption (callback API)
- `test/e2e/` — end-to-end against a local Anvil chain (value transfer,
  contract deploy + call, `signTransaction` flow, message recovery)

A refreshed `example_usage` for the modernized API is tracked as a follow-up.
