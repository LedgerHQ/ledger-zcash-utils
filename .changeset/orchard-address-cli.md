---
"@ledgerhq/zcash-utils": minor
---

Expose the default unified receiving address (ZIP-316, `u1...` / `utest1...`) from key derivation. `DerivedKeys` gains a `unified_address` field, and `ledger-zcash-cli derive` now prints it alongside the UFVK in both `human` and `json` output. Derived purely from the UFVK (watch-only, no spending key involved) and independent of `--no-sapling`, since that flag only controls what's bundled into the encoded UFVK string, not the address's receiver set.
