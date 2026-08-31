---
"@ledgerhq/zcash-utils": minor
---

Relicense to `Apache-2.0`, aligning with the Ledger device stack this package belongs to: the Device Management Kit, the Zcash device signer kit and the Zcash device app are all `Apache-2.0`. Nothing in the repository stated a license authoritatively before — `package.json` declared `MIT`, the four Rust crates declared `MIT OR Apache-2.0`, and no LICENSE file existed at all.

The declaration now lives in `[workspace.package]` of the root `Cargo.toml`, inherited by every crate, and is mirrored in `package.json`. The full Apache 2.0 text ships as `LICENSE.md`, which npm includes in the tarball even though the `files` field does not name it, so the published package now carries its own license text.
