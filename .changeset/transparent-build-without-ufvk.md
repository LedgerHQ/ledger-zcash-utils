---
"@ledgerhq/zcash-utils": minor
---

Build a transparent send without a UFVK. `buildTransaction` required a UFVK for
every flow, including a fully transparent one — which carries no shielded bundle
and reads no shielded key material. Its only key requirement is the
account-level transparent pubkey at `m/44'/coin'/account'`, used to derive the
internal change address and to verify each input's signing path. A wallet always
holds those bytes (they are the payload of the account xpub) whereas obtaining a
UFVK takes a user confirmation on the device, so the requirement forced a
viewing-key export on anyone spending public funds.

`ufvk` is now optional and a `transparentAccountPubkey` field accepts those 65
bytes (32-byte chain code ‖ 33-byte compressed pubkey) as hex. A transparent
send supplies the pubkey and omits the UFVK; both may be supplied together, in
which case the UFVK's transparent component is authoritative and the standalone
field only has to agree with it — a mismatch means key material from two
different accounts and fails the build rather than picking one. Every flow with
a shielded bundle (an Orchard spend, or a shielded recipient) still requires the
UFVK and now says so explicitly instead of failing deeper on a missing Orchard
component; `buildIronwoodTransaction`, whose bundle is always shielded, is
unchanged.

The two orchestrators now share one transparent-input decoder, so the
fund-safety check that ties each input's `(derivationScope, addressIndex)` to
its pubkey has a single implementation instead of two copies.
