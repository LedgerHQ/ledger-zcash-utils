---
"@ledgerhq/zcash-utils": minor
---

Add `parsePczt(pcztHex)` — decode canonical PCZT bytes into a structured `PcztTransaction`

- New Rust function `parse_pczt` in `zcash-crypto` that parses the canonical PCZT bytes emitted by `buildTransaction` (`PCZT` magic + u32 LE version + postcard payload) and re-shapes them into a fully structured form: the global header, every transparent input/output, and each Orchard action broken out field-by-field
- Exposed via NAPI as `parsePczt(pcztHex: string): PcztTransaction`, matching the object `@ledgerhq/device-signer-kit-zcash`'s `DmkSignerZcash.signPcztTransaction` consumes (`Uint8Array` byte fields, `bigint` zatoshi values, `signingPath` derivation strings)
- Bridges `buildTransaction` (returns `pcztHex`) to the device signer without a TypeScript postcard parser
- Fails with a clear error when the input is not a valid PCZT or is missing a field the device requires to sign (e.g. Orchard `alpha`/`rcv`, an input's single `bip32_derivation`)
