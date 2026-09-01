---
"@ledgerhq/zcash-utils": patch
---

Document what every export throws. The published declarations described no failure at all, so the only ways to learn what rejects a promise were to read the Rust or to hit each case in production. Each export now carries an `# Errors` section, which napi-rs propagates into `index.d.ts`, and the README states what holds across all of them.

Two behaviours are documented well beyond the rest, because a caller who does not know them writes code that is wrong while appearing to work. A scan reports its failure only through `stats()`: `startSync` validates nothing and `next()` cannot fail, so `null` means either "range fully scanned" or "the scan died part-way" and nothing distinguishes them — a caller that persists notes without calling `stats()` treats a truncated scan as a complete one. And a failed broadcast does not mean nothing was sent: `SendTransaction rejected (code N)` is a node refusing a transaction it saw, but `SendTransaction failed` is a transport error that may have been accepted before the connection broke, so the txid — known before broadcasting, since it is derived from the bytes — should be looked up rather than assumed absent.

The sections give categories and retry safety rather than transcribing message strings, because every failure crosses into JavaScript as a plain `Error` carrying only a message: no `code`, no subclass, nothing to switch on. Text matching is therefore a caller's only means of telling failures apart today, and the README says plainly that the categories are stable while the wording is not.
