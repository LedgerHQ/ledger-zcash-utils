# Agent instructions

Rust workspace exposing Zcash shielded scanning and PCZT crafting to Ledger Live, as a Node.js native addon and a developer CLI.

Three files already answer the usual questions: [`README.md`](README.md) is the published JS/TS API, [`CONTRIBUTING.md`](CONTRIBUTING.md) is build, test, CLI usage, the contribution conventions and release, [`docs/`](docs/) is architecture and per-area detail. This file adds only the invariants those leave implicit, and points at wherever each one is enforced rather than restating a value that will move.

## Dependency pins are load-bearing — never run a broad `cargo update`

Versions live only in `[workspace.dependencies]` at the workspace root; member crates inherit them and add features on top. Never introduce a second version of a crate pinned there.

Several entries are pinned exactly, and each states its reason as an inline comment. Read that comment before touching the pin, and rewrite it when the pin moves — a stale justification is worse than none. The failure modes those comments guard against are worth knowing, because none of them surfaces as a build error:

- a crate that defines the byte stream the firmware parses, so a bump silently changes a wire format that another repo must agree with;
- release candidates awaiting a network upgrade, to be swapped for the stable release at the moment the comment names;
- crates that must match the version a dependency already links, or the same types exist twice under identical names and values cannot cross between them;
- crates whose maintenance line sorts below a parallel feature line, so a broad update drifts off the intended line unprompted.

## Generated files that are committed anyway

The napi-rs outputs at the repository root — the JS loader and its TypeScript declarations — are tracked, because they ship in the published package (see the `files` field in `package.json`). Never hand-edit them: the next build overwrites the edit, and the published types then disagree with the addon.

To change the TypeScript surface, edit the signatures and doc comments in the napi crate and rebuild. Those Rust doc comments become the published declarations verbatim, which makes them user-facing documentation rather than internal notes — a stale one ships to consumers.

## No spending key material in this layer

This workspace reads a Unified Full Viewing Key and an account-level transparent pubkey; every signature comes from the Ledger device. Never derive spending keys from a seed here, and never add an API that would need them.

Key derivation does exist, for development, in the core crypto crate and behind a CLI subcommand, and is deliberately absent from the NAPI surface. Keep it that way: a wallet takes its keys from the device.

## One crate carries a coverage floor

`scripts/coverage.sh` enforces a minimum line coverage and names both the crate it applies to and the threshold; it is the only crate under that requirement. Tests are inline `#[cfg(test)]` modules beside the code, plus integration tests for the CLI.

Before trusting a bare `cargo check` or `cargo test`, read `default-members` in the root `Cargo.toml` — it narrows both to a subset of the workspace. Pass `--workspace` to cover everything.

## New exports follow the CLI-exposure rule

`docs/architecture.md` fixes the sequence, from the core crate through the NAPI wrapper to a CLI subcommand, and allows the CLI step to be skipped for a device-coupled feature whose standalone invocation could only produce an unsignable artifact. Skipping is allowed; skipping silently is not — record the reason inline in that document, alongside the exceptions already listed there.

## Branch, commit and PR conventions are written down — read them, don't infer them

[`CONTRIBUTING.md`](CONTRIBUTING.md#contributing-workflow) holds the branch naming, the commit grammar and what a pull request needs. It is not repeated here.

Two properties of it change how an agent should behave. Nothing in CI validates a commit subject or a PR title — there is no commitlint, no gitmoji check, no reviewing bot — so a malformed message is caught by a human or not at all, and the convention differs from one Ledger repo to the next: read this repo's own history rather than carrying over a house style from another. And signed commits are required by a branch ruleset on `main`, so an unsigned commit simply cannot merge — when signing fails, fix the signing setup and never propose bypassing it.

## Every user-visible change needs a changeset

Generate one with `pnpm changeset` and commit it with the change. The version bump and the changelog entry are produced from it by `changeset version` — never hand-write either. Commit the changeset before running that command: it reads the commit that introduced the file to prefix the changelog entry, and gets nothing from an uncommitted one.

## Value encoding is deliberate, not accidental

The same quantity is spelled two ways on purpose, and "normalizing" it breaks callers: zatoshi amounts are represented differently on the scanning path and on the crafting/PCZT path, and txid byte order differs from field to field. The README's "Value encoding" section is the reference — consult it rather than inferring the convention from a single call site.

## Markdown is formatted

Run the repository's format script after editing any `.md`. `.prettierrc` holds the style and `.prettierignore` the exclusions, which cover the generated and released files. Do not hard-wrap prose against the configured setting.

Unlike the commit convention above, this one is checked: a CI job runs the check script on every branch and pull request, so an unformatted file fails the build rather than reaching a reviewer.
