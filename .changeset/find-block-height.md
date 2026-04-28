---
"@ledgerhq/zcash-utils": minor
---

Add `findBlockHeight(grpcUrl, timestamp)` — binary search over block timestamps via gRPC

- New Rust function `find_block_height` in `zcash-sync` using interpolation search + streaming `GetBlockRange` for fast convergence (~6 RPCs, under 1.5s on mainnet)
- Exposed via NAPI as `findBlockHeight(grpcUrl: string, timestamp: number): Promise<number>`
- New CLI subcommand `height-at --grpc-url <URL> --date <YYYY-MM-DD|timestamp>`
- Returns the height of the first block whose timestamp is ≥ the target
