---
"@ledgerhq/zcash-utils": patch
---

Widen the shard-0 scan-width safety limit so that two years of chain growth still pass at NU7's 25-second block spacing, while a scan started from genesis is still refused.
