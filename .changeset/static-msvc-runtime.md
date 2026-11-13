---
"@ledgerhq/zcash-utils": patch
---

Link the C runtime statically into the Windows binaries, so the addon loads on a machine without the Visual C++ Redistributable instead of failing with "The specified module could not be found".
