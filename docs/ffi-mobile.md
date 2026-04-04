# UniFFI Mobile Binding

## Interface

The mobile interface is defined in `crates/zcash-ffi-mobile/src/zcash.udl`.
This UDL file is the single source of truth for the Android and iOS APIs.

## Building

```bash
./scripts/build-android.sh   # produces JNI .so files + Kotlin bindings
./scripts/build-ios.sh       # produces XCFramework + Swift bindings
```

## Generating bindings manually

```bash
# Kotlin (Android)
cargo run -p zcash-ffi-mobile --bin uniffi-bindgen -- generate \
    crates/zcash-ffi-mobile/src/zcash.udl \
    --language kotlin \
    --out-dir dist/android/kotlin/

# Swift (iOS)
cargo run -p zcash-ffi-mobile --bin uniffi-bindgen -- generate \
    crates/zcash-ffi-mobile/src/zcash.udl \
    --language swift \
    --out-dir dist/ios/swift/
```

Or via npm scripts:

```bash
pnpm bindgen:kotlin
pnpm bindgen:swift
```

## Android integration

1. Copy `dist/android/jniLibs/` into `app/src/main/`.
2. Copy the Kotlin bindings from `dist/android/kotlin/` into your source tree.
3. Add the generated package to your `build.gradle`:
   ```groovy
   android {
       sourceSets.main.jniLibs.srcDirs = ['src/main/jniLibs']
   }
   ```

### Kotlin usage

> **Threading:** gRPC calls block the calling thread. Always call `syncShielded`
> and `getChainTip` from a background thread (e.g. `Dispatchers.IO`).

```kotlin
import app.zcash.uniffi.*

// Key derivation
val keys = deriveZcashKeys(
    mnemonic = "abandon abandon ... about",
    account = 0u,
    network = "mainnet"
)
println(keys.ufvk)

// Full transaction decryption
val result = fullDecryptTransaction(
    txHex = "04000080...",
    ufvk = keys.ufvk,
    height = 2300000u,
    network = "mainnet"
)
result.saplingOutputs.forEach { println("${it.amount} zatoshis: ${it.memo}") }

// Block range sync (run on Dispatchers.IO)
val syncResult = withContext(Dispatchers.IO) {
    syncShielded(SyncParams(
        grpcUrl = "https://testnet.zec.rocks:443",
        ufvk = keys.ufvk,
        startHeight = 280000u,
        endHeight = 290000u,
        network = "testnet"
    ))
}
syncResult.transactions.forEach { tx ->
    tx.notes.forEach { println("${it.value} zats: ${it.memo}") }
}

// Chain tip query (run on Dispatchers.IO)
val tip = withContext(Dispatchers.IO) {
    getChainTip("https://testnet.zec.rocks:443")
}
println("Current tip: $tip")
```

## iOS integration

1. Drag `dist/ios/ZcashFFI.xcframework` into Xcode → Frameworks, Libraries,
   and Embedded Content. Select "Embed & Sign".
2. Copy `dist/ios/swift/zcash.swift` into your Swift target.

### Swift usage

> **Threading:** gRPC calls block the calling thread. Always call `syncShielded`
> and `getChainTip` from a background task (e.g. `Task.detached` or a
> `DispatchQueue.global()` block).

```swift
import ZcashFFI

// Key derivation
let keys = try deriveZcashKeys(
    mnemonic: "abandon abandon ... about",
    account: 0,
    network: "mainnet"
)
print(keys.ufvk)

// Full transaction decryption
let result = try fullDecryptTransaction(
    txHex: "04000080...",
    ufvk: keys.ufvk,
    height: 2300000,
    network: "mainnet"
)
result.saplingOutputs.forEach { print("\($0.amount) zats: \($0.memo)") }

// Block range sync (call from background thread)
Task.detached {
    let syncResult = try syncShielded(params: SyncParams(
        grpcUrl: "https://testnet.zec.rocks:443",
        ufvk: keys.ufvk,
        startHeight: 280000,
        endHeight: 290000,
        network: "testnet"
    ))
    for tx in syncResult.transactions {
        for note in tx.notes {
            print("\(note.value) zats: \(note.memo ?? "")")
        }
    }
}

// Chain tip query (call from background thread)
Task.detached {
    let tip = try getChainTip(grpcUrl: "https://testnet.zec.rocks:443")
    print("Current tip: \(tip)")
}
```

## UDL type mapping

| Rust type | Kotlin type | Swift type |
|-----------|-------------|------------|
| `String` | `String` | `String` |
| `u32` | `UInt` | `UInt32` |
| `u64` | `ULong` | `UInt64` |
| `boolean` | `Boolean` | `Bool` |
| `sequence<T>` | `List<T>` | `[T]` |
| `T?` (optional) | `T?` | `T?` |
| `bytes` | `ByteArray` | `Data` |
| dictionary | data class | struct |
| interface (opaque) | class (wrapped) | class (wrapped) |

## Adding a new function

1. Add the function signature to `crates/zcash-ffi-mobile/src/zcash.udl`.
2. Add the corresponding Rust implementation in
   `crates/zcash-ffi-mobile/src/lib.rs`, delegating to `zcash-crypto` or
   `zcash-grpc`. For async operations, create a `tokio::runtime::Runtime` and
   call `rt.block_on(...)` — UniFFI functions are synchronous; the platform
   schedules them on background threads.
3. Rebuild and regenerate bindings:
   ```bash
   ./scripts/build-android.sh
   ./scripts/build-ios.sh
   ```
