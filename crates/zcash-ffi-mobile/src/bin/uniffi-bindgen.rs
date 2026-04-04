// Entry point for the uniffi-bindgen binary.
// Generates Kotlin and Swift bindings from the UDL file.
//
// Usage examples:
//   # Generate Kotlin bindings
//   cargo run --bin uniffi-bindgen generate crates/zcash-ffi-mobile/src/zcash.udl \
//       --language kotlin --out-dir dist/android/kotlin/
//
//   # Generate Swift bindings
//   cargo run --bin uniffi-bindgen generate crates/zcash-ffi-mobile/src/zcash.udl \
//       --language swift --out-dir dist/ios/swift/
fn main() {
    uniffi::uniffi_bindgen_main()
}
