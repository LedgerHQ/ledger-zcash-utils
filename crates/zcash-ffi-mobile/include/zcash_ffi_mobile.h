/* Zcash mobile FFI — C interface for the JSI/C++ shim.
 *
 * Hand-written for the PoC surface (two functions). Once the surface grows,
 * generate this with cbindgen instead of maintaining it by hand.
 *
 * Contract: every call returns a status. On ZCASH_OK, *out is the result; on any
 * negative status except ZCASH_ERR_NULL_ARG, *out is an error message. Either
 * way the caller owns *out and must release it with zcash_string_free().
 * On ZCASH_ERR_NULL_ARG nothing is written to *out.
 */
#ifndef ZCASH_FFI_MOBILE_H
#define ZCASH_FFI_MOBILE_H

#ifdef __cplusplus
extern "C" {
#endif

#define ZCASH_OK                 0
#define ZCASH_ERR_NULL_ARG      -1
#define ZCASH_ERR_INVALID_UTF8  -2
#define ZCASH_ERR_CRYPTO        -3
#define ZCASH_ERR_PANIC         -4
#define ZCASH_ERR_INTERIOR_NUL  -5

/* Derive the Orchard-only unified address the Ledger device displays.
 * NOT the multi-receiver unified address. */
int zcash_orchard_address_from_ufvk(const char *ufvk, char **out);

/* Diagnostic: measure whether Rayon gives real parallelism on this device.
 * Not part of the wallet surface. On ZCASH_OK, *out is JSON:
 * {"threads":N,"iterations":N,"serial_ms":N,"parallel_ms":N,"speedup":N.NN} */
int zcash_ffi_thread_probe(const char *ufvk, unsigned int iterations, char **out);

/* Scan start_height..=end_height for notes belonging to ufvk, and return the
 * serialised SyncResult as JSON.
 *
 * BLOCKING: occupies the calling thread for the whole range, with no progress
 * and no cancellation, and discards everything if the last block fails. Call
 * it off the UI thread, and keep the range small. Only present when the engine
 * was built with the `sync` feature. */
int zcash_sync_range(const char *ufvk, const char *grpc_url, const char *network,
                     unsigned int start_height, unsigned int end_height,
                     const char *known_nullifiers, char **out);

/* Current chain tip height, written to *out as a decimal string. The chunked
 * scan loop needs it to know where to stop. Only with the `sync` feature. */
int zcash_chain_tip(const char *grpc_url, char **out);

/* Release a string returned through an out parameter. NULL is a no-op. */
void zcash_string_free(char *s);

/* OUI TEST ENTRY POINT */
#ifdef __cplusplus
}
#endif

#endif /* ZCASH_FFI_MOBILE_H */
