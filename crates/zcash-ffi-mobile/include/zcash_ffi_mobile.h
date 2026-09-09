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

/* Release a string returned through an out parameter. NULL is a no-op. */
void zcash_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ZCASH_FFI_MOBILE_H */
