/* Zcash mobile FFI: C interface of the read path (chain queries, block scanning,
 * transaction details).
 *
 * Hand-written. The Rust crate keeps `READ_PATH_EXPORTS` in sync with the
 * prototypes below, and a test fails when a symbol listed there is missing here.
 *
 * Contract: every call returns a status. On ZCASH_OK, *out is the result; on any
 * negative status except ZCASH_ERR_NULL_ARG, *out is an error message. Either
 * way the caller owns *out and must release it with zcash_string_free().
 * On ZCASH_ERR_NULL_ARG nothing is written to *out.
 *
 * Structured arguments and results are JSON strings. Field names and optionality
 * are those of the Node binding (index.d.ts): a TypeScript `?:` field is omitted
 * from the JSON when it has no value, never written as null.
 *
 * Blocking: calls marked BLOCKING occupy the calling thread until they finish.
 * Call them off the UI thread. Calls run on one shared runtime, so several
 * threads may call at once and a running scan never blocks another call.
 */
#ifndef ZCASH_FFI_MOBILE_H
#define ZCASH_FFI_MOBILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCASH_OK                 0
#define ZCASH_ERR_NULL_ARG      -1
#define ZCASH_ERR_INVALID_UTF8  -2
/* The engine or the network failed. *out carries the engine's own message. */
#define ZCASH_ERR_ENGINE        -3
#define ZCASH_ERR_PANIC         -4
#define ZCASH_ERR_INTERIOR_NUL  -5
/* An argument was not valid JSON for its type, or a handle was already finished. */
#define ZCASH_ERR_INVALID_ARG   -6
/* The scan was cancelled before it completed. */
#define ZCASH_ERR_CANCELLED     -7

/* Derive the Orchard-only unified address the Ledger device displays.
 * NOT the multi-receiver unified address. Non-blocking (CPU only). */
int zcash_orchard_address_from_ufvk(const char *ufvk, char **out);

/* Current chain tip height. BLOCKING. *out is a JSON number. */
int zcash_get_chain_tip(const char *grpc_url, char **out);

/* Height of the latest block whose timestamp is at or before `timestamp`
 * (Unix seconds). BLOCKING. *out is a JSON number. */
int zcash_find_block_height(const char *grpc_url, uint32_t timestamp, char **out);

/* Read the fee and the shielded payees of transactions fetched by txid.
 * BLOCKING.
 *
 * requests_json: a JSON array of TransactionDetailsRequest.
 * network:       "mainnet" or "testnet", or NULL for the default.
 * ufvk:          the account's viewing key, or NULL to skip the payees.
 * *out:          a JSON array of TransactionDetailsResult, in request order. */
int zcash_transaction_details(const char *grpc_url, const char *requests_json,
                              const char *network, const char *ufvk, char **out);

/* A scan in progress. Opaque. */
typedef struct ZcashSyncHandle ZcashSyncHandle;

/* Start scanning one chunk of blocks in the background. Non-blocking.
 *
 * params_json: a SyncParams object.
 * On ZCASH_OK, *out_handle is a new handle and *out_error is untouched.
 * On any other status except ZCASH_ERR_NULL_ARG, *out_error is a message the
 * caller frees with zcash_string_free(), and *out_handle is NULL. */
int zcash_sync_start(const char *params_json, ZcashSyncHandle **out_handle,
                     char **out_error);

/* Ask the scan to stop. Non-blocking, idempotent, safe from any thread.
 * NULL is a no-op. The result is collected with zcash_sync_finish(), which then
 * returns ZCASH_ERR_CANCELLED. */
void zcash_sync_cancel(ZcashSyncHandle *handle);

/* Wait for the scan to end or to be cancelled. BLOCKING.
 *
 * *out on ZCASH_OK is {"transactions":[ShieldedTransaction...],"stats":SyncStats}.
 * A cancelled scan returns ZCASH_ERR_CANCELLED and no partial result.
 * Call it once per handle: a second call returns ZCASH_ERR_INVALID_ARG. */
int zcash_sync_finish(ZcashSyncHandle *handle, char **out);

/* Abort the scan if it is still running, then release the handle. NULL is a
 * no-op. Do not call it while zcash_sync_finish() runs on the same handle. */
void zcash_sync_free(ZcashSyncHandle *handle);

/* Release a string returned through an out parameter. NULL is a no-op. */
void zcash_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ZCASH_FFI_MOBILE_H */
