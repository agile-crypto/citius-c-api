/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_core.h — Abstract Cryptographic API, C binding: core runtime.
 *
 * HAND-WRITTEN. Defines the idioms the rest of the C binding is built from:
 * the context, errors, sessions, and the opaque handles that later headers
 * (agc_key.h, agc_crypto.h, ...) attach accessors to as their own commits
 * land. See RECONCILIATION_PLAN.md §1 (D1-D20) for the rationale behind
 * every convention below.
 *
 * THE CONVENTIONS
 * ----------------
 * 1. Every call returns agc_rc. AGC_OK == 0. Nothing else is a success.
 * 2. Every byte output uses the two-call convention (agc_buf, agc_abi.h).
 *    The library never allocates a buffer the caller frees with free().
 * 3. Every rich message output is an opaque handle with typed accessors,
 *    freed with its own agc_*_free. Deep aggregate structs never cross the
 *    ABI (D6) — that is what keeps the algorithm catalog out of the ABI.
 * 4. Every struct passed by pointer begins with `size_t struct_size`. Use
 *    AGC_INIT() to zero it and set the size.
 * 5. Nothing in this API allocates on the caller's allocator or frees on it.
 *
 * THREADING
 * ---------
 * agc_ctx is thread-safe: any number of threads may issue operations on one
 * context concurrently. agc_session (a streaming operation) is NOT
 * thread-safe and must be confined to one thread at a time, exactly as a
 * PKCS#11 session without CKF_OS_LOCKING_OK. Handles obtained from a context
 * become invalid when that context is closed.
 *
 * FORK
 * ----
 * After fork(2) the child MUST NOT use any handle inherited from the parent.
 * The library installs a pthread_atfork handler that marks every open
 * context POISONED in the child; operations on a poisoned context fail with
 * AGC_ERR_INVALID_HANDLE rather than silently reusing state the parent also
 * holds. Call agc_ctx_reinit_after_fork() in the child to obtain a fresh,
 * usable context built from the same configuration.
 *
 * DEPLOYMENT MODE
 * ----------------
 * This reconciliation implements AGC_MODE_EMBEDDED only: direct calls into
 * the in-process stub backend (src/stub/, wired in from commit 8 onward). No
 * transport exists for AGC_MODE_LOCAL/AGC_MODE_REMOTE in this tree;
 * agc_ctx_open() returns AGC_ERR_NOT_IMPLEMENTED for them. The design is
 * still mode-shaped (D13): a later transport layer plugs in at
 * agc_ctx_open() without changing any call site, which is the entire point
 * of making mode a context property rather than a compile-time choice.
 */

#ifndef AGC_CORE_H
#define AGC_CORE_H

#include "agc_abi.h"
#include "agc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Opaque handles
 *
 * Forward-declared here even though most gain accessors only once their
 * owning commit lands (agc_metadata: commit 6; agc_key_info and the
 * migration/feasibility reports: commit 7; agc_impl_props, agc_template_info,
 * agc_scope_info: commit 11; agc_policy_decision: commit 11) — every service
 * header needs to name these as pointer types before then.
 * -------------------------------------------------------------------------- */

/* The service surface. One context binds a policy engine, a template
 * catalog and a set of provider instances. It is the C analogue of "a
 * connection to the service", except that in AGC_MODE_EMBEDDED there is no
 * connection: calls are direct function calls into the stub backend. */
typedef struct agc_ctx agc_ctx;

/* A stateful multi-part or message-based operation. Replaces the proto's
 * request-supplied `operation_id` string as the primary handle in this local
 * API; the string form is still available via agc_session_id() (and
 * accepted as an optional caller-supplied id at Init, matching the proto)
 * for cross-process correlation and for relaying a session elsewhere. */
typedef struct agc_session agc_session;

/* OperationMetadata: key version, provider output (IV/nonce/salt/...), API
 * version and user context. MUST be stored alongside every ciphertext,
 * signature, MAC and wrapped key (commit 6). */
typedef struct agc_metadata agc_metadata;

/* KeyMetadata: everything ReadKey returns about a key (commit 7). */
typedef struct agc_key_info agc_key_info;

/* TemplateInfo: one algorithm configuration plus its scoped capabilities
 * (commit 11). */
typedef struct agc_template_info agc_template_info;

/* ScopeInfo: human-readable description of one scope (commit 11). */
typedef struct agc_scope_info agc_scope_info;

/* ProviderInfo: a provider TYPE and its capabilities (commit 11). */
typedef struct agc_provider_info agc_provider_info;

/* ProviderInstance: a CONFIGURED provider ready for use (commit 11). */
typedef struct agc_provider_instance agc_provider_instance;

/* ImplementationProperties: FIPS status, verification, side-channel posture
 * (commit 11). */
typedef struct agc_impl_props agc_impl_props;

/* SecurityGuarantees: formal notions, practical outcomes, operational
 * bounds (commit 11). */
typedef struct agc_security_guarantees agc_security_guarantees;

/* EvaluatePolicyResponse: allow/deny plus reasoning and alternatives
 * (commit 11). */
typedef struct agc_policy_decision agc_policy_decision;

/* ValidateKeyOperationResponse: feasibility report for transform/migrate
 * (commit 7). */
typedef struct agc_feasibility_report agc_feasibility_report;

/* MigrateKeyResponse detail: what happened, plus archived-key info
 * (commit 7). */
typedef struct agc_migration_report agc_migration_report;

/* Iterator cursors. Each hides paging bookkeeping (D12). */
typedef struct agc_key_iter               agc_key_iter;
typedef struct agc_template_iter          agc_template_iter;
typedef struct agc_policy_iter            agc_policy_iter;
typedef struct agc_provider_iter          agc_provider_iter;
typedef struct agc_provider_instance_iter agc_provider_instance_iter;

/* --------------------------------------------------------------------------
 * Library lifecycle
 * -------------------------------------------------------------------------- */

AGC_API void         agc_version(int *major, int *minor, int *patch);
AGC_API const char  *agc_version_string(void);
AGC_API const char  *agc_build_info(void);

/* --------------------------------------------------------------------------
 * Context
 * -------------------------------------------------------------------------- */

typedef enum agc_mode {
    AGC_MODE_EMBEDDED = 0,  /* direct function calls; no serialisation, no IPC */
    AGC_MODE_LOCAL    = 1,  /* same host, out-of-process -- NOT IMPLEMENTED here */
    AGC_MODE_REMOTE   = 2   /* networked service (gRPC) -- NOT IMPLEMENTED here */
    AGC_ENUM32(agc_mode)
} agc_mode;

typedef struct agc_ctx_config {
    size_t   struct_size;

    agc_mode mode;

    /* AGC_MODE_LOCAL / AGC_MODE_REMOTE: endpoint URI. Unused in EMBEDDED. */
    agc_str  endpoint;

    /* Path to the template catalog. NULL uses the catalog compiled into the
     * library (commit 11). */
    agc_str  catalog_path;

    /* Default policy name applied when a call does not name one. May be
     * NULL, in which case operations that require a policy must name one
     * explicitly. */
    agc_str  default_policy;

    /* Provider instance configuration source. NULL uses the built-in stub
     * provider only. */
    agc_str  provider_config_path;

    /* Idle TTL, in seconds, after which a streaming session is expired and
     * its state zeroized. 0 selects the implementation default. */
    uint32_t session_idle_ttl_seconds;

    /* If non-zero, the library attempts to mlock() key material and
     * streaming state, and fails context creation if it cannot. */
    int      require_locked_memory;

    /* If non-zero, only FIPS-validated providers are eligible, regardless
     * of per-request ProviderRequirements. */
    int      fips_mode;

    /* Opaque caller identity forwarded to the policy engine for
     * authorization. In EMBEDDED mode this is the process's own credential
     * material. */
    agc_slice caller_identity;
} agc_ctx_config;

/* All agc_str/agc_slice fields of *cfg are copied; the caller need not keep
 * them alive past this call. Returns AGC_ERR_NOT_IMPLEMENTED for
 * AGC_MODE_LOCAL/AGC_MODE_REMOTE in this build. */
AGC_API agc_rc agc_ctx_open(const agc_ctx_config *cfg, agc_ctx **out_ctx);

/* Destroys the context. All handles derived from it become invalid. Any
 * outstanding session is cancelled and its state zeroized. Idempotent on
 * NULL. */
AGC_API void   agc_ctx_close(agc_ctx *ctx);

/* Re-establishes a usable context in a forked child. The inherited context
 * is closed; a fresh one is opened from the same configuration. Fails with
 * AGC_ERR_INVALID_ARGUMENT if `poisoned` was not actually poisoned (i.e. was
 * never forked, or belongs to a different process). */
AGC_API agc_rc agc_ctx_reinit_after_fork(agc_ctx *poisoned, agc_ctx **out_ctx);

/* Returns the mode this context was opened in. */
AGC_API agc_mode agc_ctx_mode(const agc_ctx *ctx);

/* --------------------------------------------------------------------------
 * Errors
 * -------------------------------------------------------------------------- */

typedef struct agc_error_detail {
    size_t      struct_size;
    agc_rc      rc;
    const char *message;        /* NUL-terminated, thread-local storage */
    const char *domain;         /* "caas.crypto.v1" for generated codes */
    const char *reason;         /* e.g. "CRYPTO_ERROR_KEY_NOT_FOUND" */
    const char *provider_id;    /* provider that produced the failure, or NULL */
    int64_t     provider_code;  /* native provider code */
    const char *failed_check;   /* policy: which check denied the operation */
} agc_error_detail;

/* Fills *out with the detail for the last failing call on THIS thread. The
 * string pointers remain valid until the next failing call on this thread.
 * Returns AGC_OK even when there is no error recorded (rc field will be
 * AGC_OK and every string NULL). */
AGC_API agc_rc agc_last_error(agc_error_detail *out);

/* Clears the thread-local error record. */
AGC_API void   agc_clear_error(void);

/* --------------------------------------------------------------------------
 * Memory hygiene
 * -------------------------------------------------------------------------- */

/* Erases n bytes at p. Not elided by the optimiser (implemented via a
 * volatile-pointer write loop, which the C standard guarantees is an
 * observable side effect the compiler cannot remove). */
AGC_API void agc_secure_zero(void *p, size_t n);

/* Constant-time (in structure, not a hardware guarantee) comparison. Returns
 * 1 if equal, 0 otherwise. Callers verifying a MAC or signature out-of-band
 * must use this rather than memcmp. */
AGC_API int  agc_ct_equal(const void *a, const void *b, size_t n);

/* Page-locked allocation for sensitive buffers (mlock, best-effort: returns
 * a normal allocation if locking is unavailable and require_locked_memory
 * was not requested on the context that will use it). agc_secure_free
 * zeroizes before releasing. Returns NULL on failure. */
AGC_API void *agc_secure_alloc(size_t n);
AGC_API void  agc_secure_free(void *p, size_t n);

/* --------------------------------------------------------------------------
 * OperationMetadata (commit 6)
 *
 * Every operation that produces a durable artifact also produces metadata
 * that MUST be stored with it. In the proto this is a nested message; here
 * it is an opaque handle with (a) a canonical byte encoding for storage and
 * (b) typed accessors for callers that need to inspect it.
 *
 * The canonical encoding IS the protobuf wire encoding of OperationMetadata
 * (hand-written codec in src/wire/, no libprotobuf dependency): an artifact
 * produced by this library must be decryptable by the Go service and vice
 * versa, and the wire format is the only encoding both already agree on.
 * Callers treat the bytes as opaque. See RECONCILIATION_PLAN.md D11.
 * -------------------------------------------------------------------------- */

/* Tag values are the proto field numbers of ProviderOutput.algorithm_output
 * (10-16), verified against the pinned descriptor by
 * conformance/tier1c_oneof_tags.py. AGC_ALGORITHM_OUTPUT_NONE (0) is the
 * "oneof unset" sentinel and NEVER appears on a handle a caller can hold —
 * an unset oneof is a provider bug and is rejected with
 * AGC_ERR_PROVIDER_CONTRACT_VIOLATION before any handle is created. */
typedef enum agc_algorithm_output_kind {
    AGC_ALGORITHM_OUTPUT_NONE          = 0,   /* provider bug: oneof unset */
    AGC_ALGORITHM_OUTPUT_NO_OUTPUT     = 10,  /* explicit "no system-generated params" */
    AGC_ALGORITHM_OUTPUT_AEAD          = 11,
    AGC_ALGORITHM_OUTPUT_BLOCK_CIPHER  = 12,
    AGC_ALGORITHM_OUTPUT_COUNTER_MODE  = 13,
    AGC_ALGORITHM_OUTPUT_STREAM_CIPHER = 14,
    AGC_ALGORITHM_OUTPUT_KDF           = 15,
    AGC_ALGORITHM_OUTPUT_VENDOR        = 16
    AGC_ENUM32(agc_algorithm_output_kind)
} agc_algorithm_output_kind;

AGC_API void   agc_metadata_free(agc_metadata *md);

/* Serialise for storage. Two-call convention (agc_buf). */
AGC_API agc_rc agc_metadata_encode(const agc_metadata *md, agc_buf out, size_t *out_len);

/* Reconstruct from stored bytes. Fails with AGC_ERR_PROVIDER_CONTRACT_VIOLATION
 * (and creates no handle) if the decoded ProviderOutput.algorithm_output
 * oneof is unset, exactly as a live provider response would be rejected. */
AGC_API agc_rc agc_metadata_decode(agc_ctx *ctx, agc_slice encoded, agc_metadata **out_md);

/* Constructs empty (NO_OUTPUT) metadata, for the rare case where a caller
 * must synthesise it (e.g. migrating artifacts produced by a pre-1.0
 * implementation). */
AGC_API agc_rc agc_metadata_new(agc_ctx *ctx, agc_metadata **out_md);

/* --- Accessors --- */

AGC_API uint32_t    agc_metadata_key_version(const agc_metadata *md);
AGC_API const char *agc_metadata_api_version(const agc_metadata *md);  /* never NULL */

/* ProviderOutput.encoding: "raw", "der", "jws", "cbor". Never NULL; "" means
 * the proto3 default ("raw" per convention, not enforced by this layer). */
AGC_API const char *agc_metadata_encoding(const agc_metadata *md);

AGC_API agc_algorithm_output_kind agc_metadata_output_kind(const agc_metadata *md);

/* Typed algorithm output. Each returns AGC_ERR_INVALID_ARGUMENT if the
 * metadata does not carry that arm. Byte outputs use the two-call
 * convention. */
AGC_API agc_rc agc_metadata_aead_nonce(const agc_metadata *md, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_metadata_aead_tag_len(const agc_metadata *md, uint32_t *out_bytes);
AGC_API agc_rc agc_metadata_block_iv(const agc_metadata *md, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_metadata_counter_block(const agc_metadata *md, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_metadata_counter_bits(const agc_metadata *md, uint32_t *out_bits);
AGC_API agc_rc agc_metadata_stream_nonce(const agc_metadata *md, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_metadata_stream_block_counter(const agc_metadata *md, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_metadata_kdf_salt(const agc_metadata *md, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_metadata_kdf_iv(const agc_metadata *md, agc_buf out, size_t *out_len);

/* VendorOutput.parameters (map<string, bytes>). Iterate by index. */
AGC_API size_t agc_metadata_vendor_param_count(const agc_metadata *md);
AGC_API agc_rc agc_metadata_vendor_param_at(const agc_metadata *md, size_t index,
                                             const char **out_key,
                                             agc_buf out_value, size_t *out_value_len);

/* user_context (map<string, string>) carried through from the request. */
AGC_API size_t      agc_metadata_user_context_count(const agc_metadata *md);
AGC_API agc_rc      agc_metadata_user_context_at(const agc_metadata *md, size_t index,
                                                  const char **out_key, const char **out_value);
AGC_API const char *agc_metadata_user_context_get(const agc_metadata *md, const char *key);

/* --------------------------------------------------------------------------
 * Sessions (StreamingCryptoService, commit 9)
 * -------------------------------------------------------------------------- */

/* The (client-supplied or library-generated) operation_id backing this
 * session. Needed only when relaying a session across a process boundary or
 * correlating with audit logs. */
AGC_API const char *agc_session_id(const agc_session *s);

/* Which operation this session performs, for defensive assertions. */
AGC_API agc_crypto_operation agc_session_operation(const agc_session *s);

/* Template the service selected for this session, when the session was
 * opened by intent rather than by key (DigestInit, XofInit). NULL
 * otherwise. */
AGC_API const char *agc_session_selected_template_id(const agc_session *s);

/* Aborts a session and releases all state (CancelOperation-shaped, though
 * CancelOperation itself is not an RPC -- see docs/PROTO_RFCS.md RFC-14).
 * Idempotent; cancelling an unknown or already-closed session succeeds.
 * `reason` may be NULL. The handle is invalid afterwards. */
AGC_API agc_rc agc_session_cancel(agc_session *s, const char *reason);

/* Releases the handle. If the session is still open it is cancelled first,
 * so an early return from a function cannot leak provider state. */
AGC_API void   agc_session_free(agc_session *s);

/* Adopts a session created elsewhere by its operation_id. Fails with
 * AGC_ERR_CRYPTO_OPERATION_EXPIRED if unknown. */
AGC_API agc_rc agc_session_attach(agc_ctx *ctx, const char *operation_id,
                                   agc_session **out_session);

#ifdef __cplusplus
}
#endif
#endif /* AGC_CORE_H */
