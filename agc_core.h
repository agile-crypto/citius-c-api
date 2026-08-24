/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_core.h — Abstract Cryptographic API, C binding: core runtime.
 *
 * ============================================================================
 * HAND-WRITTEN. This file is NOT generated. It defines the idioms that the
 * rest of the C binding is built from: handles, buffers, errors, metadata,
 * iterators, and the lifecycle of the library itself.
 * ============================================================================
 *
 * THE FIVE CONVENTIONS
 * --------------------
 * 1. Every call returns agc_rc. AGC_OK == 0. Nothing else is a success.
 * 2. Every byte output uses the two-call convention: pass buf.data == NULL to
 *    learn the size, then call again. The library never allocates a buffer the
 *    caller must free with free().
 * 3. Every rich message output is an opaque handle with typed accessors, freed
 *    with its own agc_*_free. Deep aggregate structs never cross the ABI.
 * 4. Every struct passed by pointer begins with `size_t struct_size`. Use
 *    AGC_INIT() to zero it and set the size.
 * 5. Nothing in this API allocates on the caller's allocator or frees on it.
 *    Allocation is symmetric within the library.
 *
 * THREADING
 * ---------
 * agc_ctx is thread-safe: any number of threads may issue operations on one
 * context concurrently. agc_session (a streaming operation) is NOT thread-safe
 * and must be confined to one thread at a time, exactly as a PKCS#11 session
 * without CKF_OS_LOCKING_OK. Handles obtained from a context become invalid
 * when that context is destroyed.
 *
 * FORK
 * ----
 * After fork(2) the child MUST NOT use any handle inherited from the parent.
 * The library installs a pthread_atfork handler that marks inherited contexts
 * poisoned; operations on them fail with AGC_ERR_INVALID_HANDLE rather than
 * silently reusing a DRBG state that the parent also holds. Call
 * agc_ctx_reinit_after_fork() in the child to obtain a usable context.
 */

#ifndef AGC_CORE_H
#define AGC_CORE_H

#include "agc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Opaque handles
 * -------------------------------------------------------------------------- */

/* The service surface. One context binds a policy engine, a template catalog
 * and a set of provider instances. It is the C analogue of "a connection to the
 * service", except that in the default (embedded) deployment mode there is no
 * connection: calls are direct function calls into the provider. */
typedef struct agc_ctx agc_ctx;

/* A stateful multi-part or message-based operation. Replaces the proto's
 * server-generated `operation_id` string in the local API; the string form is
 * still available via agc_session_id() for cross-process correlation and for
 * relaying a session to a remote front-end. */
typedef struct agc_session agc_session;

/* OperationMetadata: key version, provider output (IV/nonce/salt), API version
 * and user context. This is the value that MUST be stored alongside every
 * ciphertext, signature, MAC and wrapped key. */
typedef struct agc_metadata agc_metadata;

/* KeyMetadata: everything ReadKey returns about a key. */
typedef struct agc_key_info agc_key_info;

/* TemplateInfo: one algorithm configuration plus its scoped capabilities. */
typedef struct agc_template_info agc_template_info;

/* ScopeInfo: human-readable description of one scope. */
typedef struct agc_scope_info agc_scope_info;

/* ProviderInfo: a provider TYPE and its capabilities. */
typedef struct agc_provider_info agc_provider_info;

/* ProviderInstance: a CONFIGURED provider ready for use. */
typedef struct agc_provider_instance agc_provider_instance;

/* ImplementationProperties: FIPS status, verification, side-channel posture. */
typedef struct agc_impl_props agc_impl_props;

/* SecurityGuarantees: formal notions, practical outcomes, operational bounds. */
typedef struct agc_security_guarantees agc_security_guarantees;

/* EvaluatePolicyResponse: allow/deny plus reasoning and alternatives. */
typedef struct agc_policy_decision agc_policy_decision;

/* ValidateKeyOperationResponse: feasibility report for transform/migrate. */
typedef struct agc_feasibility_report agc_feasibility_report;

/* MigrateKeyResponse detail: what actually happened, plus archived-key info. */
typedef struct agc_migration_report agc_migration_report;

/* Paged list cursors. Each hides the proto's page_size/page_token pair. */
typedef struct agc_key_iter               agc_key_iter;
typedef struct agc_template_iter          agc_template_iter;
typedef struct agc_policy_iter            agc_policy_iter;
typedef struct agc_provider_iter          agc_provider_iter;
typedef struct agc_provider_instance_iter agc_provider_instance_iter;

/* --------------------------------------------------------------------------
 * Library lifecycle
 * -------------------------------------------------------------------------- */

/* Compile-time vs run-time version check. Callers SHOULD assert compatibility
 * at startup; a mismatch in major version means the header and the shared
 * object disagree about struct layout. */
AGC_API void   agc_version(int *major, int *minor, int *patch);
AGC_API const char *agc_version_string(void);      /* e.g. "1.0.0" */
AGC_API const char *agc_build_info(void);          /* provider set, FIPS mode, git rev */

/* Context configuration. Deployment mode is a property of the CONTEXT, not of
 * the API: the same 98 functions work identically whether the provider runs
 * in-process, over a UNIX socket, or over gRPC. This is the point of the C
 * binding — it lets `AGC_MODE_EMBEDDED` be the default and keeps RPC out of the
 * cryptographic hot path without changing a single call site. */
typedef enum agc_mode {
    AGC_MODE_EMBEDDED = 0,  /* direct function calls; no serialisation, no IPC */
    AGC_MODE_LOCAL    = 1,  /* same host, out-of-process (UNIX socket / vsock) */
    AGC_MODE_REMOTE   = 2   /* networked service (gRPC) */
    AGC_ENUM32(agc_mode)
} agc_mode;

typedef struct agc_ctx_config {
    size_t   struct_size;

    agc_mode mode;

    /* AGC_MODE_LOCAL / AGC_MODE_REMOTE: endpoint URI. Ignored when EMBEDDED. */
    agc_str  endpoint;

    /* Path to the template catalog (standard_algorithms.json or a compiled
     * form). NULL uses the catalog compiled into the library. */
    agc_str  catalog_path;

    /* Default policy name applied when a call does not name one. May be NULL,
     * in which case operations that require a policy must name one explicitly. */
    agc_str  default_policy;

    /* Provider instance configuration source. NULL uses the built-in software
     * provider only. */
    agc_str  provider_config_path;

    /* Idle TTL, in seconds, after which a streaming session is expired and its
     * state zeroized. Mirrors the MANDATORY server-enforced TTL in
     * messages/session.proto. 0 selects the implementation default. */
    uint32_t session_idle_ttl_seconds;

    /* If non-zero, the library attempts to mlock() key material and streaming
     * state, and fails context creation if it cannot. */
    int      require_locked_memory;

    /* If non-zero, only FIPS-validated providers are eligible, regardless of
     * per-request ProviderRequirements. */
    int      fips_mode;

    /* Opaque caller identity forwarded to the policy engine for authorization.
     * In EMBEDDED mode this is the process's own credential material. */
    agc_slice caller_identity;
} agc_ctx_config;

AGC_API agc_rc agc_ctx_open(const agc_ctx_config *cfg, agc_ctx **out_ctx);

/* Destroys the context. All handles derived from it become invalid. Any
 * outstanding session state is cancelled and zeroized. Idempotent on NULL. */
AGC_API void   agc_ctx_close(agc_ctx *ctx);

/* Re-establishes a usable context in a forked child. The inherited context is
 * closed; a fresh one is opened from the same configuration, with DRBG state
 * reseeded and provider connections re-opened. */
AGC_API agc_rc agc_ctx_reinit_after_fork(agc_ctx *poisoned, agc_ctx **out_ctx);

/* Returns the mode this context was opened in. Callers that must guarantee no
 * RPC in the hot path can assert AGC_MODE_EMBEDDED at startup. */
AGC_API agc_mode agc_ctx_mode(const agc_ctx *ctx);

/* --------------------------------------------------------------------------
 * Errors
 *
 * agc_rc is the machine-readable outcome and is always sufficient to branch on.
 * The detail record adds human-readable context and provider diagnostics; it is
 * thread-local and is overwritten by the next failing call on the same thread.
 * -------------------------------------------------------------------------- */

typedef struct agc_error_detail {
    size_t      struct_size;
    agc_rc      rc;
    const char *message;        /* NUL-terminated, thread-local storage */
    const char *domain;         /* "caas.crypto.v1" for generated codes */
    const char *reason;         /* e.g. "CRYPTO_ERROR_KEY_NOT_FOUND" */
    const char *provider_id;    /* provider that produced the failure, or NULL */
    int64_t     provider_code;  /* native provider code (e.g. PKCS#11 CKR_*) */
    const char *failed_check;   /* policy: which check denied the operation */
} agc_error_detail;

/* Fills *out with the detail for the last failing call on THIS thread. The
 * string pointers remain valid until the next failing call on this thread.
 * Returns AGC_OK even when there is no error recorded (rc field will be AGC_OK). */
AGC_API agc_rc agc_last_error(agc_error_detail *out);

/* Clears the thread-local error record. */
AGC_API void   agc_clear_error(void);

/* --------------------------------------------------------------------------
 * Memory hygiene
 *
 * These are exported because the caller owns every output buffer and is
 * therefore responsible for erasing it. The library cannot do it for them.
 * -------------------------------------------------------------------------- */

/* Erases n bytes at p. Guaranteed not to be elided by the optimiser. */
AGC_API void agc_secure_zero(void *p, size_t n);

/* Constant-time comparison. Returns 1 if equal, 0 otherwise. Provided because
 * callers verifying a MAC or signature out-of-band need it and must not reach
 * for memcmp. */
AGC_API int  agc_ct_equal(const void *a, const void *b, size_t n);

/* Page-locked allocation for sensitive buffers. agc_secure_free zeroizes before
 * releasing. Returns NULL on failure. Optional: ordinary malloc'd buffers work
 * everywhere in this API. */
AGC_API void *agc_secure_alloc(size_t n);
AGC_API void  agc_secure_free(void *p, size_t n);

/* --------------------------------------------------------------------------
 * OperationMetadata
 *
 * Every operation that produces a durable artifact also produces metadata that
 * MUST be stored with it. In the proto this is a nested message; here it is an
 * opaque handle with (a) a canonical byte encoding for storage and (b) typed
 * accessors for callers that need to inspect it.
 *
 * The canonical encoding IS the protobuf wire encoding of OperationMetadata.
 * This is deliberate: an artifact produced by the C library must be decryptable
 * by the Go service and vice versa, and the wire format is the only encoding
 * both already agree on. Callers treat it as an opaque blob.
 * -------------------------------------------------------------------------- */

AGC_API void   agc_metadata_free(agc_metadata *md);

/* Serialise for storage. Two-call convention. */
AGC_API agc_rc agc_metadata_encode(const agc_metadata *md, agc_buf out, size_t *out_len);

/* Reconstruct from stored bytes. */
AGC_API agc_rc agc_metadata_decode(agc_ctx *ctx, agc_slice encoded, agc_metadata **out_md);

/* Construct empty metadata, for the rare case where a caller must synthesise it
 * (e.g. migrating artifacts produced by a pre-1.0 implementation). */
AGC_API agc_rc agc_metadata_new(agc_ctx *ctx, agc_metadata **out_md);

/* --- Accessors --- */

AGC_API uint32_t    agc_metadata_key_version(const agc_metadata *md);
AGC_API const char *agc_metadata_api_version(const agc_metadata *md);

/* ProviderOutput.encoding: "raw", "der", "jws", "cbor". Never NULL. */
AGC_API const char *agc_metadata_encoding(const agc_metadata *md);

/* Which arm of ProviderOutput.algorithm_output is set. A well-formed metadata
 * NEVER returns AGC_ALGORITHM_OUTPUT_NONE — an unset oneof is a provider bug
 * and is rejected with AGC_ERR_PROVIDER_CONTRACT_VIOLATION at the boundary. */
AGC_API agc_algorithm_output_kind agc_metadata_output_kind(const agc_metadata *md);

/* Typed algorithm output. Each returns AGC_ERR_INVALID_ARGUMENT if the metadata
 * does not carry that arm. Byte outputs use the two-call convention. */
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
 * Sessions (StreamingCryptoService)
 * -------------------------------------------------------------------------- */

/* The server-generated operation_id backing this session. Needed only when
 * relaying a session across a process boundary or correlating with audit logs. */
AGC_API const char *agc_session_id(const agc_session *s);

/* Which operation this session performs, for defensive assertions. */
AGC_API agc_operation agc_session_operation(const agc_session *s);

/* Template the service selected for this session, when the session was opened
 * by intent rather than by key (DigestInit, XofInit). NULL otherwise. */
AGC_API const char *agc_session_selected_template(const agc_session *s);

/* Aborts a session and releases all state (CancelOperation). Idempotent;
 * cancelling an unknown or already-expired session succeeds. `reason` may be
 * NULL and is recorded in the audit trail. The handle is invalid afterwards. */
AGC_API agc_rc agc_session_cancel(agc_session *s, const char *reason);

/* Releases the handle. If the session is still open it is cancelled first, so
 * an early return from a function cannot leak provider state. */
AGC_API void   agc_session_free(agc_session *s);

/* Adopt a session created elsewhere (e.g. by a remote front-end that returned
 * an operation_id). Fails with AGC_ERR_CRYPTO_OPERATION_EXPIRED if unknown. */
AGC_API agc_rc agc_session_attach(agc_ctx *ctx, const char *operation_id,
                                  agc_session **out_session);

/* --------------------------------------------------------------------------
 * Rich message accessors
 *
 * These handles replace deep aggregate structs. The rationale is ABI: KeyMetadata
 * transitively contains TemplateInfo, which contains AlgorithmDetails, which
 * contains a 40-arm oneof over algorithm parameter messages. Exposing that as C
 * structs would freeze the entire algorithm catalog into the ABI, so that adding
 * ML-KEM-1024 to the catalog — a data change in the proto model — would become
 * a soname bump. Handles make catalog growth ABI-neutral.
 * -------------------------------------------------------------------------- */

/* ---- KeyMetadata ---- */
AGC_API void agc_key_info_free(agc_key_info *ki);

AGC_API const char             *agc_key_info_name(const agc_key_info *ki);
AGC_API uint32_t                agc_key_info_version(const agc_key_info *ki);
AGC_API const char             *agc_key_info_key_id(const agc_key_info *ki);
AGC_API const char             *agc_key_info_template_id(const agc_key_info *ki);
AGC_API const char             *agc_key_info_provider(const agc_key_info *ki);
AGC_API const char             *agc_key_info_policy(const agc_key_info *ki);
AGC_API agc_timestamp           agc_key_info_created_time(const agc_key_info *ki);
AGC_API agc_timestamp           agc_key_info_updated_time(const agc_key_info *ki);
AGC_API agc_timestamp           agc_key_info_activation_time(const agc_key_info *ki);
AGC_API agc_timestamp           agc_key_info_expiration_time(const agc_key_info *ki);
AGC_API int                     agc_key_info_extractable(const agc_key_info *ki);
AGC_API agc_key_lifecycle_state agc_key_info_lifecycle_state(const agc_key_info *ki);
AGC_API agc_key_origin          agc_key_info_origin(const agc_key_info *ki);

/* The scope specification the key was created with. Copied into *out; the
 * caller may inspect the union directly. */
AGC_API agc_rc agc_key_info_scope_spec(const agc_key_info *ki, agc_scope_spec *out);

/* Public-key material for asymmetric keys. AGC_ERR_INVALID_ARGUMENT for
 * symmetric keys. Two-call convention. */
AGC_API agc_rc agc_key_info_public_key(const agc_key_info *ki, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_key_info_public_key_format(const agc_key_info *ki, agc_key_format *out);

/* provider_metadata (map<string, string>). */
AGC_API size_t      agc_key_info_provider_metadata_count(const agc_key_info *ki);
AGC_API agc_rc      agc_key_info_provider_metadata_at(const agc_key_info *ki, size_t index,
                                                      const char **out_key, const char **out_value);

/* Borrowed sub-handles; valid while the parent key_info is alive. Do NOT free. */
AGC_API const agc_template_info *agc_key_info_template(const agc_key_info *ki);
AGC_API const agc_impl_props    *agc_key_info_implementation(const agc_key_info *ki);

/* ---- TemplateInfo ---- */
AGC_API void agc_template_info_free(agc_template_info *ti);

AGC_API const char         *agc_template_info_id(const agc_template_info *ti);
AGC_API const char         *agc_template_info_display_name(const agc_template_info *ti);
AGC_API const char         *agc_template_info_description(const agc_template_info *ti);
AGC_API agc_template_status agc_template_info_status(const agc_template_info *ti);
AGC_API const char         *agc_template_info_deprecation_notice(const agc_template_info *ti);
AGC_API size_t              agc_template_info_standards_count(const agc_template_info *ti);
AGC_API const char         *agc_template_info_standard_at(const agc_template_info *ti, size_t i);

/* AlgorithmDetails, flattened to the fields a C caller can act on. The full
 * 40-arm algorithm oneof is NOT projected into the ABI; callers that need
 * parameter-level detail read the CycloneDX projection below or fetch the
 * catalog entry as JSON via agc_template_info_to_json(). */
AGC_API const char          *agc_template_info_oid(const agc_template_info *ti);
AGC_API agc_crypto_primitive agc_template_info_primitive(const agc_template_info *ti);
AGC_API agc_key_type         agc_template_info_key_type(const agc_template_info *ti);
AGC_API uint32_t             agc_template_info_key_size_bits(const agc_template_info *ti);

/* CycloneDX v1.7 algorithmProperties projection, for CBOM export. */
AGC_API const char *agc_template_info_cdx_name(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_primitive(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_family(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_parameter_set(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_elliptic_curve(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_mode(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_padding(const agc_template_info *ti);
AGC_API uint32_t    agc_template_info_cdx_classical_level(const agc_template_info *ti);
AGC_API uint32_t    agc_template_info_cdx_quantum_level(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_execution_environment(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_implementation_platform(const agc_template_info *ti);
AGC_API size_t      agc_template_info_cdx_crypto_function_count(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_crypto_function_at(const agc_template_info *ti, size_t i);
AGC_API size_t      agc_template_info_cdx_certification_count(const agc_template_info *ti);
AGC_API const char *agc_template_info_cdx_certification_at(const agc_template_info *ti, size_t i);

/* ScopedCapabilities: one operational mode of the template. */
AGC_API size_t agc_template_info_capability_count(const agc_template_info *ti);
AGC_API agc_rc agc_template_info_capability_scope(const agc_template_info *ti, size_t i,
                                                  agc_scope_spec *out);
AGC_API size_t agc_template_info_capability_operation_count(const agc_template_info *ti, size_t i);
AGC_API agc_rc agc_template_info_capability_operation_at(const agc_template_info *ti, size_t i,
                                                         size_t j, agc_operation *out);
/* Per-scope guarantees; falls back to the template-level guarantees when the
 * capability does not override them. Borrowed; do NOT free. */
AGC_API const agc_security_guarantees *
       agc_template_info_capability_guarantees(const agc_template_info *ti, size_t i);
AGC_API const agc_security_guarantees *
       agc_template_info_guarantees(const agc_template_info *ti);

/* Full catalog entry as canonical JSON, for tooling that needs the algorithm
 * parameter detail this header deliberately does not project. Two-call. */
AGC_API agc_rc agc_template_info_to_json(const agc_template_info *ti, agc_buf out, size_t *out_len);

/* ---- SecurityGuarantees ---- */
/* Informational only: never used for template matching. Exposed for audit,
 * CBOM and compliance reporting, mirroring the proto's stated purpose. */
AGC_API agc_tribool agc_guarantees_ind_cpa(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_ind_cca1(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_ind_cca2(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_nm_cpa(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_int_ctxt(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_int_ptxt(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_euf_cma(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_suf_cma(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_prf(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_preimage_resistant(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_second_preimage_resistant(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_collision_resistant(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_ow_cca(const agc_security_guarantees *g);
AGC_API agc_tribool agc_guarantees_ind_cca_kem(const agc_security_guarantees *g);

AGC_API int agc_guarantees_confidentiality(const agc_security_guarantees *g);
AGC_API int agc_guarantees_integrity(const agc_security_guarantees *g);
AGC_API int agc_guarantees_authenticity(const agc_security_guarantees *g);
AGC_API int agc_guarantees_non_repudiation(const agc_security_guarantees *g);

AGC_API uint32_t    agc_guarantees_auth_strength_bits(const agc_security_guarantees *g);
AGC_API uint64_t    agc_guarantees_max_messages_per_key(const agc_security_guarantees *g);
AGC_API uint64_t    agc_guarantees_max_plaintext_bytes_per_key(const agc_security_guarantees *g);
/* Kept as a string, exactly as in the proto, to preserve "2^-32" notation
 * without lossy conversion to double. */
AGC_API const char *agc_guarantees_attack_success_probability(const agc_security_guarantees *g);

AGC_API size_t      agc_guarantees_additional_count(const agc_security_guarantees *g);
AGC_API agc_rc      agc_guarantees_additional_at(const agc_security_guarantees *g, size_t i,
                                                 const char **out_key, const char **out_value);

/* ---- ImplementationProperties ---- */
AGC_API void agc_impl_props_free(agc_impl_props *ip);

AGC_API int               agc_impl_props_fips_certified(const agc_impl_props *ip);
AGC_API agc_fips140_level agc_impl_props_fips_level(const agc_impl_props *ip);
AGC_API const char       *agc_impl_props_fips_certificate_number(const agc_impl_props *ip);
AGC_API const char       *agc_impl_props_fips_module_name(const agc_impl_props *ip);
AGC_API agc_timestamp     agc_impl_props_fips_validation_date(const agc_impl_props *ip);
AGC_API agc_timestamp     agc_impl_props_fips_expiration_date(const agc_impl_props *ip);

AGC_API agc_tribool agc_impl_props_common_criteria_certified(const agc_impl_props *ip);
AGC_API agc_tribool agc_impl_props_formally_verified(const agc_impl_props *ip);
AGC_API const char *agc_impl_props_verification_framework(const agc_impl_props *ip);
AGC_API agc_tribool agc_impl_props_memory_safe_language(const agc_impl_props *ip);
AGC_API const char *agc_impl_props_implementation_language(const agc_impl_props *ip);
AGC_API agc_tribool agc_impl_props_constant_time(const agc_impl_props *ip);
AGC_API agc_tribool agc_impl_props_side_channel_hardened(const agc_impl_props *ip);
AGC_API agc_tribool agc_impl_props_hardware_accelerated(const agc_impl_props *ip);
AGC_API agc_tribool agc_impl_props_no_known_cve(const agc_impl_props *ip);

AGC_API size_t      agc_impl_props_hardware_feature_count(const agc_impl_props *ip);
AGC_API const char *agc_impl_props_hardware_feature_at(const agc_impl_props *ip, size_t i);
AGC_API size_t      agc_impl_props_unpatched_cve_count(const agc_impl_props *ip);
AGC_API const char *agc_impl_props_unpatched_cve_at(const agc_impl_props *ip, size_t i);

AGC_API size_t      agc_impl_props_audit_count(const agc_impl_props *ip);
AGC_API agc_rc      agc_impl_props_audit_at(const agc_impl_props *ip, size_t i,
                                            const char **out_auditor,
                                            agc_timestamp *out_report_date,
                                            const char **out_report_id,
                                            const char **out_scope,
                                            const char **out_findings_summary,
                                            const char **out_report_url);

AGC_API size_t agc_impl_props_additional_count(const agc_impl_props *ip);
AGC_API agc_rc agc_impl_props_additional_at(const agc_impl_props *ip, size_t i,
                                            const char **out_key, const char **out_value);

/* --------------------------------------------------------------------------
 * Iterators
 *
 * The proto exposes pagination as (page_size, page_token) on the request and
 * next_page_token on the response. Reproducing that in C would push cursor
 * bookkeeping onto every caller. The iterator holds the token internally and
 * fetches pages lazily; page_size becomes a tuning knob on the open call.
 *
 * Usage:
 *     agc_key_info *ki;
 *     while ((rc = agc_key_iter_next(it, &ki)) == AGC_OK) { ...; agc_key_info_free(ki); }
 *     if (rc != AGC_ERR_ITERATOR_EXHAUSTED) { handle error }
 *     agc_key_iter_free(it);
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_key_iter_next(agc_key_iter *it, agc_key_info **out);
AGC_API void   agc_key_iter_free(agc_key_iter *it);

AGC_API agc_rc agc_template_iter_next(agc_template_iter *it, agc_template_info **out);
AGC_API void   agc_template_iter_free(agc_template_iter *it);

AGC_API agc_rc agc_provider_iter_next(agc_provider_iter *it, agc_provider_info **out);
AGC_API void   agc_provider_iter_free(agc_provider_iter *it);

AGC_API agc_rc agc_provider_instance_iter_next(agc_provider_instance_iter *it,
                                               agc_provider_instance **out);
AGC_API void   agc_provider_instance_iter_free(agc_provider_instance_iter *it);

/* PolicySummary is small enough to project as a value struct. */
typedef struct agc_policy_summary {
    size_t        struct_size;
    const char   *name;
    agc_timestamp created_at;
    agc_timestamp updated_at;
    int64_t       version;
    const char   *format;
} agc_policy_summary;

/* The strings in *out are owned by the iterator and are invalidated by the next
 * call to agc_policy_iter_next on the same iterator. */
AGC_API agc_rc agc_policy_iter_next(agc_policy_iter *it, agc_policy_summary *out);
AGC_API void   agc_policy_iter_free(agc_policy_iter *it);

#ifdef __cplusplus
}
#endif
#endif /* AGC_CORE_H */
