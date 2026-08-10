/**
 * @file stub_provider.c
 * @brief Zero-filling stub implementation of the Citius provider API.
 *
 * Every function returns CITIUS_OK and zero-fills output buffers.
 * Registered under the instance ID "stub".
 *
 * This file exists solely to validate the API contract in the test suite.
 * No real cryptography is performed.
 */

#include "citius/citius.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* =========================================================================
 * Internal: tiny global registry (key + policy slots)
 *
 * The stub uses a trivially simple array-based registry.  It is not
 * thread-safe — this is sufficient for the single-threaded test suite.
 * ========================================================================= */

#define STUB_MAX_KEYS     64
#define STUB_MAX_POLICIES 8
#define STUB_MAX_BATCH    32

static const char *STUB_INSTANCE_ID = "stub";

/* Minimal key record — keyed by name string */
typedef struct {
    int                   in_use;
    citius_key_metadata_t meta;
    char                  name_buf[64];
} stub_key_t;

static stub_key_t g_keys[STUB_MAX_KEYS];
static unsigned   g_next_key_seq = 1; /* for generating unique names */

/* Policy storage — simple name + opaque document string */
static struct {
    int  in_use;
    char name_buf[64];
    char doc_buf[256];
} g_policies[STUB_MAX_POLICIES];

/* Scratch buffers backing provider-owned-pointer response fields
 * (citius_list_keys_response_t.keys, citius_list_crypto_policies_response_t.policies,
 * citius_batch_evaluate_policy_response_t.results). Repopulated on each call. */
static citius_key_metadata_t          g_key_list_buf[STUB_MAX_KEYS];
static citius_policy_summary_t        g_policy_list_buf[STUB_MAX_POLICIES];
static citius_evaluate_policy_response_t g_batch_eval_buf[STUB_MAX_BATCH];
static uint8_t                        g_zero_key_material[64];

/* =========================================================================
 * Helpers
 * ========================================================================= */

/** Zero-fill an output buffer and set length to min(requested, capacity). */
static CITIUS_RV fill_output(citius_mutable_buffer_t *buf, size_t requested)
{
    if (!buf) return CITIUS_NULL_ARGUMENT;
    buf->length = requested;
    if (buf->data == NULL || buf->capacity == 0) {
        /* Size-query mode: report required size without writing */
        buf->capacity = 0;
        return CITIUS_OK;
    }
    if (buf->capacity < requested) {
        buf->length = requested; /* Tell caller how much is needed */
        return CITIUS_BUFFER_TOO_SMALL;
    }
    memset(buf->data, 0, requested);
    buf->length = requested;
    return CITIUS_OK;
}

/* Helper: zero-fill the metadata in a response. */
static void zero_metadata(citius_operation_metadata_t *m)
{
    memset(m, 0, sizeof(*m));
    m->provider_output.type     = CITIUS_ALGO_OUTPUT_NONE;
    m->provider_output.encoding = "raw";
    m->api_version              = "1.0";
}

/* Helper: find a key slot index by name string; returns -1 if not found */
static int key_find(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i < STUB_MAX_KEYS; ++i) {
        if (g_keys[i].in_use && strcmp(g_keys[i].name_buf, name) == 0) return i;
    }
    return -1;
}

/**
 * Register a new key slot, filling in a plausible zero-ish key_metadata.
 * Returns the slot index, or -1 if the registry is full.
 */
static int key_register(const char *requested_name)
{
    for (int i = 0; i < STUB_MAX_KEYS; ++i) {
        if (g_keys[i].in_use) continue;

        g_keys[i].in_use  = 1;

        if (requested_name && requested_name[0]) {
            snprintf(g_keys[i].name_buf, sizeof(g_keys[i].name_buf), "%s", requested_name);
        } else {
            snprintf(g_keys[i].name_buf, sizeof(g_keys[i].name_buf), "key-%u", g_next_key_seq++);
        }

        memset(&g_keys[i].meta, 0, sizeof(g_keys[i].meta));
        g_keys[i].meta.name            = g_keys[i].name_buf;
        g_keys[i].meta.key_id          = g_keys[i].name_buf;
        g_keys[i].meta.version         = 1;
        g_keys[i].meta.extractable     = 1;
        g_keys[i].meta.lifecycle_state = KEY_LIFECYCLE_STATE_ACTIVE;
        return i;
    }
    return -1;
}

/* =========================================================================
 * citius_rv_to_string()
 * ========================================================================= */

const char *citius_rv_to_string(CITIUS_RV rv)
{
    switch (rv) {
    case CITIUS_OK:                         return "CITIUS_OK";
    case CITIUS_KEY_NOT_FOUND:              return "CITIUS_KEY_NOT_FOUND";
    case CITIUS_KEY_ALREADY_EXISTS:         return "CITIUS_KEY_ALREADY_EXISTS";
    case CITIUS_KEY_INACTIVE:               return "CITIUS_KEY_INACTIVE";
    case CITIUS_KEY_COMPROMISED:            return "CITIUS_KEY_COMPROMISED";
    case CITIUS_KEY_DESTROYED:              return "CITIUS_KEY_DESTROYED";
    case CITIUS_KEY_TYPE_MISMATCH:          return "CITIUS_KEY_TYPE_MISMATCH";
    case CITIUS_KEY_SIZE_INVALID:           return "CITIUS_KEY_SIZE_INVALID";
    case CITIUS_KEY_NOT_EXTRACTABLE:        return "CITIUS_KEY_NOT_EXTRACTABLE";
    case CITIUS_KEY_ROTATION_FAILED:        return "CITIUS_KEY_ROTATION_FAILED";
    case CITIUS_TEMPLATE_NOT_FOUND:         return "CITIUS_TEMPLATE_NOT_FOUND";
    case CITIUS_TEMPLATE_DEPRECATED:        return "CITIUS_TEMPLATE_DEPRECATED";
    case CITIUS_TEMPLATE_FORBIDDEN:         return "CITIUS_TEMPLATE_FORBIDDEN";
    case CITIUS_TEMPLATE_EXPERIMENTAL:      return "CITIUS_TEMPLATE_EXPERIMENTAL";
    case CITIUS_SCOPE_MISMATCH:             return "CITIUS_SCOPE_MISMATCH";
    case CITIUS_ALGORITHM_NOT_SUPPORTED:    return "CITIUS_ALGORITHM_NOT_SUPPORTED";
    case CITIUS_PARAMETER_INVALID:          return "CITIUS_PARAMETER_INVALID";
    case CITIUS_SCOPE_NOT_SUPPORTED:        return "CITIUS_SCOPE_NOT_SUPPORTED";
    case CITIUS_PROVIDER_NOT_FOUND:         return "CITIUS_PROVIDER_NOT_FOUND";
    case CITIUS_PROVIDER_UNAVAILABLE:       return "CITIUS_PROVIDER_UNAVAILABLE";
    case CITIUS_PROVIDER_ERROR:             return "CITIUS_PROVIDER_ERROR";
    case CITIUS_PROVIDER_NOT_FIPS:          return "CITIUS_PROVIDER_NOT_FIPS";
    case CITIUS_PROVIDER_ALREADY_REGISTERED: return "CITIUS_PROVIDER_ALREADY_REGISTERED";
    case CITIUS_POLICY_VIOLATION:           return "CITIUS_POLICY_VIOLATION";
    case CITIUS_POLICY_NOT_FOUND:           return "CITIUS_POLICY_NOT_FOUND";
    case CITIUS_POLICY_ALREADY_EXISTS:      return "CITIUS_POLICY_ALREADY_EXISTS";
    case CITIUS_POLICY_INVALID:             return "CITIUS_POLICY_INVALID";
    case CITIUS_POLICY_CONFLICT:            return "CITIUS_POLICY_CONFLICT";
    case CITIUS_OPERATION_NOT_SUPPORTED:    return "CITIUS_OPERATION_NOT_SUPPORTED";
    case CITIUS_OPERATION_ACTIVE:           return "CITIUS_OPERATION_ACTIVE";
    case CITIUS_OPERATION_NOT_ACTIVE:       return "CITIUS_OPERATION_NOT_ACTIVE";
    case CITIUS_VERIFICATION_FAILED:        return "CITIUS_VERIFICATION_FAILED";
    case CITIUS_DECRYPTION_FAILED:          return "CITIUS_DECRYPTION_FAILED";
    case CITIUS_INVALID_NONCE:              return "CITIUS_INVALID_NONCE";
    case CITIUS_TAG_MISMATCH:               return "CITIUS_TAG_MISMATCH";
    case CITIUS_INVALID_SIGNATURE:          return "CITIUS_INVALID_SIGNATURE";
    case CITIUS_MIGRATION_FAILED:           return "CITIUS_MIGRATION_FAILED";
    case CITIUS_MIGRATION_NOT_SUPPORTED:    return "CITIUS_MIGRATION_NOT_SUPPORTED";
    case CITIUS_MIGRATION_POLICY_DENIED:    return "CITIUS_MIGRATION_POLICY_DENIED";
    case CITIUS_MIGRATION_VERSION_MISMATCH: return "CITIUS_MIGRATION_VERSION_MISMATCH";
    case CITIUS_INVALID_KEY_MATERIAL:       return "CITIUS_INVALID_KEY_MATERIAL";
    case CITIUS_INVALID_CIPHERTEXT:         return "CITIUS_INVALID_CIPHERTEXT";
    case CITIUS_INVALID_PLAINTEXT:          return "CITIUS_INVALID_PLAINTEXT";
    case CITIUS_INVALID_SIGNATURE_DATA:     return "CITIUS_INVALID_SIGNATURE_DATA";
    case CITIUS_INVALID_MAC_DATA:           return "CITIUS_INVALID_MAC_DATA";
    case CITIUS_ENCODING_ERROR:             return "CITIUS_ENCODING_ERROR";
    case CITIUS_DECODING_ERROR:             return "CITIUS_DECODING_ERROR";
    case CITIUS_BUFFER_TOO_SMALL:           return "CITIUS_BUFFER_TOO_SMALL";
    case CITIUS_OUT_OF_MEMORY:              return "CITIUS_OUT_OF_MEMORY";
    case CITIUS_NULL_ARGUMENT:              return "CITIUS_NULL_ARGUMENT";
    case CITIUS_GENERAL_ERROR:              return "CITIUS_GENERAL_ERROR";
    case CITIUS_FUNCTION_NOT_SUPPORTED:     return "CITIUS_FUNCTION_NOT_SUPPORTED";
    case CITIUS_RANDOM_SEED_REQUIRED:       return "CITIUS_RANDOM_SEED_REQUIRED";
    default:                                return "CITIUS_UNKNOWN";
    }
}

/* =========================================================================
 * citius_init / citius_finalize
 * ========================================================================= */

CITIUS_RV citius_init(void)
{
    memset(g_keys,     0, sizeof(g_keys));
    memset(g_policies, 0, sizeof(g_policies));
    g_next_key_seq  = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_finalize(void)
{
    memset(g_keys,     0, sizeof(g_keys));
    memset(g_policies, 0, sizeof(g_policies));
    return CITIUS_OK;
}

/* =========================================================================
 * Local provider backend registry (stub — single built-in provider)
 * ========================================================================= */

CITIUS_RV citius_provider_register(
    const citius_provider_info_t *info,
    const citius_provider_ops_t  *ops,
    CITIUS_PROVIDER_HANDLE       *instance_out)
{
    (void)info; (void)ops;
    if (instance_out) *instance_out = 1; /* Only the built-in stub */
    return CITIUS_OK;
}

CITIUS_RV citius_provider_unregister(CITIUS_PROVIDER_HANDLE instance)
{
    (void)instance;
    return CITIUS_OK;
}

CITIUS_RV citius_provider_select(
    const citius_scope_spec_t            *scope_spec,
    const citius_provider_requirements_t *requirements,
    CITIUS_PROVIDER_HANDLE               *instance_out)
{
    (void)scope_spec; (void)requirements;
    if (!instance_out) return CITIUS_NULL_ARGUMENT;
    *instance_out = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_provider_list(
    CITIUS_PROVIDER_HANDLE *instances_out,
    size_t                 *count_inout)
{
    if (!count_inout) return CITIUS_NULL_ARGUMENT;
    if (*count_inout < 1) { *count_inout = 1; return CITIUS_BUFFER_TOO_SMALL; }
    if (instances_out) instances_out[0] = 1;
    *count_inout = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_provider_describe(
    CITIUS_PROVIDER_HANDLE  instance,
    citius_provider_info_t *info_out)
{
    if (instance != 1) return CITIUS_PROVIDER_NOT_FOUND;
    if (!info_out) return CITIUS_NULL_ARGUMENT;
    memset(info_out, 0, sizeof(*info_out));
    info_out->provider_id   = STUB_INSTANCE_ID;
    info_out->display_name  = "Citius Stub Provider";
    info_out->provider_type = PROVIDER_TYPE_SOFTWARE;
    return CITIUS_OK;
}

/* =========================================================================
 * Key management  (KeyManagementService)
 * ========================================================================= */

CITIUS_RV citius_key_create(
    const citius_create_key_request_t *request,
    citius_create_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;

    int idx = key_register(request->name);
    if (idx < 0) return CITIUS_OUT_OF_MEMORY;

    memset(response, 0, sizeof(*response));
    response->success      = 1;
    response->key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_read(
    const citius_read_key_request_t *request,
    citius_read_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_find(request->name);
    if (idx < 0) return CITIUS_KEY_NOT_FOUND;
    response->key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_list(
    const citius_list_keys_request_t *request,
    citius_list_keys_response_t      *response)
{
    (void)request;
    if (!response) return CITIUS_NULL_ARGUMENT;

    size_t count = 0;
    for (int i = 0; i < STUB_MAX_KEYS && count < STUB_MAX_KEYS; ++i) {
        if (g_keys[i].in_use) g_key_list_buf[count++] = g_keys[i].meta;
    }
    response->keys            = g_key_list_buf;
    response->key_count       = count;
    response->next_page_token = NULL;
    return CITIUS_OK;
}

CITIUS_RV citius_key_delete(
    const citius_delete_key_request_t *request,
    citius_delete_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_find(request->name);
    if (idx < 0) return CITIUS_KEY_NOT_FOUND;
    g_keys[idx].meta.lifecycle_state = KEY_LIFECYCLE_STATE_DESTROYED;
    g_keys[idx].in_use = 0;
    response->success = 1;
    response->message = NULL;
    return CITIUS_OK;
}

CITIUS_RV citius_key_rotate(
    const citius_rotate_key_request_t *request,
    citius_rotate_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_find(request->name);
    if (idx < 0) return CITIUS_KEY_NOT_FOUND;
    g_keys[idx].meta.version++;
    response->success          = 1;
    response->message          = NULL;
    response->new_key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_export(
    const citius_export_key_request_t *request,
    citius_export_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_find(request->name);
    if (idx < 0) return CITIUS_KEY_NOT_FOUND;
    response->key_material     = g_zero_key_material; /* stub: zero bytes, static storage */
    response->key_material_len = sizeof(g_zero_key_material);
    response->format           = request->format;
    response->key_metadata     = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_import(
    const citius_import_key_request_t *request,
    citius_import_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_register(request->name);
    if (idx < 0) return CITIUS_OUT_OF_MEMORY;
    response->success      = 1;
    response->message      = NULL;
    response->key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_transform(
    const citius_transform_key_request_t *request,
    citius_transform_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_find(request->name);
    if (idx < 0) return CITIUS_KEY_NOT_FOUND;
    response->success      = 1;
    response->message      = NULL;
    response->key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_update_policy(
    const citius_update_key_policy_request_t *request,
    citius_update_key_policy_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_find(request->name);
    if (idx < 0) return CITIUS_KEY_NOT_FOUND;
    response->success      = 1;
    response->message      = NULL;
    response->key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_migrate(
    const citius_migrate_key_request_t *request,
    citius_migrate_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    int idx = key_find(request->name);
    if (idx < 0) return CITIUS_KEY_NOT_FOUND;
    memset(response, 0, sizeof(*response));
    response->success      = 1;
    response->key_metadata = g_keys[idx].meta;
    response->result.strategy_used        = request->strategy;
    response->result.key_bytes_preserved  = 1;
    response->result.source_provider_id   = STUB_INSTANCE_ID;
    response->result.target_provider_id   = STUB_INSTANCE_ID;
    return CITIUS_OK;
}

CITIUS_RV citius_key_validate_operation(
    const citius_validate_key_operation_request_t *request,
    citius_validate_key_operation_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    if (key_find(request->name) < 0) return CITIUS_KEY_NOT_FOUND;

    memset(response, 0, sizeof(*response));
    response->current_state.provider_id  = STUB_INSTANCE_ID;
    response->current_state.instance_id  = STUB_INSTANCE_ID;
    response->current_state.extractable  = 1;
    response->current_state.provider_type = PROVIDER_TYPE_SOFTWARE;
    response->options                    = NULL;
    response->options_count              = 0;
    response->recommended_strategy       = CITIUS_MIGRATION_STRATEGY_PROVIDER_SWITCH;
    response->recommendation_reason      = "stub: all strategies feasible";
    return CITIUS_OK;
}

/* =========================================================================
 * Single-shot crypto operations — all return CITIUS_OK + zero output
 * ========================================================================= */

CITIUS_RV citius_encrypt(
    const citius_encrypt_request_t *request,
    citius_encrypt_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    /* Stub: ciphertext length = plaintext + 16-byte tag */
    return fill_output(&response->ciphertext, request->plaintext.length + 16);
}

CITIUS_RV citius_decrypt(
    const citius_decrypt_request_t *request,
    citius_decrypt_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    size_t pt_len = request->ciphertext.length > 16
                    ? request->ciphertext.length - 16 : 0;
    return fill_output(&response->plaintext, pt_len);
}

CITIUS_RV citius_sign(
    const citius_sign_request_t *request,
    citius_sign_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->signature, 64); /* stub: 64-byte zero sig */
}

CITIUS_RV citius_verify(
    const citius_verify_request_t *request,
    citius_verify_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    response->valid = 1; /* Stub: always valid */
    return CITIUS_OK;
}

CITIUS_RV citius_digest_sign(
    const citius_digest_sign_request_t *request,
    citius_digest_sign_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->signature, 64);
}

CITIUS_RV citius_digest_verify(
    const citius_digest_verify_request_t *request,
    citius_digest_verify_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    response->valid = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_generate_mac(
    const citius_generate_mac_request_t *request,
    citius_generate_mac_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->mac, 32); /* stub: 32-byte zero tag */
}

CITIUS_RV citius_verify_mac(
    const citius_verify_mac_request_t *request,
    citius_verify_mac_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    response->valid = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_digest(
    const citius_digest_request_t *request,
    citius_digest_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->digest, 32);
}

CITIUS_RV citius_xof(
    const citius_xof_request_t *request,
    citius_xof_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    size_t len = request->output_length_bytes > 0
                 ? request->output_length_bytes : 32;
    return fill_output(&response->output, len);
}

CITIUS_RV citius_generate_random(
    const citius_generate_random_request_t *request,
    citius_generate_random_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    response->provider_id = "stub";
    return fill_output(&response->random_bytes, request->num_bytes);
}

CITIUS_RV citius_seed_random(
    const citius_seed_random_request_t *request,
    citius_seed_random_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    response->message = NULL;
    return CITIUS_OK;
}

/* =========================================================================
 * Key establishment  (DeriveKey, KeyAgreement, Encapsulate/Decapsulate, Wrap/Unwrap)
 * ========================================================================= */

CITIUS_RV citius_derive_key(
    const citius_derive_key_request_t *request,
    citius_derive_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    int idx = key_register(request->derived_key_name);
    if (idx < 0) return CITIUS_OUT_OF_MEMORY;
    response->success      = 1;
    response->message      = NULL;
    response->key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_encapsulate_key(
    const citius_encapsulate_key_request_t *request,
    citius_encapsulate_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    int idx = key_register(request->shared_secret_name);
    if (idx < 0) return CITIUS_OUT_OF_MEMORY;
    response->key_metadata = g_keys[idx].meta;
    /* Stub: 1088-byte zero ciphertext (ML-KEM-768 ct size) */
    return fill_output(&response->ciphertext, 1088);
}

CITIUS_RV citius_decapsulate_key(
    const citius_decapsulate_key_request_t *request,
    citius_decapsulate_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    int idx = key_register(request->shared_secret_name);
    if (idx < 0) return CITIUS_OUT_OF_MEMORY;
    response->success       = 1;
    response->key_metadata  = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_key_agreement(
    const citius_key_agreement_request_t *request,
    citius_key_agreement_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    int idx = key_register(request->shared_secret_name);
    if (idx < 0) return CITIUS_OUT_OF_MEMORY;
    response->success       = 1;
    response->message       = NULL;
    response->key_metadata  = g_keys[idx].meta;
    return CITIUS_OK;
}

CITIUS_RV citius_wrap_key(
    const citius_wrap_key_request_t *request,
    citius_wrap_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->wrapped_key, 40); /* stub: 40 zero bytes */
}

CITIUS_RV citius_unwrap_key(
    const citius_unwrap_key_request_t *request,
    citius_unwrap_key_response_t      *response)
{
    if (!request || !response)   return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    int idx = key_register(request->unwrapped_key_name);
    if (idx < 0) return CITIUS_OUT_OF_MEMORY;
    response->success      = 1;
    response->message      = NULL;
    response->key_metadata = g_keys[idx].meta;
    return CITIUS_OK;
}

/* =========================================================================
 * Streaming operations — opaque context backed by heap allocation
 * ========================================================================= */

struct citius_op_ctx_s {
    int active;
};

static citius_op_ctx_t make_ctx(void)
{
    struct citius_op_ctx_s *ctx = malloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->active  = 1;
    return ctx;
}

CITIUS_RV citius_op_ctx_free(citius_op_ctx_t ctx)
{
    if (ctx) free(ctx);
    return CITIUS_OK;
}

/* Generic init helper */
static CITIUS_RV streaming_init(
    citius_op_ctx_t       *ctx_out)
{
    if (!ctx_out) return CITIUS_NULL_ARGUMENT;
    *ctx_out = make_ctx();
    if (!*ctx_out) return CITIUS_OUT_OF_MEMORY;
    return CITIUS_OK;
}

/* ----- Multi-part encryption --------------------------------------------- */

CITIUS_RV citius_encrypt_init(
    const citius_encrypt_init_request_t *request,
    citius_encrypt_init_response_t      *response,
    citius_op_ctx_t                     *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_encrypt_update(
    citius_op_ctx_t                        ctx,
    const citius_encrypt_update_request_t *request,
    citius_encrypt_update_response_t      *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->ciphertext_chunk, request->plaintext_chunk.length);
}

CITIUS_RV citius_encrypt_final(
    citius_op_ctx_t                       ctx,
    const citius_encrypt_final_request_t *request,
    citius_encrypt_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->ciphertext_final, 16); /* tag */
}

/* ----- Multi-part decryption --------------------------------------------- */

CITIUS_RV citius_decrypt_init(
    const citius_decrypt_init_request_t *request,
    citius_decrypt_init_response_t      *response,
    citius_op_ctx_t                     *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_decrypt_update(
    citius_op_ctx_t                        ctx,
    const citius_decrypt_update_request_t *request,
    citius_decrypt_update_response_t      *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->plaintext_chunk, request->ciphertext_chunk.length);
}

CITIUS_RV citius_decrypt_final(
    citius_op_ctx_t                       ctx,
    const citius_decrypt_final_request_t *request,
    citius_decrypt_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->plaintext_final, 0);
}

/* ----- Multi-part signing ------------------------------------------------- */

CITIUS_RV citius_sign_init(
    const citius_sign_init_request_t *request,
    citius_sign_init_response_t      *response,
    citius_op_ctx_t                  *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_sign_update(
    citius_op_ctx_t                     ctx,
    const citius_sign_update_request_t *request,
    citius_sign_update_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_sign_final(
    citius_op_ctx_t                    ctx,
    const citius_sign_final_request_t *request,
    citius_sign_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->signature, 64);
}

/* ----- Multi-part verification -------------------------------------------- */

CITIUS_RV citius_verify_init(
    const citius_verify_init_request_t *request,
    citius_verify_init_response_t      *response,
    citius_op_ctx_t                    *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_verify_update(
    citius_op_ctx_t                       ctx,
    const citius_verify_update_request_t *request,
    citius_verify_update_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_verify_final(
    citius_op_ctx_t                      ctx,
    const citius_verify_final_request_t *request,
    citius_verify_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    response->valid = 1;
    return CITIUS_OK;
}

/* ----- Streaming digest ---------------------------------------------------- */

CITIUS_RV citius_digest_init(
    const citius_digest_init_request_t *request,
    citius_digest_init_response_t      *response,
    citius_op_ctx_t                    *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) {
        response->success              = (rv == CITIUS_OK);
        response->selected_template_id = NULL;
    }
    return rv;
}

CITIUS_RV citius_digest_update(
    citius_op_ctx_t                       ctx,
    const citius_digest_update_request_t *request,
    citius_digest_update_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_digest_key(
    citius_op_ctx_t                    ctx,
    const citius_digest_key_request_t *request,
    citius_digest_key_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_digest_final(
    citius_op_ctx_t                      ctx,
    const citius_digest_final_request_t *request,
    citius_digest_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->digest, 32);
}

/* ----- Streaming XOF -------------------------------------------------------- */

CITIUS_RV citius_xof_init(
    const citius_xof_init_request_t *request,
    citius_xof_init_response_t      *response,
    citius_op_ctx_t                 *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) {
        response->success              = (rv == CITIUS_OK);
        response->selected_template_id = NULL;
    }
    return rv;
}

CITIUS_RV citius_xof_update(
    citius_op_ctx_t                    ctx,
    const citius_xof_update_request_t *request,
    citius_xof_update_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_xof_final(
    citius_op_ctx_t                   ctx,
    const citius_xof_final_request_t *request,
    citius_xof_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->output, response->output.capacity);
}

/* ----- Message-based AEAD encrypt ------------------------------------------ */

CITIUS_RV citius_message_encrypt_init(
    const citius_encrypt_message_init_request_t *request,
    citius_encrypt_message_init_response_t      *response,
    citius_op_ctx_t                              *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_message_encrypt(
    citius_op_ctx_t                          ctx,
    const citius_encrypt_message_request_t  *request,
    citius_encrypt_message_response_t       *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->ciphertext, request->plaintext.length + 16);
}

CITIUS_RV citius_message_encrypt_begin(
    citius_op_ctx_t                                ctx,
    const citius_encrypt_message_begin_request_t  *request,
    citius_encrypt_message_begin_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    zero_metadata(&response->partial_metadata);
    return CITIUS_OK;
}

CITIUS_RV citius_message_encrypt_next(
    citius_op_ctx_t                              ctx,
    const citius_encrypt_message_next_request_t *request,
    citius_encrypt_message_next_response_t      *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->ciphertext_chunk, request->plaintext_chunk.length);
}

CITIUS_RV citius_message_encrypt_final(
    citius_op_ctx_t                               ctx,
    const citius_encrypt_message_final_request_t *request,
    citius_encrypt_message_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->ciphertext_final, 16);
}

/* ----- Message-based AEAD decrypt ------------------------------------------ */

CITIUS_RV citius_message_decrypt_init(
    const citius_decrypt_message_init_request_t *request,
    citius_decrypt_message_init_response_t      *response,
    citius_op_ctx_t                              *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_message_decrypt(
    citius_op_ctx_t                          ctx,
    const citius_decrypt_message_request_t  *request,
    citius_decrypt_message_response_t       *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    size_t len = request->ciphertext.length > 16 ? request->ciphertext.length - 16 : 0;
    return fill_output(&response->plaintext, len);
}

CITIUS_RV citius_message_decrypt_begin(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_message_begin_request_t  *request,
    citius_decrypt_message_begin_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_message_decrypt_next(
    citius_op_ctx_t                              ctx,
    const citius_decrypt_message_next_request_t *request,
    citius_decrypt_message_next_response_t      *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->plaintext_chunk, request->ciphertext_chunk.length);
}

CITIUS_RV citius_message_decrypt_final(
    citius_op_ctx_t                               ctx,
    const citius_decrypt_message_final_request_t *request,
    citius_decrypt_message_final_response_t      *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->plaintext_final, 0);
}

/* ----- Message-based signing ------------------------------------------------ */

CITIUS_RV citius_sign_message_init(
    const citius_sign_message_init_request_t *request,
    citius_sign_message_init_response_t      *response,
    citius_op_ctx_t                           *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_sign_message(
    citius_op_ctx_t                       ctx,
    const citius_sign_message_request_t  *request,
    citius_sign_message_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->signature, 64);
}

CITIUS_RV citius_sign_message_begin(
    citius_op_ctx_t                             ctx,
    const citius_sign_message_begin_request_t  *request,
    citius_sign_message_begin_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_sign_message_next(
    citius_op_ctx_t                            ctx,
    const citius_sign_message_next_request_t  *request,
    citius_sign_message_next_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_sign_message_final(
    citius_op_ctx_t                             ctx,
    const citius_sign_message_final_request_t  *request,
    citius_sign_message_final_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    return fill_output(&response->signature, 64);
}

/* ----- Message-based verification -------------------------------------------- */

CITIUS_RV citius_verify_message_init(
    const citius_verify_message_init_request_t *request,
    citius_verify_message_init_response_t      *response,
    citius_op_ctx_t                              *ctx_out)
{
    (void)request;
    CITIUS_RV rv = streaming_init(ctx_out);
    if (response) response->success = (rv == CITIUS_OK);
    return rv;
}

CITIUS_RV citius_verify_message(
    citius_op_ctx_t                         ctx,
    const citius_verify_message_request_t  *request,
    citius_verify_message_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    response->valid = 1; /* Stub: always valid */
    return CITIUS_OK;
}

CITIUS_RV citius_verify_message_begin(
    citius_op_ctx_t                               ctx,
    const citius_verify_message_begin_request_t  *request,
    citius_verify_message_begin_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_verify_message_next(
    citius_op_ctx_t                              ctx,
    const citius_verify_message_next_request_t  *request,
    citius_verify_message_next_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_verify_message_final(
    citius_op_ctx_t                               ctx,
    const citius_verify_message_final_request_t  *request,
    citius_verify_message_final_response_t       *response)
{
    (void)request;
    if (!ctx || !response) return CITIUS_NULL_ARGUMENT;
    zero_metadata(&response->metadata);
    response->valid = 1;
    return CITIUS_OK;
}

/* =========================================================================
 * Dual-function Update operations
 * ========================================================================= */

CITIUS_RV citius_digest_encrypt_update(
    citius_op_ctx_t                                ctx,
    const citius_digest_encrypt_update_request_t  *request,
    citius_digest_encrypt_update_response_t       *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->ciphertext_chunk, request->plaintext_chunk.length);
}

CITIUS_RV citius_decrypt_digest_update(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_digest_update_request_t  *request,
    citius_decrypt_digest_update_response_t       *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->plaintext_chunk, request->ciphertext_chunk.length);
}

CITIUS_RV citius_sign_encrypt_update(
    citius_op_ctx_t                              ctx,
    const citius_sign_encrypt_update_request_t  *request,
    citius_sign_encrypt_update_response_t       *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->ciphertext_chunk, request->plaintext_chunk.length);
}

CITIUS_RV citius_decrypt_verify_update(
    citius_op_ctx_t                                ctx,
    const citius_decrypt_verify_update_request_t  *request,
    citius_decrypt_verify_update_response_t       *response)
{
    if (!ctx || !request || !response) return CITIUS_NULL_ARGUMENT;
    return fill_output(&response->plaintext_chunk, request->ciphertext_chunk.length);
}

/* =========================================================================
 * Discovery  (AlgorithmDiscoveryService — stub has no template catalogue)
 * ========================================================================= */

CITIUS_RV citius_list_templates(
    const citius_list_templates_request_t *request,
    citius_list_templates_response_t      *response)
{
    (void)request;
    if (!response) return CITIUS_NULL_ARGUMENT;
    response->templates       = NULL;
    response->template_count  = 0;
    response->next_page_token = NULL;
    return CITIUS_OK;
}

CITIUS_RV citius_get_template(
    const citius_get_template_request_t *request,
    citius_get_template_response_t      *response)
{
    (void)request;
    if (!response) return CITIUS_NULL_ARGUMENT;
    return CITIUS_TEMPLATE_NOT_FOUND; /* Stub has no template catalogue */
}

CITIUS_RV citius_list_scopes(
    const citius_list_scopes_request_t  *request,
    citius_list_scopes_response_t       *response)
{
    (void)request;
    if (!response) return CITIUS_NULL_ARGUMENT;
    response->scopes.scopes = NULL;
    response->scopes.count  = 0;
    return CITIUS_OK;
}

/* =========================================================================
 * Crypto policy management  (CryptoPolicyService — stub: in-memory array)
 * ========================================================================= */

static int policy_find(const char *name)
{
    if (!name) return -1;
    for (int i = 0; i < STUB_MAX_POLICIES; ++i) {
        if (g_policies[i].in_use && strcmp(g_policies[i].name_buf, name) == 0) return i;
    }
    return -1;
}

CITIUS_RV citius_create_crypto_policy(
    const citius_create_crypto_policy_request_t *request,
    citius_create_crypto_policy_response_t      *response)
{
    if (!request || !request->name || !response) return CITIUS_NULL_ARGUMENT;
    if (policy_find(request->name) >= 0) {
        response->success = 0;
        response->message = "already exists";
        return CITIUS_POLICY_ALREADY_EXISTS;
    }
    for (int i = 0; i < STUB_MAX_POLICIES; ++i) {
        if (!g_policies[i].in_use) {
            g_policies[i].in_use = 1;
            snprintf(g_policies[i].name_buf, sizeof(g_policies[i].name_buf), "%s", request->name);
            snprintf(g_policies[i].doc_buf, sizeof(g_policies[i].doc_buf), "%s",
                     request->policy_document ? request->policy_document : "");
            response->success = 1;
            response->message = NULL;
            return CITIUS_OK;
        }
    }
    return CITIUS_OUT_OF_MEMORY;
}

CITIUS_RV citius_read_crypto_policy(
    const citius_read_crypto_policy_request_t *request,
    citius_read_crypto_policy_response_t      *response)
{
    if (!request || !response) return CITIUS_NULL_ARGUMENT;
    int idx = policy_find(request->name);
    if (idx < 0) return CITIUS_POLICY_NOT_FOUND;
    response->name            = g_policies[idx].name_buf;
    response->policy_document = g_policies[idx].doc_buf;
    return CITIUS_OK;
}

CITIUS_RV citius_delete_crypto_policy(
    const citius_delete_crypto_policy_request_t *request,
    citius_delete_crypto_policy_response_t      *response)
{
    if (!request || !response) return CITIUS_NULL_ARGUMENT;
    int idx = policy_find(request->name);
    if (idx < 0) return CITIUS_POLICY_NOT_FOUND;
    g_policies[idx].in_use = 0;
    response->success = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_update_crypto_policy(
    const citius_update_crypto_policy_request_t *request,
    citius_update_crypto_policy_response_t      *response)
{
    if (!request || !response) return CITIUS_NULL_ARGUMENT;
    int idx = policy_find(request->name);
    if (idx < 0) return CITIUS_POLICY_NOT_FOUND;
    snprintf(g_policies[idx].doc_buf, sizeof(g_policies[idx].doc_buf), "%s",
             request->policy_document ? request->policy_document : "");
    response->success = 1;
    response->message = NULL;
    return CITIUS_OK;
}

CITIUS_RV citius_list_crypto_policies(
    const citius_list_crypto_policies_request_t *request,
    citius_list_crypto_policies_response_t      *response)
{
    (void)request;
    if (!response) return CITIUS_NULL_ARGUMENT;
    size_t count = 0;
    for (int i = 0; i < STUB_MAX_POLICIES; ++i) {
        if (g_policies[i].in_use) {
            g_policy_list_buf[count].name       = g_policies[i].name_buf;
            g_policy_list_buf[count].created_at = NULL;
            g_policy_list_buf[count].updated_at = NULL;
            count++;
        }
    }
    response->policies        = g_policy_list_buf;
    response->policy_count    = count;
    response->next_page_token = NULL;
    return CITIUS_OK;
}

CITIUS_RV citius_evaluate_policy(
    const citius_evaluate_policy_request_t *request,
    citius_evaluate_policy_response_t      *response)
{
    if (!request || !response) return CITIUS_NULL_ARGUMENT;
    memset(response, 0, sizeof(*response));
    response->allowed       = 1; /* Stub: always allow */
    response->denial_reason = CITIUS_POLICY_DENIAL_REASON_UNSPECIFIED;
    response->message       = NULL;
    return CITIUS_OK;
}

CITIUS_RV citius_batch_evaluate_policy(
    const citius_batch_evaluate_policy_request_t *request,
    citius_batch_evaluate_policy_response_t      *response)
{
    if (!request || !response) return CITIUS_NULL_ARGUMENT;

    size_t count = request->evaluation_count;
    if (count > STUB_MAX_BATCH) count = STUB_MAX_BATCH;

    int32_t allowed_count = 0;
    for (size_t i = 0; i < count; ++i) {
        CITIUS_RV rv = citius_evaluate_policy(&request->evaluations[i], &g_batch_eval_buf[i]);
        if (rv != CITIUS_OK) return rv;
        if (g_batch_eval_buf[i].allowed) allowed_count++;
    }

    response->results       = g_batch_eval_buf;
    response->result_count  = count;
    response->allowed_count = allowed_count;
    response->denied_count  = (int32_t)count - allowed_count;
    return CITIUS_OK;
}

/* =========================================================================
 * ProviderService — type catalog functions
 * ========================================================================= */

CITIUS_RV citius_provider_list_types(
    const citius_provider_type_filter_t  *filter,
    citius_provider_info_t               *providers_out,
    size_t                               *count_inout)
{
    (void)filter;
    if (!count_inout) return CITIUS_NULL_ARGUMENT;
    /* Stub exposes one provider type: itself */
    if (*count_inout < 1) { *count_inout = 1; return CITIUS_BUFFER_TOO_SMALL; }
    if (providers_out) {
        memset(providers_out, 0, sizeof(*providers_out));
        providers_out->provider_id   = "stub";
        providers_out->display_name  = "Citius Stub Provider";
        providers_out->provider_type = PROVIDER_TYPE_SOFTWARE;
    }
    *count_inout = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_provider_get_type(
    const char             *provider_id,
    citius_provider_info_t *info_out)
{
    if (!provider_id || !info_out) return CITIUS_NULL_ARGUMENT;
    if (strcmp(provider_id, "stub") != 0) return CITIUS_PROVIDER_NOT_FOUND;
    memset(info_out, 0, sizeof(*info_out));
    info_out->provider_id   = "stub";
    info_out->display_name  = "Citius Stub Provider";
    info_out->provider_type = PROVIDER_TYPE_SOFTWARE;
    return CITIUS_OK;
}

/* =========================================================================
 * ProviderService — instance management
 * ========================================================================= */

CITIUS_RV citius_provider_instance_register(
    const citius_provider_instance_t *instance,
    citius_provider_instance_t       *registered_out)
{
    if (!instance) return CITIUS_NULL_ARGUMENT;
    if (registered_out) *registered_out = *instance;
    return CITIUS_OK;
}

CITIUS_RV citius_provider_instance_list(
    const citius_instance_filter_t *filter,
    citius_provider_instance_t     *instances_out,
    size_t                         *count_inout)
{
    (void)filter;
    if (!count_inout) return CITIUS_NULL_ARGUMENT;
    if (*count_inout < 1) { *count_inout = 1; return CITIUS_BUFFER_TOO_SMALL; }
    if (instances_out) {
        memset(instances_out, 0, sizeof(*instances_out));
        instances_out->instance_id  = "stub";
        instances_out->provider_id  = "stub";
        instances_out->display_name = "Citius Stub Provider";
        instances_out->enabled      = 1;
    }
    *count_inout = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_provider_instance_get(
    const char                 *instance_id,
    citius_provider_instance_t *instance_out)
{
    if (!instance_id || !instance_out) return CITIUS_NULL_ARGUMENT;
    if (strcmp(instance_id, "stub") != 0) return CITIUS_PROVIDER_NOT_FOUND;
    memset(instance_out, 0, sizeof(*instance_out));
    instance_out->instance_id  = "stub";
    instance_out->provider_id  = "stub";
    instance_out->display_name = "Citius Stub Provider";
    instance_out->enabled      = 1;
    return CITIUS_OK;
}

CITIUS_RV citius_provider_instance_update(
    const citius_provider_instance_t *instance,
    citius_provider_instance_t       *updated_out,
    const char                      **message_out)
{
    if (!instance) return CITIUS_NULL_ARGUMENT;
    if (updated_out) *updated_out = *instance;
    if (message_out) *message_out = NULL;
    return CITIUS_OK; /* Stub: accept any update */
}

CITIUS_RV citius_provider_instance_delete(
    const char           *instance_id,
    const char          **message_out)
{
    (void)instance_id;
    if (message_out) *message_out = NULL;
    return CITIUS_OK; /* Stub: accept any delete */
}

/* =========================================================================
 * ProviderService — provider matching
 * ========================================================================= */

CITIUS_RV citius_provider_match(
    const citius_provider_match_request_t *request,
    citius_matched_provider_t             *matches_out,
    size_t                                *count_inout)
{
    (void)request;
    if (!count_inout) return CITIUS_NULL_ARGUMENT;
    if (*count_inout < 1) { *count_inout = 1; return CITIUS_BUFFER_TOO_SMALL; }
    if (matches_out) {
        memset(matches_out, 0, sizeof(*matches_out));
        matches_out->instance.instance_id  = "stub";
        matches_out->instance.provider_id  = "stub";
        matches_out->instance.display_name = "Citius Stub Provider";
        matches_out->instance.enabled      = 1;
        matches_out->match_score           = 1;
    }
    *count_inout = 1;
    return CITIUS_OK;
}
