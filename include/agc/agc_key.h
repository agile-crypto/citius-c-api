/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_key.h — KeyManagementService (11 RPCs; api/services/key_management_service.proto).
 *
 * Every request struct below is derived field-for-field from the real proto
 * message, verified directly against api/messages/key_management.proto (not
 * against an earlier design draft). Where a field exists in this header but
 * not in the proto, or vice versa, it is a bug -- see
 * RECONCILIATION_PLAN.md §3.1 and conformance/DIVERGENCES.yaml (commit 12)
 * for the only intentional exceptions.
 *
 * CALLER-ALLOCATED RECORDS
 * ------------------------
 * KeyMetadata, MigrationResult, ValidateKeyOperationResponse and
 * ImplementationProperties are public records with no lifecycle of their
 * own, so they are caller-allocated structs defined here, not opaque
 * handles (docs/agc_crypto.md). The key itself never leaves the key store,
 * which stays behind agc_ctx. Only the iterator agc_key_iter remains a
 * library-owned handle, by the rule for objects with a lifecycle.
 *
 * STORAGE CONTRACT (applies to every record with a `storage` field)
 * ------------------------------------------------------------------
 * Scalars are written inline. Every variable-length value -- strings,
 * public-key bytes, map items and their strings, option arrays -- is COPIED
 * into the caller-provided `storage` region, and the record's pointers are
 * set into it. `storage_used` receives the bytes consumed. The record is
 * valid for as long as `storage` is; nothing in it references library
 * memory. A by-value copy of the record shares the storage.
 *
 * Size query: if `storage.data` is NULL or `storage.cap` is smaller than
 * required, the call returns AGC_ERR_BUFFER_TOO_SMALL with `storage_used`
 * set to the requirement and writes no other field of the record. For
 * read-only operations (read_key, key_iter_next, validate_key_operation)
 * the requirement is exact and nothing else happens. For operations that
 * create or change a key (create, rotate, transform, update_policy,
 * migrate, import, export) the size query does NOT perform the operation:
 * the requirement returned is an upper bound computed from the request,
 * the policy and the selected template and provider, so the operation is
 * never performed for a caller that cannot store its result, and
 * `storage_used` after the real call may be smaller than the bound.
 *
 * The caller MUST AGC_INIT() every record before the call and may then
 * set only `storage`.
 *
 *
 */

#ifndef AGC_KEY_H
#define AGC_KEY_H

#include "agc_core.h"
#include "agc_scope.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ImplementationProperties (api/types/implementation.proto)
 *
 * Embedded by value in agc_key_info. Carries no storage of its own: its
 * one string lives in the enclosing record's storage.
 * -------------------------------------------------------------------------- */

typedef struct agc_impl_props {
    int               fips_certified;
    agc_fips140_level fips_level;
    agc_tribool       formally_verified;
    agc_tribool       memory_safe_language;
    const char       *implementation_language;  /* NUL-terminated, in the enclosing record's storage; may be "" */
    agc_tribool       constant_time;
    agc_tribool       side_channel_hardened;
    agc_tribool       hardware_accelerated;
} agc_impl_props;

/* --------------------------------------------------------------------------
 * KeyMetadata (api/messages/key_management.proto)
 * -------------------------------------------------------------------------- */

/* Everything the service knows about one key version. Caller-allocated;
 * see STORAGE CONTRACT. Never contains key material: p_public_key is the
 * public half of an asymmetric key and nothing else. */
typedef struct agc_key_info {
    size_t                  struct_size;

    const char             *key_name;            /* NUL-terminated, in storage */
    uint32_t                version;
    const char             *key_id;          /* NUL-terminated, in storage */
    const char             *template_id;     /* NUL-terminated, in storage */
    const char             *provider_id;     /* NUL-terminated, in storage */
    const char             *policy_name;          /* NUL-terminated, in storage */
    agc_timestamp           created_time;
    agc_timestamp           updated_time;
    int                     extractable;
    agc_key_lifecycle_state lifecycle_state;

    /* The scope specification the key was created with. Inline; the
     * additional_properties items and strings of its arm are in storage. */
    agc_scope_spec          scope_spec;

    /* Public-key material for asymmetric keys.
     * NULL with public_key_len 0 when the key has none: symmetric keys, or
     * an asymmetric key whose provider did not surface it. */
    const uint8_t          *p_public_key;    /* in storage */
    size_t                  public_key_len;
    agc_key_format          public_key_format;

    /* provider_metadata (map<string, string>): items and strings in storage. */
    agc_kv_list             provider_metadata;

    /* Properties of the implementation serving this key. */
    agc_impl_props          implementation_props;

    agc_buf                 storage;         /* IN: caller region for every variable-length value */
    size_t                  storage_used;    /* OUT: bytes consumed, or required on AGC_ERR_BUFFER_TOO_SMALL */
} agc_key_info;

/* --------------------------------------------------------------------------
 * CreateKey
 * -------------------------------------------------------------------------- */

typedef struct agc_create_key_params {
    size_t struct_size;

    const char *key_name;      /* REQUIRED */
    const char *policy_name;    /* REQUIRED */
    const char *provider_id; /* NULL => policy selects */
    agc_kv_list provider_configuration;

    const agc_scope_spec scope_spec;  /* REQUIRED */
    const char           *template_id; /* NULL => policy selects */

    const agc_provider_requirements *provider_requirements; /* NULL => no filter */
} agc_create_key_params;

/* CreateKeyResponse has 5 fields; success/message collapse into agc_rc (D4).
 * implementation_properties is out_key->implementation. security_guarantees
 * is not exposed by this reconciliation: it is reachable via the key's
 * template, never duplicated. */
AGC_API agc_rc agc_create_key(agc_ctx *ctx, const agc_create_key_params *params,
                               agc_key_info *out_key);

/* --------------------------------------------------------------------------
 * ReadKey / ListKeys
 * -------------------------------------------------------------------------- */

/* version == 0 reads the latest (proto: optional uint32 version, absent =
 * latest; versions start at 1, so 0 is an unambiguous sentinel). */
AGC_API agc_rc agc_read_key(agc_ctx *ctx, const char *key_name, uint32_t version,
                             agc_key_info *out_key);

typedef struct agc_list_keys_params {
    size_t struct_size;
    const agc_scope_spec   *scope_spec;      /* NULL => no scope filter */
    const char              *provider_id;     /* NULL => any */
    const char              *policy;          /* NULL => any */
    agc_key_lifecycle_state  lifecycle_state; /* UNSPECIFIED => any */
    uint32_t                 page_size;       /* 0 => implementation default */
} agc_list_keys_params;

/* The iterator is a library-owned handle (it has a lifecycle: paging
 * bookkeeping, D12); the records it yields are caller-allocated. */
AGC_API agc_rc agc_list_keys(agc_ctx *ctx, const agc_list_keys_params *params,
                              agc_key_iter **out_iter);

/* Fills *out with the next key. On AGC_ERR_BUFFER_TOO_SMALL the cursor does
 * not advance, so the caller may resize out->storage and call again for the
 * same key. AGC_ERR_ITERATOR_EXHAUSTED at the end. A caller may reuse one
 * record and one storage region across the whole loop. */
AGC_API agc_rc agc_key_iter_next(agc_key_iter *it, agc_key_info *out);
AGC_API void   agc_key_iter_free(agc_key_iter *it);

/* --------------------------------------------------------------------------
 * DeleteKey
 * -------------------------------------------------------------------------- */

/* Zeroizes key material in the provider -- irreversible */
AGC_API agc_rc agc_delete_key(agc_ctx *ctx, const char *key_name);

/* --------------------------------------------------------------------------
 * RotateKey
 * -------------------------------------------------------------------------- */

/* RotateKeyRequest is `{name}` on the wire.
 * *out_new_key describes the new version's metadata. */
AGC_API agc_rc agc_rotate_key(agc_ctx *ctx, const char *key_name, agc_key_info *out_new_key);

/* --------------------------------------------------------------------------
 * TransformKey 
 * -------------------------------------------------------------------------- */

typedef struct agc_transform_key_params {
    size_t struct_size;
    const char            *key_name;             /* REQUIRED */
    int                    retain_key_bytes; /* 0 = regenerate (default), 1 = keep material */
    const agc_scope_spec  *scope_spec;       /* intent-based target */
    const char            *template_id;      /* explicit target; NULL => policy selects */
} agc_transform_key_params;

AGC_API agc_rc agc_transform_key(agc_ctx *ctx, const agc_transform_key_params *params,
                                  agc_key_info *out_key);

/* --------------------------------------------------------------------------
 * UpdateKeyPolicy
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_update_key_policy(agc_ctx *ctx, const char *key_name, const char *new_policy_name,
                                      agc_key_info *out_key);

/* --------------------------------------------------------------------------
 * MigrateKey
 * -------------------------------------------------------------------------- */

/* MigrateKeyRequest.target is a required oneof {target_instance_id=2,
 * provider_target=3}; tags are those proto field numbers (verified,
 * registered in conformance/tier1c_oneof_tags.py). */
typedef enum agc_migrate_target_kind {
    AGC_MIGRATE_TARGET_NONE     = 0,  /* invalid: the oneof is required */
    AGC_MIGRATE_TARGET_INSTANCE = 2,
    AGC_MIGRATE_TARGET_PROVIDER = 3
    AGC_ENUM32(agc_migrate_target_kind)
} agc_migrate_target_kind;

typedef struct agc_provider_target {
    const char *provider_id;
    agc_kv_list configuration;
} agc_provider_target;

typedef struct agc_migrate_target {
    agc_migrate_target_kind kind;
    union {
        const char          *instance_id;
        agc_provider_target  provider;
    } u;
} agc_migrate_target;

typedef struct agc_migrate_key_params {
    size_t struct_size;
    const char            *key_name;         /* REQUIRED */
    agc_migrate_target     target;       /* REQUIRED */
    agc_migration_strategy strategy;     /* REQUIRED; UNSPECIFIED is rejected */
    const agc_scope_spec  *scope_spec;   /* optional algorithm change during migration */
    const char            *template_id;  /* optional explicit algorithm change */
} agc_migrate_key_params;

/* MigrationResult plus ArchivedKeyInfo. Caller-allocated; see STORAGE
 * CONTRACT. */
typedef struct agc_migration_report {
    size_t                 struct_size;
    agc_migration_strategy strategy_used;
    int                    key_bytes_preserved;
    const char            *source_provider_id;    /* NUL-terminated, in storage */
    const char            *source_instance_id;    /* NUL-terminated, in storage */
    const char            *target_provider_id;    /* NUL-terminated, in storage */
    const char            *target_instance_id;    /* NUL-terminated, in storage */
    int has_target_implementation_properties;     /* OUT: true if target_implementation_properties is available */
    agc_impl_props        *target_implementation_properties; /* optional, NIL means caller does not want it;
                                                             non-NULL means the caller wants it. */
    const char            *wrapping_key_name;     /* NUL-terminated, in storage; "" if none */

    /* ArchivedKeyInfo -- present only for REKEY_AND_ARCHIVE. When
     * has_archived_key is 0 the three fields below are NULL / absent. */
    int                    has_archived_key;
    const char            *archived_key_name;     /* NUL-terminated, in storage */
    const char            *archived_provider_id;  /* NUL-terminated, in storage */
    agc_timestamp          archived_expiration;

    agc_buf                storage;               /* IN */
    size_t                 storage_used;          /* OUT */
} agc_migration_report;

/* MigrateKeyResponse. Caller-allocated. Two records, each with its own
 * storage region so that a caller wanting only one of them pays for only
 * that one: leave the other's storage {NULL,0} to opt out of it entirely,
 * in which case that record is not written and its size is not reported.
 * Opting out of both is legal and reduces the call to "migrate, tell me
 * only whether it worked". */
typedef struct agc_migrate_key_response {
    size_t               struct_size;

    /* The key after migration: new provider, and a new version when the
     * strategy rekeyed. Its storage follows the STORAGE CONTRACT. */
    agc_key_info         key_info;

    /* What the migration actually did. Its storage follows the STORAGE
     * CONTRACT. The strategy reported here may differ from the one
     * requested when the provider could not serve it. */
    agc_migration_report report;
} agc_migrate_key_response;

/* Both records are size-checked before the migration is attempted; on
 * AGC_ERR_BUFFER_TOO_SMALL each requested record's storage_used holds its
 * bound and no key has been touched. */
AGC_API agc_rc agc_migrate_key(agc_ctx *ctx, const agc_migrate_key_params *params,
                                agc_migrate_key_response *resp);

/* --------------------------------------------------------------------------
 * ValidateKeyOperation — pre-flight feasibility
 * -------------------------------------------------------------------------- */

typedef enum agc_validate_intent_kind {
    AGC_VALIDATE_INTENT_NONE      = 0,  /* invalid: the oneof is required */
    AGC_VALIDATE_INTENT_TRANSFORM = 2,
    AGC_VALIDATE_INTENT_MIGRATE   = 3
    AGC_ENUM32(agc_validate_intent_kind)
} agc_validate_intent_kind;

typedef struct agc_validate_transform_intent {
    const agc_scope_spec *scope_spec;
    const char           *template_id;
    int                   prefer_retain_bytes;
} agc_validate_transform_intent;

/* ValidateMigrateIntent.target is a oneof WITHOUT `required` in the proto,
 * so "neither" is legal there and means "assess all targets". Tags are the
 * proto field numbers (1, 2); AGC_VALIDATE_MIGRATE_TARGET_ANY (0) is a
 * legal, meaningful tag here -- unlike every required-oneof NONE=0 in this
 * API, it does not mean "invalid". */
typedef enum agc_validate_migrate_target_kind {
    AGC_VALIDATE_MIGRATE_TARGET_ANY      = 0,
    AGC_VALIDATE_MIGRATE_TARGET_INSTANCE = 1,
    AGC_VALIDATE_MIGRATE_TARGET_PROVIDER = 2
    AGC_ENUM32(agc_validate_migrate_target_kind)
} agc_validate_migrate_target_kind;

typedef struct agc_validate_migrate_intent {
    agc_validate_migrate_target_kind target_kind;
    const char                      *target_id;          /* instance or provider id */
    agc_migration_strategy           preferred_strategy; /* UNSPECIFIED => assess all */
} agc_validate_migrate_intent;

typedef struct agc_validate_key_op_params {
    size_t                   struct_size;
    const char              *key_name;   /* REQUIRED */
    agc_validate_intent_kind kind;   /* REQUIRED */
    union {
        agc_validate_transform_intent transform;
        agc_validate_migrate_intent   migrate;
    } u;
} agc_validate_key_op_params;

/* One StrategyOption. For TRANSFORM intents `strategy` is
 * AGC_MIGRATION_STRATEGY_UNSPECIFIED and feasibility rides on
 * feasible / infeasibility_reason, exactly as the proto documents. */
typedef struct agc_strategy_option {
    agc_migration_strategy strategy;
    int                    feasible;
    const char            *infeasibility_reason;  /* NUL-terminated, in the report's storage; "" if feasible */
    int32_t                complexity_level;
} agc_strategy_option;

typedef struct agc_key_state {
    const char *template_id;     /* NUL-terminated, in the report's storage */
    const char *provider_id;     /* NUL-terminated, in the report's storage */
    const char *instance_id;     /* NUL-terminated, in the report's storage */
    int         extractable;
    agc_provider_type provider_type;
    int has_implementation_properties;
    agc_impl_props *implementation_properties; /* optional, NULL means the caller does not want it;
                                                  non-null and has_implementation_properties false means 
                                                  the library cannot provide it. */
} agc_key_state;

/* ValidateKeyOperationResponse. Caller-allocated; see STORAGE CONTRACT. */
typedef struct agc_validate_key_op_response {
    size_t                 struct_size;

    /* KeyState (current_state, field 1). */
    agc_key_state          current_state;

    /* StrategyOption list (options, field 2): array in storage. */
    const agc_strategy_option *p_options;
    size_t                     option_count;

    agc_migration_strategy recommended_strategy;
    const char            *recommendation_reason;  /* NUL-terminated, in storage */

    agc_buf                storage;                /* IN */
    size_t                 storage_used;           /* OUT */
} agc_validate_key_op_response;

/* Read-only: performs no key operation. */
AGC_API agc_rc agc_validate_key_operation(agc_ctx *ctx, const agc_validate_key_op_params *params,
                                           agc_validate_key_op_response *out_report);

/* --------------------------------------------------------------------------
 * ExportKey / ImportKey
 * -------------------------------------------------------------------------- */

typedef struct agc_export_key_params {
    size_t          struct_size;
    const char     *key_name;              /* REQUIRED */
    agc_key_format  format;            /* REQUIRED */
    const char     *wrapping_key_name; /* REQUIRED when format == WRAPPED */
} agc_export_key_params;

/* ExportKeyResponse. Caller-allocated. The key material goes into its own
 * region, deliberately separate from key_info.storage: it is the one output
 * in this header that is secret, and it must be placeable in locked memory
 * and zeroized independently of the public record next to it. */
typedef struct agc_export_key_response {
    size_t          struct_size;

    /* Exported key material in actual_format. Two-call: if material.data is
     * NULL or material.cap < required, AGC_ERR_BUFFER_TOO_SMALL with
     * material_len set to the requirement, nothing written. For
     * format == WRAPPED this is ciphertext under wrapping_key_name; for every
     * other format it is PLAINTEXT KEY MATERIAL. */
    agc_buf         material;        /* IN: caller region. OUT: written */
    size_t          material_len;    /* OUT: bytes written, or required */
    agc_key_format  actual_format;   /* OUT: may differ from params->format when the
                                        provider can only serve an equivalent one */

    /* Metadata of the exported key version. Its storage is sized and filled
     * under the STORAGE CONTRACT; set key_info.storage to {NULL,0} and leave
     * it there to opt out of the record entirely (key_info is then not
     * written and its size is not reported). */
    agc_key_info    key_info;
} agc_export_key_response;

/* SECURITY: the caller owns the exported material and MUST agc_secure_zero
 * it -- the library cannot know when the caller is finished with it, which
 * is precisely why the buffer is caller-owned. Both resp->material and
 * resp->key_info.storage (when requested) are size-checked before any
 * material is produced; on AGC_ERR_BUFFER_TOO_SMALL every length field is
 * set and no material has left the provider. */
AGC_API agc_rc agc_export_key(agc_ctx *ctx, const agc_export_key_params *params,
                               agc_export_key_response *resp);

typedef struct agc_import_key_params {
    size_t          struct_size;
    const char     *key_name;                /* REQUIRED */
    const char     *policy_name;
    agc_slice       key_material;        /* REQUIRED */
    agc_key_format  format;              /* REQUIRED */
    const char     *unwrapping_key_name; /* REQUIRED when format == WRAPPED */
    const char     *provider_id;
    agc_kv_list     provider_configuration;
    const char     *template_id;         /* REQUIRED by the proto */
} agc_import_key_params;

AGC_API agc_rc agc_import_key(agc_ctx *ctx, const agc_import_key_params *params,
                               agc_key_info *out_key);

#ifdef __cplusplus
}
#endif
#endif /* AGC_KEY_H */
