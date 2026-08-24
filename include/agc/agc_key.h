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
 * SELECTION MODES
 * ---------------
 * CreateKey/TransformKey support the proto's two selection modes in one
 * struct: set scope_spec (intent-based, recommended) or template_id
 * (explicit), or both -- when both are set they must agree, else
 * AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE. This is a struct with a documented
 * precedence rule rather than two functions, so an operator pinning a
 * template in policy does not require a call-site code change.
 */

#ifndef AGC_KEY_H
#define AGC_KEY_H

#include "agc_core.h"
#include "agc_scope.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * KeyMetadata accessors (api/messages/key_management.proto: KeyMetadata)
 * -------------------------------------------------------------------------- */

AGC_API void agc_key_info_free(agc_key_info *ki);

AGC_API const char             *agc_key_info_name(const agc_key_info *ki);
AGC_API uint32_t                agc_key_info_version(const agc_key_info *ki);
AGC_API const char             *agc_key_info_key_id(const agc_key_info *ki);
AGC_API const char             *agc_key_info_template_id(const agc_key_info *ki);
AGC_API const char             *agc_key_info_provider(const agc_key_info *ki);
AGC_API const char             *agc_key_info_policy(const agc_key_info *ki);
AGC_API agc_timestamp           agc_key_info_created_time(const agc_key_info *ki);
AGC_API agc_timestamp           agc_key_info_updated_time(const agc_key_info *ki);
AGC_API int                     agc_key_info_extractable(const agc_key_info *ki);
AGC_API agc_key_lifecycle_state agc_key_info_lifecycle_state(const agc_key_info *ki);

/* The scope specification the key was created with. Copied into *out. */
AGC_API agc_rc agc_key_info_scope_spec(const agc_key_info *ki, agc_scope_spec *out);

/* Public-key material for asymmetric keys (optional bytes on the wire).
 * AGC_ERR_INVALID_ARGUMENT if the key has none (symmetric keys, or an
 * asymmetric key whose provider did not surface it). Two-call convention. */
AGC_API agc_rc agc_key_info_public_key(const agc_key_info *ki, agc_buf out, size_t *out_len);
AGC_API agc_rc agc_key_info_public_key_format(const agc_key_info *ki, agc_key_format *out);

/* provider_metadata (map<string, string>). */
AGC_API size_t agc_key_info_provider_metadata_count(const agc_key_info *ki);
AGC_API agc_rc agc_key_info_provider_metadata_at(const agc_key_info *ki, size_t index,
                                                  const char **out_key, const char **out_value);

/* --------------------------------------------------------------------------
 * CreateKey
 * -------------------------------------------------------------------------- */

typedef struct agc_create_key_params {
    size_t struct_size;

    const char *name;      /* REQUIRED */
    const char *policy;    /* REQUIRED on the wire; NULL uses ctx.default_policy locally */
    const char *provider_id; /* NULL => auto-select */
    agc_kv_list provider_configuration;

    const agc_scope_spec *scope_spec;  /* required unless template_id is set */
    const char           *template_id; /* NULL => policy selects from scope_spec */

    const agc_provider_requirements *provider_requirements; /* NULL => no filter */
} agc_create_key_params;

/* CreateKeyResponse has 5 fields; success/message collapse into agc_rc (D4).
 * security_guarantees is NOT a third out-parameter -- it is not otherwise
 * exposed by this reconciliation (agc_template_info/CBOM land in commit 11;
 * when they do, it is reachable via the key's template, never duplicated). */
AGC_API agc_rc agc_create_key(agc_ctx *ctx, const agc_create_key_params *params,
                               agc_key_info **out_key,
                               agc_impl_props **out_impl /* optional, may be NULL; commit 11 */);

/* --------------------------------------------------------------------------
 * ReadKey / ListKeys
 * -------------------------------------------------------------------------- */

/* version == 0 reads the latest (proto: optional uint32 version, absent =
 * latest; versions start at 1, so 0 is an unambiguous sentinel). */
AGC_API agc_rc agc_read_key(agc_ctx *ctx, const char *name, uint32_t version,
                             agc_key_info **out_key);

typedef struct agc_list_keys_params {
    size_t struct_size;
    const agc_scope_spec   *scope_spec;      /* NULL => no scope filter */
    const char              *provider_id;     /* NULL => any */
    const char              *policy;          /* NULL => any */
    agc_key_lifecycle_state  lifecycle_state; /* UNSPECIFIED => any */
    uint32_t                 page_size;       /* 0 => implementation default */
} agc_list_keys_params;

AGC_API agc_rc agc_list_keys(agc_ctx *ctx, const agc_list_keys_params *params,
                              agc_key_iter **out_iter);
AGC_API agc_rc agc_key_iter_next(agc_key_iter *it, agc_key_info **out);
AGC_API void   agc_key_iter_free(agc_key_iter *it);

/* --------------------------------------------------------------------------
 * DeleteKey
 * -------------------------------------------------------------------------- */

/* Zeroizes key material in the provider -- irreversible. DeleteKeyRequest is
 * `{name}` on the wire; there is no remove_metadata field (an earlier draft
 * of this reconciliation invented one -- see docs/PROTO_RFCS.md RFC-05). */
AGC_API agc_rc agc_delete_key(agc_ctx *ctx, const char *name);

/* --------------------------------------------------------------------------
 * RotateKey
 * -------------------------------------------------------------------------- */

/* RotateKeyRequest is `{name}` on the wire -- no reason field (RFC-06). */
AGC_API agc_rc agc_rotate_key(agc_ctx *ctx, const char *name, agc_key_info **out_new_key);

/* --------------------------------------------------------------------------
 * TransformKey — the agility primitive
 * -------------------------------------------------------------------------- */

typedef struct agc_transform_key_params {
    size_t struct_size;
    const char            *name;             /* REQUIRED */
    int                    retain_key_bytes; /* 0 = regenerate (default), 1 = keep material */
    const agc_scope_spec  *scope_spec;       /* intent-based target */
    const char            *template_id;      /* explicit target; NULL => policy selects */
} agc_transform_key_params;

AGC_API agc_rc agc_transform_key(agc_ctx *ctx, const agc_transform_key_params *params,
                                  agc_key_info **out_key);

/* --------------------------------------------------------------------------
 * UpdateKeyPolicy
 * -------------------------------------------------------------------------- */

AGC_API agc_rc agc_update_key_policy(agc_ctx *ctx, const char *name, const char *new_policy,
                                      agc_key_info **out_key);

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
    const char            *name;         /* REQUIRED */
    agc_migrate_target     target;       /* REQUIRED */
    agc_migration_strategy strategy;     /* REQUIRED; UNSPECIFIED is rejected */
    const agc_scope_spec  *scope_spec;   /* optional algorithm change during migration */
    const char            *template_id;  /* optional explicit algorithm change */
} agc_migrate_key_params;

AGC_API agc_rc agc_migrate_key(agc_ctx *ctx, const agc_migrate_key_params *params,
                                agc_key_info **out_key,
                                agc_migration_report **out_report /* optional */);

AGC_API void agc_migration_report_free(agc_migration_report *r);

AGC_API agc_migration_strategy agc_migration_report_strategy_used(const agc_migration_report *r);
AGC_API int         agc_migration_report_key_bytes_preserved(const agc_migration_report *r);
AGC_API const char *agc_migration_report_source_provider_id(const agc_migration_report *r);
AGC_API const char *agc_migration_report_target_provider_id(const agc_migration_report *r);
AGC_API const char *agc_migration_report_wrapping_key_name(const agc_migration_report *r);

/* ArchivedKeyInfo -- present only for REKEY_AND_ARCHIVE. Returns 0 otherwise. */
AGC_API int           agc_migration_report_has_archived_key(const agc_migration_report *r);
AGC_API const char   *agc_migration_report_archived_key_name(const agc_migration_report *r);
AGC_API const char   *agc_migration_report_archived_provider_id(const agc_migration_report *r);
AGC_API agc_timestamp agc_migration_report_archived_expiration(const agc_migration_report *r);

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
    const char              *name;   /* REQUIRED */
    agc_validate_intent_kind kind;   /* REQUIRED */
    union {
        agc_validate_transform_intent transform;
        agc_validate_migrate_intent   migrate;
    } u;
} agc_validate_key_op_params;

AGC_API agc_rc agc_validate_key_operation(agc_ctx *ctx, const agc_validate_key_op_params *params,
                                           agc_feasibility_report **out_report);

AGC_API void agc_feasibility_report_free(agc_feasibility_report *r);

/* KeyState (current_state, field 1). */
AGC_API const char       *agc_feasibility_current_template_id(const agc_feasibility_report *r);
AGC_API const char       *agc_feasibility_current_provider_id(const agc_feasibility_report *r);
AGC_API int               agc_feasibility_current_extractable(const agc_feasibility_report *r);
AGC_API agc_provider_type agc_feasibility_current_provider_type(const agc_feasibility_report *r);

/* StrategyOption list (options, field 2). For TRANSFORM intents `strategy`
 * is AGC_MIGRATION_STRATEGY_UNSPECIFIED and feasibility rides on
 * `feasible`/`infeasibility_reason`, exactly as the proto documents. */
AGC_API size_t agc_feasibility_option_count(const agc_feasibility_report *r);
AGC_API agc_rc agc_feasibility_option_at(const agc_feasibility_report *r, size_t i,
                                          agc_migration_strategy *out_strategy,
                                          int *out_feasible,
                                          const char **out_infeasibility_reason,
                                          int32_t *out_complexity_level);

AGC_API agc_migration_strategy agc_feasibility_recommended_strategy(const agc_feasibility_report *r);
AGC_API const char            *agc_feasibility_recommendation_reason(const agc_feasibility_report *r);

/* --------------------------------------------------------------------------
 * ExportKey / ImportKey
 * -------------------------------------------------------------------------- */

typedef struct agc_export_key_params {
    size_t          struct_size;
    const char     *name;              /* REQUIRED */
    agc_key_format  format;            /* REQUIRED */
    const char     *wrapping_key_name; /* REQUIRED when format == WRAPPED */
} agc_export_key_params;

/* SECURITY: the caller owns the exported material and MUST agc_secure_zero
 * it -- the library cannot know when the caller is finished with it, which
 * is precisely why the buffer is caller-owned. Two-call convention. */
AGC_API agc_rc agc_export_key(agc_ctx *ctx, const agc_export_key_params *params,
                               agc_buf out_material, size_t *out_material_len,
                               agc_key_format *out_actual_format,
                               agc_key_info **out_key);

typedef struct agc_import_key_params {
    size_t          struct_size;
    const char     *name;                /* REQUIRED */
    const char     *policy_name;
    agc_slice       key_material;        /* REQUIRED */
    agc_key_format  format;              /* REQUIRED */
    const char     *unwrapping_key_name; /* REQUIRED when format == WRAPPED */
    const char     *provider_id;
    agc_kv_list     provider_configuration;
    const char     *template_id;         /* REQUIRED by the proto */
} agc_import_key_params;

AGC_API agc_rc agc_import_key(agc_ctx *ctx, const agc_import_key_params *params,
                               agc_key_info **out_key);

#ifdef __cplusplus
}
#endif
#endif /* AGC_KEY_H */
