/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_key.h — KeyManagementService (12 RPCs).
 *
 * Key lifecycle: CRUD, rotate, transform, migrate, state transitions,
 * import/export, and pre-flight validation.
 *
 * SELECTION MODES
 * ---------------
 * Every creation-shaped call supports the proto's two selection modes:
 *   - scope-based:  set scope_spec, leave template_id NULL  (recommended)
 *   - template-based: set template_id, optionally with a scope_spec that must
 *                     agree with it
 * In C this is a struct with both fields and a documented precedence rule,
 * rather than two functions, so that a call site written for scope-based
 * selection does not have to change when an operator pins a template.
 */

#ifndef AGC_KEY_H
#define AGC_KEY_H

#include "agc_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * CreateKey
 * -------------------------------------------------------------------------- */

typedef struct agc_create_key_params {
    size_t struct_size;

    /* REQUIRED. 1..256 bytes. */
    const char *name;

    /* Policy governing this key. NULL uses the context's default_policy. */
    const char *policy;

    /* Optional explicit provider. NULL => auto-select from policy and
     * provider_requirements. */
    const char *provider_id;

    /* Ad-hoc provider settings for this creation only. Prefer
     * provider_requirements or a pre-registered instance; ad-hoc configuration
     * bypasses instance-level property tracking and degrades CBOM accuracy. */
    agc_kv_list provider_configuration;

    /* Intent. Required unless template_id is set. */
    const agc_scope_spec *scope_spec;

    /* Explicit template. NULL => policy selects from scope_spec.
     * When both are set they must agree, else AGC_ERR_CRYPTO_NO_MATCHING_TEMPLATE. */
    const char *template_id;

    /* Implementation requirements for provider selection. NULL => no filter. */
    const agc_provider_requirements *provider_requirements;

    /* Cryptoperiod bounds (NIST SP 800-57 §5.3). Leave .present = 0 to inherit
     * the policy default. */
    agc_timestamp activation_time;
    agc_timestamp expiration_time;
} agc_create_key_params;

/* On success *out_key is the created key's metadata; *out_impl (optional, may
 * be NULL) receives the implementation properties of the provider that created
 * it, which the caller needs for CBOM and compliance reporting. Both must be
 * freed. The SecurityGuarantees from CreateKeyResponse are reachable through
 * agc_key_info_template()/agc_template_info_guarantees() and are therefore not
 * duplicated as a third out-parameter. */
AGC_API agc_rc agc_create_key(agc_ctx *ctx,
                              const agc_create_key_params *params,
                              agc_key_info **out_key,
                              agc_impl_props **out_impl);

/* --------------------------------------------------------------------------
 * ReadKey / ListKeys
 * -------------------------------------------------------------------------- */

/* version == 0 reads the latest version, matching the proto's `optional uint32
 * version` where absence means latest. Version numbering starts at 1, so 0 is
 * an unambiguous sentinel and no separate presence flag is needed. */
AGC_API agc_rc agc_read_key(agc_ctx *ctx, const char *name, uint32_t version,
                            agc_key_info **out_key);

typedef struct agc_list_keys_params {
    size_t struct_size;
    const agc_scope_spec   *scope_spec;       /* NULL => no scope filter */
    const char             *provider_id;      /* NULL => any */
    const char             *policy;           /* NULL => any */
    agc_key_lifecycle_state lifecycle_state;  /* UNSPECIFIED => any */
    uint32_t                page_size;        /* 0 => implementation default */
} agc_list_keys_params;

AGC_API agc_rc agc_list_keys(agc_ctx *ctx, const agc_list_keys_params *params,
                             agc_key_iter **out_iter);

/* --------------------------------------------------------------------------
 * DeleteKey
 * -------------------------------------------------------------------------- */

/* Zeroizes key material in the provider — irreversible. By default the key
 * record transitions to DESTROYED (or DESTROYED_COMPROMISED) and metadata is
 * retained for audit per NIST SP 800-57 §8.3.
 *
 * `remove_metadata` is an int rather than a bool to keep the ABI stable and to
 * make the destructive variant visually distinct at the call site. */
AGC_API agc_rc agc_delete_key(agc_ctx *ctx, const char *name, int remove_metadata);

/* --------------------------------------------------------------------------
 * RotateKey
 * -------------------------------------------------------------------------- */

/* New version, same template and policy. Previous versions remain usable for
 * process operations (decrypt/verify/unwrap). `reason` is recorded in the audit
 * trail; may be NULL. */
AGC_API agc_rc agc_rotate_key(agc_ctx *ctx, const char *name, const char *reason,
                              agc_key_info **out_new_key);

/* --------------------------------------------------------------------------
 * TransformKey — the agility primitive
 * -------------------------------------------------------------------------- */

typedef struct agc_transform_key_params {
    size_t struct_size;
    const char           *name;              /* REQUIRED */
    int                   retain_key_bytes;  /* 0 = regenerate (default), 1 = keep material */
    const agc_scope_spec *scope_spec;        /* intent-based target */
    const char           *template_id;       /* explicit target; NULL => policy selects */
} agc_transform_key_params;

/* Changes a key's algorithm while preserving its identity, so existing call
 * sites keep working. Fails with AGC_ERR_CRYPTO_INCOMPATIBLE_PARAMETERS if
 * retain_key_bytes is set and the transform is not material-compatible. */
AGC_API agc_rc agc_transform_key(agc_ctx *ctx,
                                 const agc_transform_key_params *params,
                                 agc_key_info **out_key);

/* --------------------------------------------------------------------------
 * UpdateKeyState / UpdateKeyPolicy
 * -------------------------------------------------------------------------- */

/* Explicit, auditable lifecycle transition per NIST SP 800-57 §7. `reason` is
 * REQUIRED for transitions to COMPROMISED; passing NULL there returns
 * AGC_ERR_INVALID_ARGUMENT. Invalid transitions return
 * AGC_ERR_CRYPTO_INVALID_KEY_STATE_TRANSITION. Destruction goes through
 * agc_delete_key, not through this call. */
AGC_API agc_rc agc_update_key_state(agc_ctx *ctx, const char *name,
                                    agc_key_lifecycle_state target_state,
                                    const char *reason,
                                    agc_key_info **out_key);

/* Rebinds a key to a different policy. Kept a separate call, as in the proto,
 * so that IAM can grant transform rights without granting governance rights. */
AGC_API agc_rc agc_update_key_policy(agc_ctx *ctx, const char *name,
                                     const char *new_policy,
                                     agc_key_info **out_key);

/* --------------------------------------------------------------------------
 * MigrateKey
 * -------------------------------------------------------------------------- */

/* MigrateKeyRequest.target is a oneof over {target_instance_id, ProviderTarget}.
 * Expressed here as a tagged union rather than as two mutually exclusive string
 * fields, so that "neither set" is unrepresentable rather than merely invalid. */
typedef enum agc_migrate_target_kind {
    AGC_MIGRATE_TARGET_NONE     = 0,  /* invalid: the oneof is required */
    AGC_MIGRATE_TARGET_INSTANCE = 2,  /* pre-registered ProviderInstance */
    AGC_MIGRATE_TARGET_PROVIDER = 3   /* provider_id + ad-hoc configuration */
    AGC_ENUM32(agc_migrate_target_kind)
} agc_migrate_target_kind;

typedef struct agc_provider_target {
    const char *provider_id;
    agc_kv_list configuration;
} agc_provider_target;

typedef struct agc_migrate_target {
    agc_migrate_target_kind kind;
    union {
        const char         *instance_id;
        agc_provider_target provider;
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

/* *out_report (optional) carries MigrationResult and, for REKEY_AND_ARCHIVE,
 * ArchivedKeyInfo. */
AGC_API agc_rc agc_migrate_key(agc_ctx *ctx,
                               const agc_migrate_key_params *params,
                               agc_key_info **out_key,
                               agc_migration_report **out_report);

AGC_API void agc_migration_report_free(agc_migration_report *r);

AGC_API agc_migration_strategy agc_migration_report_strategy_used(const agc_migration_report *r);
AGC_API int         agc_migration_report_key_bytes_preserved(const agc_migration_report *r);
AGC_API const char *agc_migration_report_source_provider_id(const agc_migration_report *r);
AGC_API const char *agc_migration_report_source_instance_id(const agc_migration_report *r);
AGC_API const char *agc_migration_report_target_provider_id(const agc_migration_report *r);
AGC_API const char *agc_migration_report_target_instance_id(const agc_migration_report *r);
AGC_API const char *agc_migration_report_wrapping_key_name(const agc_migration_report *r);
AGC_API const agc_impl_props *agc_migration_report_target_implementation(const agc_migration_report *r);

/* ArchivedKeyInfo — present only for REKEY_AND_ARCHIVE. Returns 0 otherwise. */
AGC_API int           agc_migration_report_has_archived_key(const agc_migration_report *r);
AGC_API const char   *agc_migration_report_archived_key_name(const agc_migration_report *r);
AGC_API const char   *agc_migration_report_archived_provider_id(const agc_migration_report *r);
AGC_API agc_timestamp agc_migration_report_archived_expiration(const agc_migration_report *r);
AGC_API size_t        agc_migration_report_archived_allowed_op_count(const agc_migration_report *r);
AGC_API agc_rc        agc_migration_report_archived_allowed_op_at(const agc_migration_report *r,
                                                                  size_t i, agc_operation *out);

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

/* ValidateMigrateIntent.target is an unconstrained oneof in the proto (no
 * `required`), so "neither" is representable there. Here it is still a tagged
 * union but AGC_VALIDATE_MIGRATE_TARGET_ANY is a legal tag meaning "assess all
 * targets", which makes the previously-implicit case explicit. */
typedef enum agc_validate_migrate_target_kind {
    AGC_VALIDATE_MIGRATE_TARGET_ANY      = 0,
    AGC_VALIDATE_MIGRATE_TARGET_INSTANCE = 1,
    AGC_VALIDATE_MIGRATE_TARGET_PROVIDER = 2
    AGC_ENUM32(agc_validate_migrate_target_kind)
} agc_validate_migrate_target_kind;

typedef struct agc_validate_migrate_intent {
    agc_validate_migrate_target_kind target_kind;
    const char                      *target_id;           /* instance or provider id */
    agc_migration_strategy           preferred_strategy;  /* UNSPECIFIED => assess all */
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

AGC_API agc_rc agc_validate_key_operation(agc_ctx *ctx,
                                          const agc_validate_key_op_params *params,
                                          agc_feasibility_report **out_report);

AGC_API void agc_feasibility_report_free(agc_feasibility_report *r);

/* Current key state (KeyState message). */
AGC_API const char       *agc_feasibility_current_template_id(const agc_feasibility_report *r);
AGC_API const char       *agc_feasibility_current_provider_id(const agc_feasibility_report *r);
AGC_API const char       *agc_feasibility_current_instance_id(const agc_feasibility_report *r);
AGC_API int               agc_feasibility_current_extractable(const agc_feasibility_report *r);
AGC_API agc_provider_type agc_feasibility_current_provider_type(const agc_feasibility_report *r);
AGC_API const agc_impl_props *agc_feasibility_current_implementation(const agc_feasibility_report *r);

/* StrategyOption list. For TRANSFORM intents the strategy field is
 * AGC_MIGRATION_STRATEGY_UNSPECIFIED and feasibility is carried by
 * `feasible` / `infeasibility_reason`, exactly as documented in the proto. */
AGC_API size_t agc_feasibility_option_count(const agc_feasibility_report *r);
AGC_API agc_rc agc_feasibility_option_at(const agc_feasibility_report *r, size_t i,
                                         agc_migration_strategy *out_strategy,
                                         int *out_feasible,
                                         const char **out_infeasibility_reason,
                                         int32_t *out_complexity_level);
AGC_API size_t      agc_feasibility_option_security_note_count(const agc_feasibility_report *r, size_t i);
AGC_API const char *agc_feasibility_option_security_note_at(const agc_feasibility_report *r,
                                                            size_t i, size_t j);

AGC_API agc_migration_strategy agc_feasibility_recommended_strategy(const agc_feasibility_report *r);
AGC_API const char            *agc_feasibility_recommendation_reason(const agc_feasibility_report *r);

/* --------------------------------------------------------------------------
 * ExportKey / ImportKey
 * -------------------------------------------------------------------------- */

typedef struct agc_export_key_params {
    size_t          struct_size;
    const char     *name;                /* REQUIRED */
    agc_key_format  format;              /* REQUIRED */
    const char     *wrapping_key_name;   /* REQUIRED when format == WRAPPED */
} agc_export_key_params;

/* Two-call convention on out_material. out_kcv (optional) receives the key
 * check value, also two-call — pass a zero agc_buf and NULL length pointer to
 * skip it entirely.
 *
 * SECURITY: the caller owns the exported material and MUST agc_secure_zero it.
 * The library cannot do this, which is precisely why the buffer is caller-owned
 * rather than library-allocated. */
AGC_API agc_rc agc_export_key(agc_ctx *ctx,
                              const agc_export_key_params *params,
                              agc_buf out_material, size_t *out_material_len,
                              agc_buf out_kcv, size_t *out_kcv_len,
                              agc_key_format *out_actual_format,
                              agc_key_info **out_key);

typedef struct agc_import_key_params {
    size_t          struct_size;
    const char     *name;                  /* REQUIRED */
    const char     *policy_name;           /* policy for the imported key */
    agc_slice       key_material;          /* REQUIRED */
    agc_key_format  format;                /* REQUIRED */
    const char     *unwrapping_key_name;   /* REQUIRED when format == WRAPPED */
    const char     *provider_id;
    agc_kv_list     provider_configuration;
    const char     *template_id;           /* REQUIRED by the proto */
    agc_slice       key_attestation;       /* optional BYOK attestation evidence */
} agc_import_key_params;

AGC_API agc_rc agc_import_key(agc_ctx *ctx,
                              const agc_import_key_params *params,
                              agc_key_info **out_key);

#ifdef __cplusplus
}
#endif
#endif /* AGC_KEY_H */
