/**
 * @file citius_key_management.h  (messages/)
 * @brief Key management request and response structs.
 *
 * Mirrors api/proto/messages/key_management.proto.
 *
 * Proto correspondence
 * --------------------
 *  KeyMetadata                  → citius_key_metadata_t
 *  CreateKeyRequest             → citius_create_key_request_t
 *  CreateKeyResponse            → citius_create_key_response_t
 *  ReadKeyRequest               → citius_read_key_request_t
 *  ReadKeyResponse              → citius_read_key_response_t
 *  ListKeysRequest              → citius_list_keys_request_t
 *  ListKeysResponse             → citius_list_keys_response_t
 *  DeleteKeyRequest             → citius_delete_key_request_t
 *  DeleteKeyResponse            → citius_delete_key_response_t
 *  RotateKeyRequest             → citius_rotate_key_request_t
 *  RotateKeyResponse            → citius_rotate_key_response_t
 *  ExportKeyRequest             → citius_export_key_request_t
 *  ExportKeyResponse            → citius_export_key_response_t
 *  ImportKeyRequest             → citius_import_key_request_t
 *  ImportKeyResponse            → citius_import_key_response_t
 *  TransformKeyRequest          → citius_transform_key_request_t
 *  TransformKeyResponse         → citius_transform_key_response_t
 *  UpdateKeyPolicyRequest       → citius_update_key_policy_request_t
 *  UpdateKeyPolicyResponse      → citius_update_key_policy_response_t
 *  MigrationStrategy (enum)     → citius_migration_strategy_t
 *  MigrateKeyRequest            → citius_migrate_key_request_t
 *  MigrateKeyResponse           → citius_migrate_key_response_t
 *  ArchivedKeyInfo              → citius_archived_key_info_t
 *  MigrationResult              → citius_migration_result_t
 *  ProviderTarget               → citius_provider_target_t
 *  ValidateKeyOperationRequest  → citius_validate_key_operation_request_t
 *  ValidateKeyOperationResponse → citius_validate_key_operation_response_t
 *  ValidateTransformIntent      → citius_validate_transform_intent_t
 *  ValidateMigrateIntent        → citius_validate_migrate_intent_t
 *  KeyState                     → citius_key_state_t
 *  StrategyOption               → citius_strategy_option_t
 */

#ifndef CITIUS_MESSAGES_KEY_MANAGEMENT_H
#define CITIUS_MESSAGES_KEY_MANAGEMENT_H

#include "citius/types/citius_types.h"
#include "citius/types/citius_common.h"
#include "citius/types/citius_templates.h"
#include "citius/types/citius_implementation.h"
#include "citius/types/citius_providers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* KeyFormat and WrapFormat are defined in citius/types/citius_common.h
 * (included above via citius_templates.h). */

/* =========================================================================
 * KeyMetadata  (proto: KeyMetadata)
 *
 * Returned by Create/Read/Rotate/Transform/Import/Export/Migrate responses
 * and in Encapsulate/Decapsulate/Wrap/Unwrap/Derive/Agree responses.
 * Forward-declare guard: other message headers (key_derivation, key_encapsulation,
 * key_wrapping) forward-declare citius_key_metadata_t with:
 *   #ifndef CITIUS_KEY_METADATA_DEFINED
 *   struct citius_key_metadata_s;
 *   typedef struct citius_key_metadata_s citius_key_metadata_t;
 *   #define CITIUS_KEY_METADATA_DEFINED 1
 *   #endif
 * This header provides the full struct body. Both the forward-decl and the
 * full definition refer to the same underlying struct tag, so they are compatible.
 * ========================================================================= */

typedef struct citius_key_metadata_s {
    const char                    *name;
    uint32_t                       version;
    const char                    *key_id;
    const char                    *template_id;
    citius_scope_specification_t   scope_spec;
    const char                    *provider;
    const char                    *created_time;   /**< ISO 8601 timestamp; nullable */
    const char                    *updated_time;   /**< ISO 8601 timestamp; nullable */
    const char                    *policy;         /**< nullable */
    const citius_map_t            *provider_metadata; /**< nullable */
    citius_template_info_t         template_info;
    citius_implementation_properties_t implementation_properties;
    uint8_t                        extractable;
    citius_key_lifecycle_state_t   lifecycle_state;
    const uint8_t                 *public_key_bytes;  /**< nullable — asymmetric keys only */
    size_t                         public_key_bytes_len;
    uint8_t                        has_public_key_format;
    citius_key_format_t            public_key_format;
} citius_key_metadata_t;

#ifndef CITIUS_KEY_METADATA_DEFINED
#define CITIUS_KEY_METADATA_DEFINED 1
#endif

/* =========================================================================
 * CreateKeyRequest / CreateKeyResponse
 * ========================================================================= */

typedef struct {
    const char                    *name;                   /**< required */
    const char                    *policy;                 /**< required */
    const char                    *provider_id;            /**< nullable */
    const citius_map_t            *provider_configuration; /**< nullable */
    citius_scope_specification_t   scope_spec;
    const char                    *template_id;            /**< nullable */
    citius_provider_requirements_t provider_requirements;
} citius_create_key_request_t;

typedef struct {
    uint8_t                          success;
    const char                      *message;                  /**< nullable */
    citius_key_metadata_t            key_metadata;
    citius_security_guarantees_t     security_guarantees;
    citius_implementation_properties_t implementation_properties;
} citius_create_key_response_t;

/* =========================================================================
 * ReadKeyRequest / ReadKeyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
    uint8_t     has_version;
    uint32_t    version;   /**< used only when has_version != 0 */
} citius_read_key_request_t;

typedef struct {
    citius_key_metadata_t key_metadata;
} citius_read_key_response_t;

/* =========================================================================
 * ListKeysRequest / ListKeysResponse
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t  scope_spec;
    const char                   *provider_id;      /**< nullable */
    const char                   *policy;           /**< nullable */
    uint8_t                       has_lifecycle_state;
    citius_key_lifecycle_state_t  lifecycle_state;
    int32_t                       page_size;        /**< 0 = server default */
    const char                   *page_token;       /**< nullable */
} citius_list_keys_request_t;

typedef struct {
    const citius_key_metadata_t  *keys;            /**< array of key_count entries */
    size_t                        key_count;
    const char                   *next_page_token; /**< nullable */
} citius_list_keys_response_t;

/* =========================================================================
 * DeleteKeyRequest / DeleteKeyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
} citius_delete_key_request_t;

typedef struct {
    uint8_t     success;
    const char *message; /**< nullable */
} citius_delete_key_response_t;

/* =========================================================================
 * RotateKeyRequest / RotateKeyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
} citius_rotate_key_request_t;

typedef struct {
    uint8_t               success;
    const char           *message;         /**< nullable */
    citius_key_metadata_t new_key_metadata;
} citius_rotate_key_response_t;

/* =========================================================================
 * ExportKeyRequest / ExportKeyResponse
 * ========================================================================= */

typedef struct {
    const char          *name;
    citius_key_format_t  format;
    const char          *wrapping_key_name; /**< required if format == CITIUS_KEY_FORMAT_WRAPPED */
} citius_export_key_request_t;

typedef struct {
    const uint8_t        *key_material;       /**< raw or wrapped bytes */
    size_t                key_material_len;
    citius_key_format_t   format;
    citius_key_metadata_t key_metadata;
} citius_export_key_response_t;

/* =========================================================================
 * ImportKeyRequest / ImportKeyResponse
 * ========================================================================= */

typedef struct {
    const char           *name;
    const char           *policy_name;
    const uint8_t        *key_material;
    size_t                key_material_len;
    citius_key_format_t   format;
    const char           *unwrapping_key_name;  /**< required if format == WRAPPED */
    const char           *provider_id;          /**< nullable */
    const citius_map_t   *provider_configuration; /**< nullable */
    const char           *template_id;          /**< required */
} citius_import_key_request_t;

typedef struct {
    uint8_t               success;
    const char           *message;      /**< nullable */
    citius_key_metadata_t key_metadata;
} citius_import_key_response_t;

/* =========================================================================
 * TransformKeyRequest / TransformKeyResponse
 * ========================================================================= */

typedef struct {
    const char                   *name;
    uint8_t                       retain_key_bytes;
    citius_scope_specification_t  scope_spec;
    const char                   *template_id; /**< nullable */
} citius_transform_key_request_t;

typedef struct {
    uint8_t               success;
    const char           *message;      /**< nullable */
    citius_key_metadata_t key_metadata;
} citius_transform_key_response_t;

/* =========================================================================
 * UpdateKeyPolicyRequest / UpdateKeyPolicyResponse
 * ========================================================================= */

typedef struct {
    const char *name;
    const char *new_policy;
} citius_update_key_policy_request_t;

typedef struct {
    uint8_t               success;
    const char           *message;      /**< nullable */
    citius_key_metadata_t key_metadata;
} citius_update_key_policy_response_t;

/* =========================================================================
 * MigrationStrategy  (proto: MigrationStrategy)
 * ========================================================================= */

typedef enum {
    CITIUS_MIGRATION_STRATEGY_UNSPECIFIED       = 0,
    CITIUS_MIGRATION_STRATEGY_PROVIDER_SWITCH   = 1,
    CITIUS_MIGRATION_STRATEGY_EXTRACT_AND_IMPORT = 2,
    CITIUS_MIGRATION_STRATEGY_WRAPPED_TRANSFER  = 3,
    CITIUS_MIGRATION_STRATEGY_REKEY_AND_ARCHIVE = 4,
    CITIUS_MIGRATION_STRATEGY_REKEY_AND_DESTROY = 5
} citius_migration_strategy_t;

/* =========================================================================
 * ProviderTarget  (proto: ProviderTarget)
 * ========================================================================= */

typedef struct {
    const char         *provider_id;    /**< e.g. "pkcs11", "openssl3" */
    const citius_map_t *configuration;  /**< provider-specific config; nullable */
} citius_provider_target_t;

/* =========================================================================
 * MigrateKeyRequest / MigrateKeyResponse
 * ========================================================================= */

typedef enum {
    CITIUS_MIGRATE_TARGET_INSTANCE_ID = 1,
    CITIUS_MIGRATE_TARGET_PROVIDER    = 2
} citius_migrate_target_type_t;

typedef struct {
    const char                   *name;
    citius_migrate_target_type_t  target_type;
    union {
        const char                *target_instance_id; /**< pre-registered ProviderInstance */
        citius_provider_target_t   provider_target;    /**< inline provider spec */
    } target;
    citius_migration_strategy_t   strategy;
    uint8_t                       has_scope_spec;
    citius_scope_specification_t  scope_spec;
    const char                   *template_id; /**< nullable */
} citius_migrate_key_request_t;

typedef struct {
    const char                   *archived_key_name;
    const char                   *provider_id;
    const citius_crypto_operation_t *allowed_operations; /**< array; nullable */
    size_t                         allowed_operations_count;
    const char                    *expiration_time;  /**< ISO 8601; nullable */
} citius_archived_key_info_t;

typedef struct {
    citius_migration_strategy_t         strategy_used;
    uint8_t                             key_bytes_preserved;
    const char                         *source_provider_id;
    const char                         *source_instance_id;
    const char                         *target_provider_id;
    const char                         *target_instance_id;
    citius_implementation_properties_t  target_implementation;
    const char                         *wrapping_key_name; /**< WRAPPED_TRANSFER only; nullable */
} citius_migration_result_t;

typedef struct {
    uint8_t                      success;
    const char                  *message;           /**< nullable */
    citius_key_metadata_t        key_metadata;
    citius_archived_key_info_t   archived_key_info; /**< populated for REKEY_AND_ARCHIVE */
    citius_migration_result_t    result;
} citius_migrate_key_response_t;

/* =========================================================================
 * ValidateKeyOperation  (proto: ValidateKeyOperationRequest/Response)
 * ========================================================================= */

typedef struct {
    citius_scope_specification_t  scope_spec;
    const char                   *template_id;       /**< nullable */
    uint8_t                       prefer_retain_bytes;
} citius_validate_transform_intent_t;

typedef enum {
    CITIUS_VALIDATE_MIGRATE_BY_INSTANCE_ID = 1,
    CITIUS_VALIDATE_MIGRATE_BY_PROVIDER_ID = 2
} citius_validate_migrate_target_type_t;

typedef struct {
    citius_validate_migrate_target_type_t target_type;
    const char                           *target_id; /**< instance_id or provider_id */
    uint8_t                               has_preferred_strategy;
    citius_migration_strategy_t           preferred_strategy;
} citius_validate_migrate_intent_t;

typedef enum {
    CITIUS_VALIDATE_INTENT_TRANSFORM = 1,
    CITIUS_VALIDATE_INTENT_MIGRATE   = 2
} citius_validate_intent_type_t;

typedef struct {
    const char                        *name;
    citius_validate_intent_type_t      intent_type;
    union {
        citius_validate_transform_intent_t transform;
        citius_validate_migrate_intent_t   migrate;
    } intent;
} citius_validate_key_operation_request_t;

typedef struct {
    const char                    *template_id;
    const char                    *provider_id;
    const char                    *instance_id;
    uint8_t                        extractable;
    citius_provider_type_t         provider_type;
    citius_implementation_properties_t implementation;
} citius_key_state_t;

typedef struct {
    citius_migration_strategy_t  strategy;
    uint8_t                      feasible;
    const char                  *infeasibility_reason; /**< nullable */
    const char * const          *security_notes;       /**< NULL-terminated array; nullable */
    int32_t                      complexity_level;     /**< 1-5 */
} citius_strategy_option_t;

typedef struct {
    citius_key_state_t              current_state;
    const citius_strategy_option_t *options;             /**< array */
    size_t                          options_count;
    citius_migration_strategy_t     recommended_strategy;
    const char                     *recommendation_reason; /**< nullable */
} citius_validate_key_operation_response_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_KEY_MANAGEMENT_H */
