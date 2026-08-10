/**
 * @file citius_key_management_service.h
 * @brief Key lifecycle operations (KeyManagementService).
 *
 * C mirror of api/proto/services/key_management_service.proto —
 * KeyManagementService.
 *
 * This service manages the lifecycle of cryptographic keys:
 *   - CRUD operations (create, read, list, delete)
 *   - Lifecycle operations (rotate, transform, migrate)
 *   - Import/export for interoperability
 *   - Policy binding (UpdateKeyPolicy)
 *   - Pre-flight validation (ValidateKeyOperation)
 *
 * Proto → C mapping
 * -----------------
 *   rpc CreateKey(CreateKeyRequest) → CreateKeyResponse
 *       citius_key_create(request*, response*)
 *
 *   rpc ReadKey(ReadKeyRequest) → ReadKeyResponse
 *       citius_key_read(request*, response*)
 *
 *   rpc ListKeys(ListKeysRequest) → ListKeysResponse
 *       citius_key_list(request*, response*)
 *
 *   rpc DeleteKey(DeleteKeyRequest) → DeleteKeyResponse
 *       citius_key_delete(request*, response*)
 *
 *   rpc RotateKey(RotateKeyRequest) → RotateKeyResponse
 *       citius_key_rotate(request*, response*)
 *
 *   rpc ExportKey(ExportKeyRequest) → ExportKeyResponse
 *       citius_key_export(request*, response*)
 *
 *   rpc ImportKey(ImportKeyRequest) → ImportKeyResponse
 *       citius_key_import(request*, response*)
 *
 *   rpc TransformKey(TransformKeyRequest) → TransformKeyResponse
 *       citius_key_transform(request*, response*)
 *
 *   rpc UpdateKeyPolicy(UpdateKeyPolicyRequest) → UpdateKeyPolicyResponse
 *       citius_key_update_policy(request*, response*)
 *
 *   rpc MigrateKey(MigrateKeyRequest) → MigrateKeyResponse
 *       citius_key_migrate(request*, response*)
 *
 *   rpc ValidateKeyOperation(ValidateKeyOperationRequest) → ValidateKeyOperationResponse
 *       citius_key_validate_operation(request*, response*)
 *
 * HTTP REST paths (from proto annotations):
 *   POST   /v1/keys/{name}            citius_key_create()
 *   GET    /v1/keys/{name}            citius_key_read()
 *   GET    /v1/keys                   citius_key_list()
 *   DELETE /v1/keys/{name}            citius_key_delete()
 *   POST   /v1/keys/{name}/rotate     citius_key_rotate()
 *   POST   /v1/keys/{name}/export     citius_key_export()
 *   POST   /v1/keys:import            citius_key_import()
 *   POST   /v1/keys/{name}/transform  citius_key_transform()
 *   PUT    /v1/keys/{name}/policy     citius_key_update_policy()
 *   POST   /v1/keys/{name}/migrate    citius_key_migrate()
 *   POST   /v1/keys/{name}/validate   citius_key_validate_operation()
 *
 * Cryptographic agility note
 * --------------------------
 * Key creation supports two algorithm selection modes:
 *   - Scope-based (policy determines template) — recommended
 *   - Explicit template_id (discovered via AlgorithmDiscoveryService)
 *
 * Migration strategies (proto: MigrationStrategy):
 *   PROVIDER_SWITCH      — SW→SW metadata-only change
 *   EXTRACT_AND_IMPORT   — Key crosses security boundary
 *   WRAPPED_TRANSFER     — HSM→HSM with maximum security
 *   REKEY_AND_ARCHIVE    — New key, archive old
 *   REKEY_AND_DESTROY    — New key, destroy old
 */

#ifndef CITIUS_SERVICES_KEY_MANAGEMENT_SERVICE_H
#define CITIUS_SERVICES_KEY_MANAGEMENT_SERVICE_H

#include "citius/types/citius_types.h"
#include "citius/messages/citius_key_management.h"

#ifdef __cplusplus
extern "C" {
#endif

CITIUS_RV citius_key_create(
    const citius_create_key_request_t *request,
    citius_create_key_response_t      *response
);

CITIUS_RV citius_key_read(
    const citius_read_key_request_t *request,
    citius_read_key_response_t      *response
);

CITIUS_RV citius_key_list(
    const citius_list_keys_request_t *request,
    citius_list_keys_response_t      *response
);

CITIUS_RV citius_key_delete(
    const citius_delete_key_request_t *request,
    citius_delete_key_response_t      *response
);

CITIUS_RV citius_key_rotate(
    const citius_rotate_key_request_t *request,
    citius_rotate_key_response_t      *response
);

CITIUS_RV citius_key_export(
    const citius_export_key_request_t *request,
    citius_export_key_response_t      *response
);

CITIUS_RV citius_key_import(
    const citius_import_key_request_t *request,
    citius_import_key_response_t      *response
);

CITIUS_RV citius_key_transform(
    const citius_transform_key_request_t *request,
    citius_transform_key_response_t      *response
);

CITIUS_RV citius_key_update_policy(
    const citius_update_key_policy_request_t  *request,
    citius_update_key_policy_response_t       *response
);

CITIUS_RV citius_key_migrate(
    const citius_migrate_key_request_t *request,
    citius_migrate_key_response_t      *response
);

CITIUS_RV citius_key_validate_operation(
    const citius_validate_key_operation_request_t *request,
    citius_validate_key_operation_response_t      *response
);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_SERVICES_KEY_MANAGEMENT_SERVICE_H */
