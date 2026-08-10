/**
 * @file citius.h
 * @brief Top-level aggregate include for the Citius C cryptographic API.
 *
 * A single #include "citius/citius.h" pulls in the complete API.
 * For fine-grained control, include individual subdirectory headers directly.
 *
 * Directory layout (mirrors api/proto/)
 * --------------------------------------
 *   types/      — data type definitions only; no function declarations
 *   messages/   — request/response structs; one file per proto messages/ file
 *   services/   — function declarations; one file per proto services/ file
 *
 * ── types/ ──────────────────────────────────────────────────────────────────
 *
 *   citius_types.h            ← (no proto analogue)
 *     CITIUS_RV return type, opaque handle typedefs (CITIUS_OBJECT_HANDLE,
 *     CITIUS_PROVIDER_HANDLE), citius_byte_buffer_t, citius_mutable_buffer_t.
 *
 *   citius_algorithm_params.h ← types/algorithm_params.proto
 *     Per-algorithm parameter structs and enums used in key templates:
 *     hash algorithms, elliptic curves, key types, RSA/ECDSA/EdDSA/ML-DSA/
 *     SLH-DSA/ML-KEM/HKDF/PBKDF2/Argon2/SP800-108/TLS/GOST/X3DH params.
 *
 *   citius_common.h           ← types/common.proto
 *     Per-primitive scope enums (*Scope), ScopeSpecification tagged union,
 *     UniversalSecurityProperties, KeyLifecycleState, KeyFormat, WrapFormat,
 *     CryptoOperation, CryptoErrorCode.
 *
 *   citius_implementation.h   ← types/implementation.proto
 *     Fips140Level, Fips140Certification, AuditReport,
 *     ImplementationProperties, ProviderRequirements, ProviderInstance.
 *
 *   citius_providers.h        ← types/providers.proto
 *     ProviderType, ConfigurationParameter, ProviderInfo.
 *
 *   citius_templates.h        ← types/templates.proto
 *     TemplateStatus, AlgorithmDetails, CombinerStrategy,
 *     FormalSecurityNotions, PracticalSecurityOutcomes, OperationalBounds,
 *     SecurityGuarantees, all ScopeSpec structs, ScopedCapabilities,
 *     CycloneDXAlgorithmProperties, TemplateInfo, ScopeInfo.
 *
 *   citius_algorithms.h       ← types/algorithms.proto
 *     StandardAlgorithmCatalog, AlgorithmFamilySpec.
 *
 *   citius_operation_params.h ← types/operation_params.proto
 *     Per-call operation parameter structs passed in request messages:
 *     NoParams, AeadEncryptParams, XtsEncryptParams, AsymmetricEncryptParams,
 *     SignatureDomainContext, CustomizableMacParams, all KDF operation params
 *     (HkdfOperationParams, Pbkdf2OperationParams, Argon2OperationParams,
 *     EcdhOperationParams, X942DhOperationParams, TlsPrfOperationParams,
 *     Tls12KdfOperationParams, Sp800108OperationParams, GostKdfOperationParams,
 *     X3dhOperationParams), KeyAgreementWrapParams, GostWrapOperationParams,
 *     and all vendor wrapper types.
 *
 * ── messages/ ───────────────────────────────────────────────────────────────
 *
 *   citius_metadata.h         ← messages/metadata.proto
 *     AeadOutput, BlockCipherOutput, CounterModeOutput,
 *     StreamCipherOutput, KdfOutput, ProviderOutput, OperationMetadata.
 *     (citius_map_t / citius_byte_map_t live in citius_types.h.)
 *
 *   citius_key_management.h   ← messages/key_management.proto
 *     citius_key_metadata_t; Create/Read/List/Delete/Rotate/Export/Import/
 *     Transform/UpdateKeyPolicy/MigrateKey/ValidateKeyOperation
 *     request+response structs; MigrationStrategy, ProviderTarget,
 *     ArchivedKeyInfo, MigrationResult, KeyState, StrategyOption.
 *
 *   citius_encryption.h       ← messages/encryption.proto
 *     Single-shot Encrypt/Decrypt; multi-part Init/Update/Final;
 *     message-based EncryptMessage/DecryptMessage Init/Message/Begin/Next/Final;
 *     dual-function DigestEncryptUpdate, DecryptDigestUpdate,
 *     SignEncryptUpdate, DecryptVerifyUpdate.
 *
 *   citius_signing.h          ← messages/signing.proto
 *     Single-shot Sign/Verify, DigestSign/DigestVerify;
 *     multi-part SignInit/Update/Final, VerifyInit/Update/Final;
 *     message-based SignMessage/VerifyMessage Init/Message/Begin/Next/Final.
 *
 *   citius_mac.h              ← messages/mac.proto
 *     GenerateMAC/VerifyMAC request+response structs.
 *
 *   citius_digest.h           ← messages/digest.proto
 *     Single-shot Digest/Xof; streaming DigestInit/Update/DigestKey/Final;
 *     streaming XofInit/Update/Final.
 *
 *   citius_random.h           ← messages/random.proto
 *     GenerateRandom/SeedRandom request+response structs.
 *
 *   citius_key_derivation.h   ← messages/key_derivation.proto
 *     DeriveKey/KeyAgreement request+response structs.
 *
 *   citius_key_encapsulation.h ← messages/key_encapsulation.proto
 *     EncapsulateKey/DecapsulateKey request+response structs.
 *
 *   citius_key_wrapping.h     ← messages/key_wrapping.proto
 *     WrapKey/UnwrapKey request+response structs.
 *
 *   citius_policy.h           ← messages/policy.proto
 *     Create/Read/Update/Delete/ListCryptoPolicy request+response structs;
 *     PolicySummary, PolicyDenialReason, PolicyDecisionDetails;
 *     EvaluatePolicy/BatchEvaluatePolicy request+response structs.
 *
 * ── services/ ───────────────────────────────────────────────────────────────
 *
 *   citius_crypto_service.h          ← services/crypto_service.proto
 *     citius_encrypt(), citius_decrypt(),
 *     citius_sign(), citius_verify(),
 *     citius_digest_sign(), citius_digest_verify(),
 *     citius_generate_mac(), citius_verify_mac(),
 *     citius_digest(), citius_xof(),
 *     citius_generate_random(), citius_seed_random().
 *
 *   citius_key_management_service.h  ← services/key_management_service.proto
 *     citius_key_create(), citius_key_read(), citius_key_list(),
 *     citius_key_delete(), citius_key_rotate(), citius_key_export(),
 *     citius_key_import(), citius_key_transform(),
 *     citius_key_update_policy(), citius_key_migrate(),
 *     citius_key_validate_operation().
 *
 *   citius_key_establishment_service.h ← services/key_establishment_service.proto
 *     citius_wrap_key(), citius_unwrap_key(),
 *     citius_derive_key(), citius_key_agreement(),
 *     citius_encapsulate_key(), citius_decapsulate_key().
 *
 *   citius_streaming_crypto_service.h ← services/streaming_crypto_service.proto
 *     citius_op_ctx_free();
 *     citius_encrypt_init/update/final(),
 *     citius_decrypt_init/update/final(),
 *     citius_sign_init/update/final(),
 *     citius_verify_init/update/final(),
 *     citius_digest_init/update/key/final(),
 *     citius_xof_init/update/final();
 *     citius_message_encrypt_init/encrypt/begin/next/final(),
 *     citius_message_decrypt_init/decrypt/begin/next/final(),
 *     citius_sign_message_init/message/begin/next/final(),
 *     citius_verify_message_init/message/begin/next/final();
 *     citius_digest_encrypt_update(), citius_decrypt_digest_update(),
 *     citius_sign_encrypt_update(), citius_decrypt_verify_update().
 *
 *   citius_crypto_policy_service.h   ← services/crypto_policy_service.proto
 *     citius_create_crypto_policy(), citius_read_crypto_policy(),
 *     citius_update_crypto_policy(), citius_delete_crypto_policy(),
 *     citius_list_crypto_policies(), citius_evaluate_policy(),
 *     citius_batch_evaluate_policy().
 *
 *   citius_discovery_service.h       ← services/discovery_service.proto
 *     citius_list_templates(),
 *     citius_get_template(),
 *     citius_list_scopes().
 *
 *   citius_provider_service.h        ← services/provider_service.proto
 *     Provider catalog, instance registration/query, and matching functions.
 *     Also declares the local (non-proto) provider backend registration API:
 *     citius_provider_register/unregister/select/list/describe(), and
 *     citius_init()/citius_finalize() (library lifecycle, in citius_types.h
 *     — no session to open first; call once at startup/shutdown).
 */

#ifndef CITIUS_H
#define CITIUS_H

/* --- Types (in dependency order) --- */
#include "citius/types/citius_types.h"
#include "citius/types/citius_algorithm_params.h"
#include "citius/types/citius_common.h"
#include "citius/types/citius_implementation.h"
#include "citius/types/citius_providers.h"
#include "citius/types/citius_templates.h"
#include "citius/types/citius_algorithms.h"
#include "citius/types/citius_operation_params.h"

/* --- Messages (request/response structs) --- */
#include "citius/messages/citius_messages.h"

/* --- Services (function declarations) --- */
#include "citius/services/citius_services.h"

#endif /* CITIUS_H */
