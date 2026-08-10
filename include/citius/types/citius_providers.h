/**
 * @file citius_providers.h
 * @brief Provider type classification, ProviderInfo, and ConfigurationParameter.
 *
 * Mirrors api/proto/types/providers.proto.
 */

#ifndef CITIUS_PROVIDERS_H
#define CITIUS_PROVIDERS_H

#include "citius_types.h"
#include "citius_implementation.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * ProviderType  (proto: ProviderType)
 * ========================================================================= */

typedef enum {
    PROVIDER_TYPE_UNSPECIFIED = 0,
    PROVIDER_TYPE_SOFTWARE    = 1, /**< In-process software (go-crypto, OpenSSL, …)   */
    PROVIDER_TYPE_HSM         = 2, /**< Hardware Security Module (PKCS#11 hardware)    */
    PROVIDER_TYPE_CLOUD_KMS   = 3, /**< Cloud-managed KMS (AWS KMS, GCP KMS, Azure KV) */
    PROVIDER_TYPE_REMOTE      = 4  /**< Remote/networked service (KMIP, Vault, …)      */
} citius_provider_type_t;

/* =========================================================================
 * ConfigurationParameter  (proto: ConfigurationParameter)
 * ========================================================================= */

typedef struct {
    const char *name;          /**< Parameter name (e.g. "pkcs11_library_path") */
    const char *type;          /**< Parameter type (e.g. "string", "int", "bool") */
    const char *description;
    uint8_t     required;
    const char *default_value; /**< nullable */
} citius_configuration_parameter_t;

/* =========================================================================
 * ProviderInfo  (proto: ProviderInfo)
 * ========================================================================= */

typedef struct {
    const char                              *provider_id;    /**< Unique identifier          */
    const char                              *display_name;
    const char                              *description;    /**< nullable                   */

    /**< General capabilities as key-value pairs (citius_map_t.size entries) */
    const citius_map_t                      *capabilities;

    /**< Configuration schema entries */
    const citius_configuration_parameter_t *configuration_schema;
    size_t                                   num_configuration_schema;

    citius_implementation_properties_t       default_implementation;

    const citius_provider_template_support_t *template_support;
    size_t                                    num_template_support;

    citius_provider_type_t                   provider_type;
} citius_provider_info_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_PROVIDERS_H */
