/**
 * @file citius_implementation.h
 * @brief Implementation properties, FIPS certification, and provider requirements.
 *
 * Mirrors api/proto/types/implementation.proto.
 */

#ifndef CITIUS_IMPLEMENTATION_H
#define CITIUS_IMPLEMENTATION_H

#include "citius_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Fips140Level  (proto: Fips140Level)
 * ========================================================================= */

typedef enum {
    FIPS_140_LEVEL_UNSPECIFIED = 0,
    FIPS_140_LEVEL_1           = 1,
    FIPS_140_LEVEL_2           = 2,
    FIPS_140_LEVEL_3           = 3,
    FIPS_140_LEVEL_4           = 4
} citius_fips_140_level_t;

/* =========================================================================
 * Fips140Certification  (proto: Fips140Certification)
 * ========================================================================= */

typedef struct {
    uint8_t                  certified;          /**< Whether FIPS 140 certified                   */
    citius_fips_140_level_t  level;              /**< Security level (1–4)                         */
    const char              *certificate_number; /**< CMVP certificate number; nullable            */
    const char              *module_name;        /**< Cryptographic module name; nullable          */
    const char              *validation_date;    /**< ISO 8601 validation date; nullable           */
    const char              *expiration_date;    /**< ISO 8601 expiration date; nullable           */
} citius_fips_140_certification_t;

/* =========================================================================
 * AuditReport  (proto: AuditReport)
 * ========================================================================= */

typedef struct {
    const char *auditor;           /**< Auditing firm (e.g., "Trail of Bits")    */
    const char *report_date;       /**< ISO 8601 report date                     */
    const char *report_id;         /**< Reference identifier                     */
    const char *scope;             /**< Scope of the audit                       */
    const char *findings_summary;  /**< Brief summary of findings                */
    const char *report_url;        /**< Link to public report; nullable          */
} citius_audit_report_t;

/* =========================================================================
 * ImplementationProperties  (proto: ImplementationProperties)
 * ========================================================================= */

typedef struct {
    /* Certifications */
    citius_fips_140_certification_t fips_140;
    int8_t                          common_criteria_certified; /**< -1=unset, 0=false, 1=true */
    const citius_audit_report_t    *audits;
    size_t                          num_audits;

    /* Code quality */
    int8_t      formally_verified;        /**< -1=unset, 0=false, 1=true */
    const char *verification_framework;   /**< e.g. "HACL*", "F*"; nullable */
    int8_t      memory_safe_language;     /**< -1=unset, 0=false, 1=true */
    const char *implementation_language;  /**< nullable */

    /* Side-channel */
    int8_t constant_time;          /**< -1=unset, 0=false, 1=true */
    int8_t side_channel_hardened;  /**< -1=unset, 0=false, 1=true */

    /* Performance */
    int8_t       hardware_accelerated;    /**< -1=unset, 0=false, 1=true */
    const char **hardware_features;       /**< e.g. {"aes-ni", "avx2"}; nullable */
    size_t       num_hardware_features;

    /* Security posture */
    int8_t       no_known_cve;      /**< -1=unset, 0=false, 1=true */
    const char **unpatched_cves;    /**< nullable */
    size_t       num_unpatched_cves;

    /* Extensibility */
    const citius_map_t *additional; /**< nullable — vendor-specific or emerging properties (proto field 15) */
} citius_implementation_properties_t;

/* =========================================================================
 * ProviderTemplateSupport  (proto: ProviderTemplateSupport)
 * ========================================================================= */

typedef struct {
    const char                          *template_id;    /**< Must match a registered TemplateInfo.template_id */
    citius_implementation_properties_t   implementation; /**< Per-template overrides                           */
    const char                          *notes;          /**< Optional notes; nullable                         */
    uint8_t                              enabled;        /**< 1 = enabled (default); 0 = disabled             */
} citius_provider_template_support_t;

/* =========================================================================
 * ProviderRequirements  (proto: ProviderRequirements)
 * ========================================================================= */

typedef struct {
    /* Certification */
    int8_t                  fips_140_certified;         /**< -1=unset, 0=false, 1=true */
    citius_fips_140_level_t min_fips_level;
    int8_t                  common_criteria_certified;  /**< -1=unset, 0=false, 1=true */

    /* Code quality */
    int8_t formally_verified; /**< -1=unset, 0=false, 1=true */
    int8_t memory_safe;       /**< -1=unset, 0=false, 1=true */

    /* Side-channel */
    int8_t constant_time;         /**< -1=unset, 0=false, 1=true */
    int8_t side_channel_hardened; /**< -1=unset, 0=false, 1=true */

    /* Security posture */
    int8_t no_known_cve; /**< -1=unset, 0=false, 1=true */

    /* Performance preference */
    int8_t prefer_hardware_accelerated; /**< -1=unset, 0=false, 1=true (soft requirement) */

    /* Extensibility */
    const citius_map_t *additional; /**< nullable — vendor-specific or emerging requirements (proto field 15) */
} citius_provider_requirements_t;

/* =========================================================================
 * ProviderInstance  (proto: ProviderInstance)
 * ========================================================================= */

typedef struct {
    const char                         *instance_id;             /**< Unique instance identifier          */
    const char                         *provider_id;             /**< References ProviderInfo.provider_id */
    const char                         *display_name;            /**< Human-readable name                 */
    const char                         *description;             /**< nullable                            */
    const citius_map_t                 *configuration;           /**< Key-value configuration pairs       */
    uint8_t                             enabled;                 /**< 1 = active                          */
    citius_implementation_properties_t  implementation_override; /**< Overrides ProviderInfo defaults     */
} citius_provider_instance_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_IMPLEMENTATION_H */
