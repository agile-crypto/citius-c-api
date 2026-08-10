/**
 * @file citius_algorithms.h
 * @brief Standard algorithm catalog definitions.
 *
 * Mirrors api/proto/types/algorithms.proto.
 */

#ifndef CITIUS_ALGORITHMS_H
#define CITIUS_ALGORITHMS_H

#include "citius_types.h"
#include "citius_templates.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * AlgorithmFamilySpec  (proto: AlgorithmFamilySpec)
 * ========================================================================= */

typedef struct {
    const char  *family;             /**< e.g. "AES", "ML-KEM", "ECDSA"                */
    const char  *display_name;       /**< e.g. "Advanced Encryption Standard"          */
    const char  *description;        /**< nullable                                      */
    const char  *primitive;          /**< e.g. "ae", "signature", "kem", "kdf"         */
    const char **standards;          /**< e.g. {"NIST FIPS 197", "RFC 5116"}           */
    size_t       num_standards;
    const char **template_ids;       /**< Template IDs belonging to this family        */
    size_t       num_template_ids;
    const char  *default_template_id; /**< Recommended configuration; nullable         */
    uint8_t      has_pqc_variants;   /**< Whether any variant is post-quantum           */
    uint32_t     min_security_level; /**< Minimum recommended security level in bits   */
} citius_algorithm_family_spec_t;

/* =========================================================================
 * StandardAlgorithmCatalog  (proto: StandardAlgorithmCatalog)
 *
 * In C the templates map is represented as a flat array; callers search by
 * template_id.  The citius_map_t here is separate from the KV map type —
 * use the typed array below.
 * ========================================================================= */

typedef struct {
    const char                            *version;       /**< Semantic version string          */
    const char                            *last_updated;  /**< ISO 8601 timestamp; nullable     */
    const char                            *description;   /**< nullable                         */
    const citius_template_info_t          *templates;     /**< Flat array, search by template_id */
    size_t                                 num_templates;
    const citius_algorithm_family_spec_t  *families;
    size_t                                 num_families;
} citius_standard_algorithm_catalog_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_ALGORITHMS_H */
