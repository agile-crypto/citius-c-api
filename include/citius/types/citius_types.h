/**
 * @file citius_types.h
 * @brief Foundation types for the Citius C cryptographic API.
 *
 * This is the leaf header included by every other Citius header.
 * It defines handles, the return-value type, error codes, and byte-buffer
 * helpers.
 *
 * Proto correspondence: error codes mirror CryptoErrorCode in
 * api/proto/types/common.proto.
 */

#ifndef CITIUS_TYPES_H
#define CITIUS_TYPES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Version
 * ========================================================================= */

#define CITIUS_VERSION_MAJOR 0
#define CITIUS_VERSION_MINOR 1
#define CITIUS_VERSION_PATCH 0

/** Runtime version information. */
typedef struct {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    const char *label; /**< nullable — e.g. "alpha", NULL for release builds */
} citius_version_t;

/** Returns the compile-time version of the library. */
static inline citius_version_t citius_version(void) {
    citius_version_t v = {
        CITIUS_VERSION_MAJOR,
        CITIUS_VERSION_MINOR,
        CITIUS_VERSION_PATCH,
        NULL
    };
    return v;
}

/* =========================================================================
 * Opaque handles
 *
 * All handles are unsigned integers of pointer width.  The value 0 is
 * reserved as CITIUS_INVALID_HANDLE.
 * ========================================================================= */

typedef uintptr_t CITIUS_OBJECT_HANDLE;   /**< Reference to a stored key object */
typedef uintptr_t CITIUS_PROVIDER_HANDLE; /**< Registered provider instance     */

/** Sentinel value indicating an uninitialised or invalid handle. */
#define CITIUS_INVALID_HANDLE ((uintptr_t)0)

/* =========================================================================
 * Return value type
 *
 * Every Citius function returns CITIUS_RV.  CITIUS_OK (0) means success.
 * All other values are domain-specific error codes defined below.
 * ========================================================================= */

typedef uint32_t CITIUS_RV;

/** Success. */
#define CITIUS_OK ((CITIUS_RV)0)

/* -------------------------------------------------------------------------
 * Error codes — mirror CryptoErrorCode enum groupings from common.proto
 * -------------------------------------------------------------------------
 *
 *   1–9    Key errors
 *  10–19   Template errors
 *  20–29   Provider errors
 *  30–39   Policy errors
 *  40–49   Operation errors
 *  50–59   Migration errors
 *  60–69   Crypto material errors
 *  70–79   Resource / runtime errors
 * 100+     Implementation-defined vendor extensions
 * ------------------------------------------------------------------------- */

/* Key errors (1–9) */
#define CITIUS_KEY_NOT_FOUND          ((CITIUS_RV)1)
#define CITIUS_KEY_ALREADY_EXISTS     ((CITIUS_RV)2)
#define CITIUS_KEY_INACTIVE           ((CITIUS_RV)3)
#define CITIUS_KEY_COMPROMISED        ((CITIUS_RV)4)
#define CITIUS_KEY_DESTROYED          ((CITIUS_RV)5)
#define CITIUS_KEY_TYPE_MISMATCH      ((CITIUS_RV)6)
#define CITIUS_KEY_SIZE_INVALID       ((CITIUS_RV)7)
#define CITIUS_KEY_NOT_EXTRACTABLE    ((CITIUS_RV)8)
#define CITIUS_KEY_ROTATION_FAILED    ((CITIUS_RV)9)

/* Template errors (10–19) */
#define CITIUS_TEMPLATE_NOT_FOUND     ((CITIUS_RV)10)
#define CITIUS_TEMPLATE_DEPRECATED    ((CITIUS_RV)11)
#define CITIUS_TEMPLATE_FORBIDDEN     ((CITIUS_RV)12)
#define CITIUS_TEMPLATE_EXPERIMENTAL  ((CITIUS_RV)13)
#define CITIUS_SCOPE_MISMATCH         ((CITIUS_RV)14)
#define CITIUS_ALGORITHM_NOT_SUPPORTED ((CITIUS_RV)15)
#define CITIUS_PARAMETER_INVALID      ((CITIUS_RV)16)
#define CITIUS_SCOPE_NOT_SUPPORTED    ((CITIUS_RV)17)

/* Provider errors (20–29) */
#define CITIUS_PROVIDER_NOT_FOUND     ((CITIUS_RV)20)
#define CITIUS_PROVIDER_UNAVAILABLE   ((CITIUS_RV)21)
#define CITIUS_PROVIDER_ERROR         ((CITIUS_RV)22)
#define CITIUS_PROVIDER_NOT_FIPS      ((CITIUS_RV)23)
#define CITIUS_PROVIDER_ALREADY_REGISTERED ((CITIUS_RV)26)

/* Policy errors (30–39) */
#define CITIUS_POLICY_VIOLATION       ((CITIUS_RV)30)
#define CITIUS_POLICY_NOT_FOUND       ((CITIUS_RV)31)
#define CITIUS_POLICY_ALREADY_EXISTS  ((CITIUS_RV)32)
#define CITIUS_POLICY_INVALID         ((CITIUS_RV)33)
#define CITIUS_POLICY_CONFLICT        ((CITIUS_RV)34)

/* Operation errors (40–49) */
#define CITIUS_OPERATION_NOT_SUPPORTED ((CITIUS_RV)40)
#define CITIUS_OPERATION_ACTIVE       ((CITIUS_RV)41)
#define CITIUS_OPERATION_NOT_ACTIVE   ((CITIUS_RV)42)
#define CITIUS_VERIFICATION_FAILED    ((CITIUS_RV)43)
#define CITIUS_DECRYPTION_FAILED      ((CITIUS_RV)44)
#define CITIUS_INVALID_NONCE          ((CITIUS_RV)45)
#define CITIUS_TAG_MISMATCH           ((CITIUS_RV)46)
#define CITIUS_INVALID_SIGNATURE      ((CITIUS_RV)47)

/* Migration errors (50–59) */
#define CITIUS_MIGRATION_FAILED       ((CITIUS_RV)50)
#define CITIUS_MIGRATION_NOT_SUPPORTED ((CITIUS_RV)51)
#define CITIUS_MIGRATION_POLICY_DENIED ((CITIUS_RV)52)
#define CITIUS_MIGRATION_VERSION_MISMATCH ((CITIUS_RV)53)

/* Crypto material errors (60–69) */
#define CITIUS_INVALID_KEY_MATERIAL   ((CITIUS_RV)60)
#define CITIUS_INVALID_CIPHERTEXT     ((CITIUS_RV)61)
#define CITIUS_INVALID_PLAINTEXT      ((CITIUS_RV)62)
#define CITIUS_INVALID_SIGNATURE_DATA ((CITIUS_RV)63)
#define CITIUS_INVALID_MAC_DATA       ((CITIUS_RV)64)
#define CITIUS_ENCODING_ERROR         ((CITIUS_RV)65)
#define CITIUS_DECODING_ERROR         ((CITIUS_RV)66)

/* Resource / runtime errors (70–79) */
#define CITIUS_BUFFER_TOO_SMALL       ((CITIUS_RV)70)
#define CITIUS_OUT_OF_MEMORY          ((CITIUS_RV)71)
#define CITIUS_NULL_ARGUMENT          ((CITIUS_RV)72)
#define CITIUS_GENERAL_ERROR          ((CITIUS_RV)73)
#define CITIUS_FUNCTION_NOT_SUPPORTED ((CITIUS_RV)74)
#define CITIUS_RANDOM_SEED_REQUIRED   ((CITIUS_RV)75)

/* =========================================================================
 * Byte buffer helpers
 * ========================================================================= */

/**
 * @brief Immutable view of a byte sequence.
 *
 * Mirrors proto `bytes` fields.  Does not own the pointed-to memory.
 */
typedef struct {
    const uint8_t *data;   /**< Pointer to the first byte; may be NULL if length == 0 */
    size_t         length; /**< Number of valid bytes at data                          */
} citius_byte_buffer_t;

/**
 * @brief Caller-owned mutable output buffer.
 *
 * Pattern for output parameters:
 *   - Pass with capacity == 0 (or data == NULL) to receive the required size
 *     in `length` without performing the operation (size-query mode).
 *   - Pass with capacity >= required size to receive the actual output.
 *   - On success `length` is set to the number of bytes written.
 */
typedef struct {
    uint8_t *data;     /**< Caller-allocated storage; may be NULL for size queries */
    size_t   length;   /**< [out] Bytes written (or required if capacity == 0)     */
    size_t   capacity; /**< [in]  Total bytes available at data                    */
} citius_mutable_buffer_t;

/** Convenience macro to declare a stack-allocated mutable buffer. */
#define CITIUS_STACK_BUFFER(name, sz) \
    uint8_t name##_storage_[sz];      \
    citius_mutable_buffer_t name = { name##_storage_, 0, (sz) }

/* =========================================================================
 * Key-value maps
 * ========================================================================= */

/**
 * @brief String-to-string key-value map.
 *
 * Mirrors proto `map<string, string>` fields (e.g. user_context,
 * additional_properties, capabilities).
 */
typedef struct {
    const char  **keys;
    const char  **values;
    size_t        size;
} citius_map_t;

/**
 * @brief String-to-bytes key-value map.
 *
 * Mirrors proto `map<string, bytes>` fields (e.g. VendorOutput.parameters).
 */
typedef struct {
    const char           **keys;
    citius_byte_buffer_t  *values;
    size_t                 size;
} citius_byte_map_t;

/* =========================================================================
 * Utility
 * ========================================================================= */

/**
 * @brief Returns a human-readable string for a CITIUS_RV value.
 *
 * The returned pointer is a string literal; do not free it.
 * Unknown codes return "CITIUS_UNKNOWN".
 */
const char *citius_rv_to_string(CITIUS_RV rv);

/* =========================================================================
 * Library lifecycle
 * ========================================================================= */

/**
 * @brief Initialise the Citius library.
 *
 * Must be called once before any other Citius function.
 * Thread-safe; subsequent calls return CITIUS_OK without re-initialising.
 */
CITIUS_RV citius_init(void);

/**
 * @brief Finalise the Citius library and release all global resources.
 */
CITIUS_RV citius_finalize(void);

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_TYPES_H */
