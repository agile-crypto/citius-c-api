/**
 * @file citius_metadata.h
 * @brief Operation metadata and typed algorithm output structs.
 *
 * Mirrors api/proto/messages/metadata.proto.
 *
 * OperationMetadata is returned in every single-shot response and must be
 * stored alongside the cryptographic artifact (ciphertext, signature, wrapped
 * key, etc.) so that the corresponding reverse operation (Decrypt, Verify,
 * Unwrap) can recover the system-generated parameters (nonce, IV, etc.) and
 * the key version used.
 *
 * Proto correspondence
 * --------------------
 *  AeadOutput          → citius_aead_output_t
 *  BlockCipherOutput   → citius_block_cipher_output_t
 *  CounterModeOutput   → citius_counter_mode_output_t
 *  StreamCipherOutput  → citius_stream_cipher_output_t
 *  KdfOutput           → citius_kdf_output_t
 *  NoAlgorithmOutput   → CITIUS_ALGO_OUTPUT_NONE discriminator value
 *  VendorOutput        → citius_byte_map_t vendor arm
 *  ProviderOutput      → citius_provider_output_t
 *  OperationMetadata   → citius_operation_metadata_t
 */

#ifndef CITIUS_MESSAGES_METADATA_H
#define CITIUS_MESSAGES_METADATA_H

#include "citius/types/citius_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Typed algorithm output  (proto: ProviderOutput.algorithm_output oneof)
 *
 * These carry the system-generated per-operation parameters that must be
 * stored alongside a cryptographic artifact so the operation can later be
 * reversed or verified.
 * ========================================================================= */

/**
 * System-generated AEAD parameters.  (proto: AeadOutput)
 *
 * Covers: AES-GCM, AES-CCM, AES-GCM-SIV, ChaCha20-Poly1305,
 *         XChaCha20-Poly1305, AES-GMAC.
 *
 * AES-GMAC is authentication-only (no ciphertext) but reuses this struct
 * rather than getting its own: nonce carries the IV and tag_length_bytes
 * carries the MAC length, matching PKCS#11's shared CK_GCM_PARAMS usage.
 *
 * PKCS#11 mapping:
 *   CK_GCM_PARAMS.pIv / CK_CCM_PARAMS.pNonce → nonce
 *   CK_GCM_PARAMS.ulTagBits / 8              → tag_length_bytes
 */
typedef struct {
    citius_byte_buffer_t nonce;             /**< System-generated IV / nonce       */
    uint32_t             tag_length_bytes;  /**< Authentication tag size in bytes  */
} citius_aead_output_t;

/**
 * System-generated block-cipher IV.  (proto: BlockCipherOutput)
 *
 * Covers: AES-CBC, AES-OFB, AES-CFB, 3DES-CBC, Camellia-CBC, ARIA-CBC,
 *         SEED-CBC, GOST 28147 (CFB).
 *
 * PKCS#11 mapping: CK_<CIPHER>_CBC_PARAMS.iv
 */
typedef struct {
    citius_byte_buffer_t iv; /**< System-generated initialisation vector */
} citius_block_cipher_output_t;

/**
 * System-generated CTR initial counter block.  (proto: CounterModeOutput)
 *
 * Covers: AES-CTR, Camellia-CTR.
 *
 * PKCS#11 mapping: CK_AES_CTR_PARAMS.cb / CK_AES_CTR_PARAMS.ulCounterBits
 */
typedef struct {
    citius_byte_buffer_t counter_block; /**< Full 16-byte initial counter block */
    uint32_t             counter_bits;  /**< Rightmost bits used as the counter  */
} citius_counter_mode_output_t;

/**
 * System-generated stream-cipher parameters.  (proto: StreamCipherOutput)
 *
 * Covers: ChaCha20 (non-AEAD), Salsa20 (non-AEAD).
 *
 * PKCS#11 mapping: CK_CHACHA20_PARAMS.pNonce / CK_CHACHA20_PARAMS.pBlockCounter
 */
typedef struct {
    citius_byte_buffer_t nonce;
    citius_byte_buffer_t block_counter; /**< Initial block counter value */
} citius_stream_cipher_output_t;

/**
 * System-generated KDF parameters.  (proto: KdfOutput)
 *
 * Covers: HKDF, PBKDF2, Argon2 (system-generated salt),
 *         SP800-108 Feedback KDF (system-generated IV).
 *
 * PKCS#11 mapping: CK_HKDF_PARAMS.pSalt / CK_SP800_108_FEEDBACK_KDF_PARAMS.pIV
 */
typedef struct {
    citius_byte_buffer_t salt; /**< System-generated salt (HKDF, PBKDF2, Argon2) */
    citius_byte_buffer_t iv;   /**< System-generated IV (SP800-108 Feedback mode) */
} citius_kdf_output_t;

/**
 * Discriminator for citius_provider_output_t.algorithm_output.
 *
 * Providers MUST always set this explicitly.
 * CITIUS_ALGO_OUTPUT_NONE is the intentional "no system-generated params"
 * value (signatures, MACs, AES-KW, asymmetric encryption, XTS, etc.).
 * An uninitialised zero is rejected by the core as a provider bug.
 */
typedef enum {
    CITIUS_ALGO_OUTPUT_NONE          = 0,
    CITIUS_ALGO_OUTPUT_AEAD          = 1,
    CITIUS_ALGO_OUTPUT_BLOCK_CIPHER  = 2,
    CITIUS_ALGO_OUTPUT_COUNTER_MODE  = 3,
    CITIUS_ALGO_OUTPUT_STREAM_CIPHER = 4,
    CITIUS_ALGO_OUTPUT_KDF           = 5,
    CITIUS_ALGO_OUTPUT_VENDOR        = 6
} citius_algo_output_type_t;

/**
 * Tagged union of all provider-supplied algorithm output types.
 * (proto: ProviderOutput)
 */
typedef struct {
    citius_algo_output_type_t type;
    union {
        citius_aead_output_t          aead;
        citius_block_cipher_output_t  block_cipher;
        citius_counter_mode_output_t  counter_mode;
        citius_stream_cipher_output_t stream_cipher;
        citius_kdf_output_t           kdf;
        citius_byte_map_t             vendor; /**< Named vendor parameters (proto: VendorOutput.parameters) */
    } output;
    /**
     * Artifact encoding format.
     * Values: "raw" (default), "der" (ASN.1/DER), "jws" (JOSE), "cbor"
     * NULL is treated as "raw".
     */
    const char *encoding;
} citius_provider_output_t;

/* =========================================================================
 * OperationMetadata  (proto: OperationMetadata)
 *
 * Returned in every response struct.  Callers MUST store this alongside
 * the cryptographic artifact and pass a pointer to the stored copy on
 * the corresponding reverse call (Decrypt, Verify, UnwrapKey, etc.).
 * ========================================================================= */

typedef struct {
    /**
     * Key version used for this operation.
     * Critical for backward compatibility as keys are rotated.
     * Using the wrong version causes decryption failure / garbage plaintext.
     * 0 = not applicable (e.g. digest, random generation).
     */
    uint32_t key_version;

    /**
     * Provider-supplied output — algorithm parameters and encoding.
     * Contains the nonce / IV / salt generated during the operation.
     */
    citius_provider_output_t provider_output;

    /**
     * API version that produced this metadata.
     * Format: "major.minor" (e.g. "1.0").
     * NULL is treated as "1.0".
     */
    const char *api_version;

    /**
     * User-provided context passed through from the request.
     * For audit-trail enrichment only — NOT cryptographically authenticated.
     */
    const citius_map_t *user_context;
} citius_operation_metadata_t;

#ifdef __cplusplus
}
#endif

#endif /* CITIUS_MESSAGES_METADATA_H */
