/**
 * @file test_helpers.h
 * @brief Shared test helpers for the Citius C API test suite.
 */

#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include "citius/citius.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * CITIUS_ASSERT — abort the test with a descriptive message on failure.
 * ------------------------------------------------------------------------- */

#define CITIUS_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "ASSERTION FAILED: %s\n  at %s:%d\n", \
                    #expr, __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

#define CITIUS_ASSERT_RV(rv, expected) \
    do { \
        CITIUS_RV _rv = (rv); \
        CITIUS_RV _ex = (expected); \
        if (_rv != _ex) { \
            fprintf(stderr, "RV MISMATCH: got %s (%u), expected %s (%u)\n  at %s:%d\n", \
                    citius_rv_to_string(_rv), _rv, \
                    citius_rv_to_string(_ex), _ex, \
                    __FILE__, __LINE__); \
            exit(1); \
        } \
    } while (0)

/* -------------------------------------------------------------------------
 * Library init / cleanup helpers.
 * ------------------------------------------------------------------------- */

static inline void citius_test_init(void)
{
    CITIUS_RV rv = citius_init();
    CITIUS_ASSERT_RV(rv, CITIUS_OK);
}

static inline void citius_test_cleanup(void)
{
    citius_finalize();
}

/* -------------------------------------------------------------------------
 * Convenience: create a key and assert success.
 * ------------------------------------------------------------------------- */

static inline const char *citius_test_create_key(const char *name)
{
    citius_create_key_request_t request;
    memset(&request, 0, sizeof(request));
    request.name                          = name;
    request.policy                        = "default-policy";
    request.scope_spec.type               = CITIUS_SCOPE_SPEC_AEAD;
    request.scope_spec.spec.aead.scope    = AEAD_SCOPE_STANDARD;
    request.scope_spec.spec.aead.security.security_strength_bits = 256;

    citius_create_key_response_t response;
    memset(&response, 0, sizeof(response));
    CITIUS_RV rv = citius_key_create(&request, &response);
    CITIUS_ASSERT_RV(rv, CITIUS_OK);
    CITIUS_ASSERT(response.key_metadata.key_id != NULL);
    return response.key_metadata.key_id;
}

#endif /* TEST_HELPERS_H */
