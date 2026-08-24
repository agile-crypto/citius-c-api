/* SPDX-License-Identifier: Apache-2.0
 * Exercises the generated agc_types.c at runtime: name<->value round trips
 * and the agc_rc helpers, across both the local and the wire-derived range.
 */
#include "agilecrypto.h"
#include "test_helpers.h"

int main(void)
{
    /* generated enum -> string */
    AGC_ASSERT_EQ_STR(agc_aead_scope_name(AGC_AEAD_SCOPE_STANDARD), "AEAD_SCOPE_STANDARD");
    AGC_ASSERT_EQ_STR(agc_crypto_operation_name(AGC_CRYPTO_OPERATION_ENCRYPT), "CRYPTO_OPERATION_ENCRYPT");

    /* string -> generated enum, including the failure path */
    agc_aead_scope scope;
    AGC_ASSERT_OK(agc_aead_scope_from_name("AEAD_SCOPE_DETERMINISTIC", &scope));
    AGC_ASSERT_EQ_INT(scope, AGC_AEAD_SCOPE_DETERMINISTIC);
    AGC_ASSERT_EQ_INT(agc_aead_scope_from_name("NOT_A_REAL_VALUE", &scope), AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT_EQ_INT(agc_aead_scope_from_name(NULL, &scope), AGC_ERR_INVALID_ARGUMENT);

    /* deprecated values are retained at their proto numeric value */
    AGC_ASSERT_EQ_INT(AGC_HASH_ALGORITHM_SHA1, 100);
    AGC_ASSERT_EQ_INT(AGC_HASH_ALGORITHM_MD5, 101);

    /* the promoted nested enum */
    AGC_ASSERT_EQ_STR(agc_combiner_strategy_name(AGC_COMBINER_NESTING), "COMBINER_NESTING");

    /* agc_rc: local range */
    AGC_ASSERT_EQ_STR(agc_rc_name(AGC_OK), "AGC_OK");
    AGC_ASSERT_EQ_STR(agc_rc_name(AGC_ERR_BUFFER_TOO_SMALL), "AGC_ERR_BUFFER_TOO_SMALL");
    AGC_ASSERT(strlen(agc_rc_message(AGC_ERR_BUFFER_TOO_SMALL)) > 0);

    /* agc_rc: wire-derived range, and the reversible transform (D2) */
    AGC_ASSERT_EQ_INT(AGC_ERR_CRYPTO_KEY_NOT_FOUND, -(1000 + 1));
    AGC_ASSERT_EQ_INT(AGC_ERR_CRYPTO_AUTHENTICATION_FAILED, -(1000 + 42));
    int wire = -(AGC_ERR_CRYPTO_AUTHENTICATION_FAILED) - 1000;
    AGC_ASSERT_EQ_INT(wire, 42);
    AGC_ASSERT_EQ_STR(agc_rc_name(AGC_ERR_CRYPTO_KEY_NOT_FOUND), "AGC_ERR_CRYPTO_KEY_NOT_FOUND");

    AGC_PASS("test_types");
}
