/* SPDX-License-Identifier: Apache-2.0
 * Exercises agc_scope_spec and the operation-params unions (commit 4).
 */
#include "agilecrypto.h"
#include "test_helpers.h"

int main(void)
{
    /* Worked example from RECONCILIATION_PLAN.md §3.6: AGC_TRUE, not 1 --
     * the tribool is what lets "quantum-safe required" and "don't care" be
     * expressed with the same type. */
    agc_scope_spec scope;
    AGC_INIT(&scope);
    scope.kind = AGC_SCOPE_KIND_SIGNATURE;
    scope.u.signature.scope = AGC_SIGNATURE_SCOPE_STANDARD;
    scope.u.signature.security.quantum_safe = AGC_TRUE;
    AGC_ASSERT_EQ_INT(scope.kind, AGC_SCOPE_KIND_SIGNATURE);
    AGC_ASSERT_EQ_INT(scope.u.signature.security.quantum_safe, AGC_TRUE);
    /* A zeroed scope_spec (via AGC_INIT) means "no filters", not "not
     * quantum safe" -- security.quantum_safe defaults to AGC_UNSET == 0. */
    agc_scope_spec any_scope;
    AGC_INIT(&any_scope);
    AGC_ASSERT_EQ_INT(any_scope.kind, AGC_SCOPE_KIND_NONE);
    AGC_ASSERT_EQ_INT(any_scope.u.aead.security.quantum_safe, AGC_UNSET);

    /* Tag values are the proto field numbers for agc_scope_kind. */
    AGC_ASSERT_EQ_INT(AGC_SCOPE_KIND_AEAD, 2);
    AGC_ASSERT_EQ_INT(AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION, 12);

    /* agc_encrypt_params: independent tag, NOT a field number (see
     * agc_params.h header comment) -- just confirm NoParams is a tag value,
     * not an empty struct, and that AEAD carries its optional length flag. */
    agc_encrypt_params ep;
    AGC_INIT(&ep);
    ep.kind = AGC_ENCRYPT_PARAMS_NO_PARAMS;
    AGC_ASSERT_EQ_INT(ep.kind, AGC_ENCRYPT_PARAMS_NO_PARAMS);

    agc_encrypt_params ep_aead;
    AGC_INIT(&ep_aead);
    ep_aead.kind = AGC_ENCRYPT_PARAMS_AEAD;
    const uint8_t aad[4] = {0xde, 0xad, 0xbe, 0xef};
    ep_aead.u.aead.aad.data = aad;
    ep_aead.u.aead.aad.len = sizeof(aad);
    ep_aead.u.aead.has_plaintext_length = 1;
    ep_aead.u.aead.plaintext_length = 42;
    AGC_ASSERT_EQ_INT(ep_aead.u.aead.aad.len, 4);
    AGC_ASSERT_EQ_INT(ep_aead.u.aead.plaintext_length, 42);

    /* Fixed-length XTS tweak (buf.validate bytes.len == 16). */
    agc_encrypt_params ep_xts;
    AGC_INIT(&ep_xts);
    ep_xts.kind = AGC_ENCRYPT_PARAMS_XTS;
    AGC_ASSERT_EQ_INT(sizeof(ep_xts.u.xts.tweak), 16);

    /* Bounded SignatureDomainContext (buf.validate bytes.max_len == 255). */
    agc_sign_params sp;
    AGC_INIT(&sp);
    sp.kind = AGC_SIGN_PARAMS_DOMAIN_CONTEXT;
    AGC_ASSERT_EQ_INT(sizeof(sp.u.domain_context.context), 255);

    /* CustomOperationParams tags ARE proto field numbers. */
    AGC_ASSERT_EQ_INT(AGC_CUSTOM_PARAMS_GENERIC, 10);
    AGC_ASSERT_EQ_INT(AGC_CUSTOM_PARAMS_TYPED, 11);

    /* HKDF: absent vs. present-empty salt must be distinguishable. */
    agc_kdf_params kp;
    AGC_INIT(&kp);
    kp.kind = AGC_KDF_PARAMS_HKDF;
    kp.u.hkdf.salt.present = 0;   /* absent => server generates a random salt */
    AGC_ASSERT_EQ_INT(kp.u.hkdf.salt.present, 0);

    /* TLS 1.2 KDF fixed-length randoms (buf.validate bytes.len == 32 each). */
    AGC_ASSERT_EQ_INT(sizeof(kp.u.tls12.client_random), 32);
    AGC_ASSERT_EQ_INT(sizeof(kp.u.tls12.server_random), 32);

    /* ProviderRequirements: zeroed means no filters (all AGC_UNSET). */
    agc_provider_requirements req;
    AGC_INIT(&req);
    AGC_ASSERT_EQ_INT(req.fips_140_certified, AGC_UNSET);
    AGC_ASSERT_EQ_INT(req.struct_size, sizeof(req));

    AGC_PASS("test_scope_params");
}
