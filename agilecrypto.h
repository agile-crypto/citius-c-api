/* SPDX-License-Identifier: Apache-2.0
 *
 * agilecrypto.h — Abstract Cryptographic API, C binding.
 *
 * A transport-agnostic, provider-agnostic, policy-driven cryptographic API.
 * Cryptographic INTENT ("I need authenticated encryption") is separated from
 * IMPLEMENTATION ("AES-256-GCM on this HSM"), so algorithms can be governed and
 * migrated centrally — including the transition to post-quantum cryptography —
 * without rewriting application code.
 *
 * This header is the C projection of the protobuf specification in
 * github.com/agile-crypto/api. The protobuf remains normative for the
 * VOCABULARY and SEMANTICS; this header is normative for the LOCAL ABI.
 * See docs/C_API_MAPPING.md for the full derivation and rationale.
 *
 * Coverage: all 98 RPCs across all 7 services.
 *
 * QUICK START
 * -----------
 *   agc_ctx_config cfg; AGC_INIT(&cfg);
 *   cfg.mode = AGC_MODE_EMBEDDED;
 *   cfg.default_policy = "prod-encryption";
 *   agc_ctx *ctx; agc_ctx_open(&cfg, &ctx);
 *
 *   agc_scope_spec scope; AGC_INIT(&scope);
 *   scope.kind = AGC_SCOPE_KIND_AEAD;
 *   scope.u.aead.scope = AGC_AEAD_SCOPE_STANDARD;
 *   scope.u.aead.security.security_strength_bits = 256;
 *   scope.u.aead.security.fips_approved = AGC_TRUE;
 *
 *   agc_create_key_params ck; AGC_INIT(&ck);
 *   ck.name = "app-encryption-key";
 *   ck.scope_spec = &scope;
 *   agc_key_info *ki;
 *   agc_create_key(ctx, &ck, &ki, NULL);
 *
 *   agc_encrypt_params ep; AGC_INIT(&ep);
 *   ep.kind = AGC_ENCRYPT_PARAMS_AEAD;
 *   ep.u.aead.aad = (agc_slice){ hdr, hdr_len };
 *
 *   agc_encrypt_request er; AGC_INIT(&er);
 *   er.key_name  = "app-encryption-key";
 *   er.plaintext = (agc_slice){ pt, pt_len };
 *   er.params    = &ep;
 *
 *   size_t n = 0;
 *   agc_encrypt(ctx, &er, (agc_buf){0}, &n, NULL);      // size query
 *   uint8_t *ct = malloc(n);
 *   agc_metadata *md = NULL;
 *   agc_encrypt(ctx, &er, (agc_buf){ct, n}, &n, &md);   // real call
 *   // store ct[0..n) together with agc_metadata_encode(md, ...)
 *
 * Note that no algorithm identifier appears anywhere above. Migrating this key
 * to ML-KEM-backed hybrid AEAD is a TransformKey call plus a policy edit; not
 * one line of the code above changes. That property is the reason the API
 * exists, and preserving it end to end is the acceptance criterion for this
 * C binding.
 */

#ifndef AGILECRYPTO_H
#define AGILECRYPTO_H

#include "agc_types.h"
#include "agc_core.h"
#include "agc_key.h"
#include "agc_crypto.h"
#include "agc_stream.h"
#include "agc_establish.h"
#include "agc_policy.h"
#include "agc_discovery.h"
#include "agc_provider.h"

#endif /* AGILECRYPTO_H */
