/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_ext.h -- PROPOSED extensions: constructs with NO corresponding RPC in
 * github.com/agile-crypto/api today (D16). Every symbol here is prefixed
 * agc_ext_ (never agc_<verb>, which is reserved for the 90 real RPCs) and
 * carries an RFC id from docs/PROTO_RFCS.md in its doc comment.
 *
 * Gated behind AGC_ENABLE_PROPOSED_EXTENSIONS (off by default): with the
 * flag off, this header does not exist as far as a build is concerned, and
 * "the core is exactly 90 RPCs, machine-checked by conformance/tier1b_surface.py"
 * stays a true statement regardless of what a build opts into. A symbol
 * whose RFC is rejected is deleted from here outright, never left as dead
 * code with a comment explaining why it doesn't work anymore.
 *
 * NOT included by agilecrypto.h. A caller who wants these must both define
 * AGC_ENABLE_PROPOSED_EXTENSIONS and #include <agc/agc_ext.h> explicitly --
 * two deliberate steps, not one, so nobody links against this surface by
 * accident.
 */
#ifndef AGC_EXT_H
#define AGC_EXT_H

#ifndef AGC_ENABLE_PROPOSED_EXTENSIONS
#error "agc_ext.h requires -DAGC_ENABLE_PROPOSED_EXTENSIONS=1 (see docs/PROTO_RFCS.md)"
#endif

#include "agc_core.h"
#include "agc_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * RFC-01: UpdateKeyState
 *
 * KeyLifecycleState has 8 values (PRE_ACTIVE, ACTIVE, SUSPENDED,
 * DEACTIVATED, COMPROMISED, DESTROYED, DESTROYED_COMPROMISED) and, in the
 * proto today, no RPC that moves a key between them -- NIST SP 800-57 §7's
 * state machine is unimplementable without one. `reason` is REQUIRED when
 * `target == AGC_KEY_LIFECYCLE_STATE_COMPROMISED` (the one transition an
 * audit trail cannot do without) and optional otherwise.
 * -------------------------------------------------------------------------- */
AGC_API agc_rc agc_ext_update_key_state(agc_ctx *ctx, const char *name,
                                         agc_key_lifecycle_state target,
                                         const char *reason, agc_key_info **out_key);

/* --------------------------------------------------------------------------
 * RFC-14: CancelOperation
 *
 * Pure convenience over two calls that already exist in core (commit 5,
 * D10): agc_session_attach() recovers a handle from a wire operation_id,
 * agc_session_cancel() force-closes it. Proposed anyway because a real
 * wire CancelOperation RPC would still need exactly this C shape on the
 * EMBEDDED/LOCAL side. Does not free/unregister the session -- exactly
 * like calling agc_session_cancel() directly, the original creator still
 * owns the handle and must eventually call agc_session_free() on it.
 * -------------------------------------------------------------------------- */
AGC_API agc_rc agc_ext_cancel_operation(agc_ctx *ctx, const char *operation_id, const char *reason);

/* --------------------------------------------------------------------------
 * RFC-13: MAC streaming
 *
 * MacScope.MAC_SCOPE_STREAMING exists in the proto with no RPC family
 * behind it -- every other primitive with a streaming scope kind has one.
 * Mirrors the multi-part digest family (agc_digest_init/update/final)
 * exactly: Update accumulates message bytes, Final computes the MAC once
 * over everything accumulated -- the stub backend has no real incremental
 * MAC primitive to expose, same honesty as every other stub construction
 * in this tree (RECONCILIATION_PLAN.md's stub cryptography).
 * -------------------------------------------------------------------------- */
typedef struct agc_ext_mac_init_params {
    size_t                 struct_size;
    const char            *key_name;      /* REQUIRED */
    const agc_mac_params  *params;        /* REQUIRED -- the oneof is required */
    const char            *operation_id;  /* NULL => generated (D10) */
    agc_kv_list            user_context;
} agc_ext_mac_init_params;

AGC_API agc_rc agc_ext_generate_mac_init(agc_ctx *ctx, const agc_ext_mac_init_params *p,
                                          agc_session **out_session);
AGC_API agc_rc agc_ext_generate_mac_update(agc_session *s, agc_slice data_chunk);
AGC_API agc_rc agc_ext_generate_mac_final(agc_session *s, agc_buf out_mac, size_t *out_len,
                                           agc_metadata **out_md);

AGC_API agc_rc agc_ext_verify_mac_init(agc_ctx *ctx, const agc_ext_mac_init_params *p,
                                        agc_session **out_session);
AGC_API agc_rc agc_ext_verify_mac_update(agc_session *s, agc_slice data_chunk);
/* Comparison is constant-time inside the library (agc_ct_equal), same as
 * the single-shot agc_verify_mac() (fail-closed per D9: *out_valid is set
 * to 0 before any work, and a mismatch also returns a non-OK agc_rc). */
AGC_API agc_rc agc_ext_verify_mac_final(agc_session *s, agc_slice mac, int *out_valid,
                                         agc_metadata **out_md);

#ifdef __cplusplus
}
#endif
#endif /* AGC_EXT_H */
