/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_ext.h -- PROPOSED extensions: constructs with NO corresponding RPC in
 * github.com/agile-crypto/api today (D16). Every symbol here is prefixed
 * agc_ext_ (never agc_<verb>, which is reserved for the real RPCs) and
 * carries an RFC id from docs/PROTO_RFCS.md in its doc comment.
 *
 * Gated behind AGC_ENABLE_PROPOSED_EXTENSIONS (off by default): with the
 * flag off, this header does not exist as far as a build is concerned, and
 * "the core is exactly the proto's RPCs, machine-checked by conformance/tier1b_surface.py"
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

/* Empty: every proposal that was here (RFC-01 UpdateKeyState, RFC-13 MAC
 * streaming, RFC-14 CancelOperation) was accepted into the proto with api
 * v0.3.0 and promoted into the core headers without the agc_ext_ prefix:
 * agc_update_key_state (agc_key.h), agc_generate_mac_init/... and
 * agc_cancel_operation (agc_stream.h). New proposals go here. */

#ifdef __cplusplus
}
#endif
#endif /* AGC_EXT_H */
