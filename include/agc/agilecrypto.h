/* SPDX-License-Identifier: Apache-2.0
 *
 * agilecrypto.h — Abstract Cryptographic API, C binding.
 *
 * A transport-agnostic, provider-agnostic, policy-driven cryptographic API.
 * Cryptographic INTENT ("I need authenticated encryption") is separated from
 * IMPLEMENTATION ("AES-256-GCM on this HSM"), so algorithms can be governed
 * and migrated centrally without rewriting application code.
 *
 * This header is the C projection of the protobuf specification in
 * github.com/agile-crypto/api (package caas.crypto.v1). The protobuf remains
 * normative for VOCABULARY and SEMANTICS; this header is normative for the
 * LOCAL ABI. See docs/C_API_MAPPING.md for the derivation and
 * RECONCILIATION_PLAN.md for how this tree was assembled.
 *
 * Coverage: all 90 RPCs across all 7 services. Every deliberate divergence
 * from the wire specification is recorded in conformance/DIVERGENCES.yaml and
 * enforced by the conformance suite (commit 12) — there is no undeclared
 * third category between "matches the proto" and "documented exception".
 *
 * This aggregate header grows across the reconciliation commits; see
 * RECONCILIATION_PLAN.md §6 for the sequencing.
 */

#ifndef AGILECRYPTO_H
#define AGILECRYPTO_H

#include "agc_abi.h"
#include "agc_types.h"
#include "agc_scope.h"
#include "agc_params.h"
#include "agc_algorithm_params.h"
#include "agc_core.h"
#include "agc_metadata.h"
#include "agc_key_types.h"
#include "agc_key.h"
#include "agc_crypto_types.h"
#include "agc_crypto.h"
#include "agc_stream.h"
#include "agc_establish_types.h"
#include "agc_establish.h"
#include "agc_policy_types.h"
#include "agc_policy.h"
#include "agc_discovery_types.h"
#include "agc_discovery.h"
#include "agc_provider.h"

#endif /* AGILECRYPTO_H */
