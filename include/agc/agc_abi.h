/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_abi.h — Abstract Cryptographic API, C binding: ABI infrastructure.
 *
 * HAND-WRITTEN. Never generated. This is the small, stable set of macros every
 * other header depends on: symbol visibility, the version constants, and (from
 * commit 3 onward) the scalar and presence types that have no protobuf source
 * of their own (agc_slice, agc_buf, agc_tribool, ...).
 *
 * Kept separate from agc_types.h so that the "GENERATED — DO NOT EDIT" banner
 * on agc_types.h is actually true. Mixing hand-written scalar idioms into a
 * generated vocabulary file is how that banner stops being trustworthy — see
 * RECONCILIATION_PLAN.md §9 and C_API_COMPARISON.md finding B1.
 */

#ifndef AGC_ABI_H
#define AGC_ABI_H

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * ABI / API version
 * -------------------------------------------------------------------------- */

#define AGC_API_VERSION_MAJOR 1
#define AGC_API_VERSION_MINOR 0
#define AGC_API_VERSION_PATCH 0

/* Matches OperationMetadata.api_version ("major.minor"). */
#define AGC_API_VERSION_STRING "1.0"

#if defined(_WIN32)
#  if defined(AGC_BUILDING_DLL)
#    define AGC_API __declspec(dllexport)
#  elif !defined(AGC_STATIC)
#    define AGC_API __declspec(dllimport)
#  else
#    define AGC_API
#  endif
#else
#  define AGC_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
}
#endif
#endif /* AGC_ABI_H */
