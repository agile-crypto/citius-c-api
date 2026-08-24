/* SPDX-License-Identifier: Apache-2.0
 *
 * agc_core.h — Abstract Cryptographic API, C binding: core runtime.
 *
 * HAND-WRITTEN. Grows across the reconciliation commits (see
 * RECONCILIATION_PLAN.md §6): this commit adds only library version info.
 * Context, error handling, handles, metadata, iterators and memory hygiene
 * land in commit 5 once agc_types.h (commit 2) and the scalar/scope/param
 * headers (commits 3-4) exist for them to build on.
 */

#ifndef AGC_CORE_H
#define AGC_CORE_H

#include "agc_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Compile-time vs run-time version check. Callers SHOULD assert compatibility
 * at startup; a mismatch in major version means the header and the shared
 * object disagree about struct layout. */
AGC_API void         agc_version(int *major, int *minor, int *patch);
AGC_API const char  *agc_version_string(void);   /* e.g. "1.0.0" */
AGC_API const char  *agc_build_info(void);       /* provider set, FIPS mode, git rev */

#ifdef __cplusplus
}
#endif
#endif /* AGC_CORE_H */
