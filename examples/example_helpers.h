/* SPDX-License-Identifier: Apache-2.0
 *
 * Minimal shared helper for the example programs: on failure, print the
 * agc_rc name plus whatever agc_last_error() has for it, then exit(1).
 * Real applications should handle errors per-call; these examples fail
 * fast so a broken example is loud, not silently wrong.
 */
#ifndef AGC_EXAMPLE_HELPERS_H
#define AGC_EXAMPLE_HELPERS_H

#include <agilecrypto.h>
#include <stdio.h>
#include <stdlib.h>

static inline void agc_example_check(agc_rc rc, const char *what)
{
    if (rc == AGC_OK) return;
    agc_error_detail detail;
    AGC_INIT(&detail);
    agc_last_error(&detail);
    fprintf(stderr, "%s failed: %s (%s)", what, agc_rc_name(rc), agc_rc_message(rc));
    if (detail.message) fprintf(stderr, " -- %s", detail.message);
    fprintf(stderr, "\n");
    exit(1);
}

#define AGC_EXAMPLE_CHECK(call) agc_example_check((call), #call)

#endif /* AGC_EXAMPLE_HELPERS_H */
