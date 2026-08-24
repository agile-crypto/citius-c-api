/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L /* mlock/munlock */
#include "agc_core.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/mman.h>
#define AGC_HAVE_MLOCK 1
#endif

void agc_secure_zero(void *p, size_t n)
{
    if (!p || n == 0) return;
    /* A volatile pointer write is an observable side effect the C standard
     * forbids the optimiser from eliding, unlike a plain memset() call that
     * a sufficiently aggressive compiler can prove is dead if the buffer is
     * never read again. */
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) {
        *vp++ = 0;
    }
}

int agc_ct_equal(const void *a, const void *b, size_t n)
{
    if (!a || !b) return 0;
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }
    return diff == 0;
}

void *agc_secure_alloc(size_t n)
{
    if (n == 0) return NULL;
    void *p = malloc(n);
    if (p == NULL) return NULL;
#if defined(AGC_HAVE_MLOCK)
    /* Best-effort: a locking failure (e.g. RLIMIT_MEMLOCK) degrades to an
     * ordinary heap allocation rather than failing the call. A context
     * opened with require_locked_memory != 0 is where that requirement is
     * actually enforced (agc_ctx_open), not here.
     *
     * GCC's -Wmaybe-uninitialized misfires on `p` through mlock()'s
     * `const void *` parameter even though the NULL check above makes it
     * unreachable uninitialized; silenced locally rather than for the
     * whole translation unit. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    int lock_rc = mlock(p, n);
    (void)lock_rc;
#pragma GCC diagnostic pop
#endif
    return p;
}

void agc_secure_free(void *p, size_t n)
{
    if (!p) return;
    agc_secure_zero(p, n);
#if defined(AGC_HAVE_MLOCK)
    (void)munlock(p, n);
#endif
    free(p);
}
