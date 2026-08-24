/* SPDX-License-Identifier: Apache-2.0
 *
 * A real CSPRNG (the OS's, via getrandom()), used for generated key material
 * and (commit 8) GenerateRandom. See the header comment on
 * agc__stub_random() in agc_internal.h for why "stub" does not mean "fake"
 * here.
 */
#define _DEFAULT_SOURCE /* getrandom() */
#include "agc_internal.h"

#include <errno.h>
#include <sys/random.h>

agc_rc agc__stub_random(uint8_t *out, size_t n)
{
    if (!out && n > 0) return AGC_ERR_INVALID_ARGUMENT;
    size_t off = 0;
    while (off < n) {
        ssize_t got = getrandom(out + off, n - off, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            return AGC_ERR_CRYPTO_INSUFFICIENT_ENTROPY;
        }
        off += (size_t)got;
    }
    return AGC_OK;
}
