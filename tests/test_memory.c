/* SPDX-License-Identifier: Apache-2.0
 * Exercises the memory hygiene functions (commit 5).
 */
#include "agilecrypto.h"
#include "test_helpers.h"

static void test_secure_zero(void)
{
    uint8_t buf[32];
    memset(buf, 0x42, sizeof(buf));
    agc_secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++) AGC_ASSERT_EQ_INT(buf[i], 0);

    /* NULL/zero-length must not crash. */
    agc_secure_zero(NULL, 0);
    agc_secure_zero(buf, 0);
}

static void test_ct_equal(void)
{
    uint8_t a[16], b[16];
    memset(a, 0x11, sizeof(a));
    memset(b, 0x11, sizeof(b));
    AGC_ASSERT(agc_ct_equal(a, b, sizeof(a)) == 1);

    b[15] ^= 0x01; /* differ in the last byte only */
    AGC_ASSERT(agc_ct_equal(a, b, sizeof(a)) == 0);

    b[15] ^= 0x01; /* restore */
    b[0] ^= 0x01;  /* differ in the first byte only */
    AGC_ASSERT(agc_ct_equal(a, b, sizeof(a)) == 0);

    AGC_ASSERT(agc_ct_equal(NULL, b, sizeof(b)) == 0);
    AGC_ASSERT(agc_ct_equal(a, NULL, sizeof(a)) == 0);
}

static void test_secure_alloc_free(void)
{
    uint8_t *p = agc_secure_alloc(64);
    AGC_ASSERT(p != NULL);
    memset(p, 0xAB, 64);
    agc_secure_free(p, 64); /* must zeroize before releasing; nothing to
                              * observe post-free without a UAF read, so
                              * this asserts only that it does not crash. */

    AGC_ASSERT(agc_secure_alloc(0) == NULL);
    agc_secure_free(NULL, 0); /* no-op, must not crash */
}

int main(void)
{
    test_secure_zero();
    test_ct_equal();
    test_secure_alloc_free();
    AGC_PASS("test_memory");
}
