/* SPDX-License-Identifier: Apache-2.0
 * Exercises the thread-local error record and the AGC_FIELD_FITS clamping
 * that agc_last_error() uses (commit 5).
 */
#include "agilecrypto.h"
#include "test_helpers.h"

#include <pthread.h>
#include <stddef.h>

static void trigger_known_error(void)
{
    /* AGC_MODE_LOCAL is rejected with a real agc__set_error() call inside
     * agc_ctx_open -- use it as a reliable, public way to populate the
     * thread-local record without needing internal test hooks. */
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_LOCAL;
    agc_ctx *ctx = NULL;
    agc_rc rc = agc_ctx_open(&cfg, &ctx);
    AGC_ASSERT_EQ_INT(rc, AGC_ERR_NOT_IMPLEMENTED);
}

static void test_last_error_roundtrip(void)
{
    agc_clear_error();
    agc_error_detail empty;
    AGC_INIT(&empty);
    AGC_ASSERT_OK(agc_last_error(&empty));
    AGC_ASSERT_EQ_INT(empty.rc, AGC_OK);
    AGC_ASSERT(empty.message == NULL);

    trigger_known_error();

    agc_error_detail d;
    AGC_INIT(&d);
    AGC_ASSERT_OK(agc_last_error(&d));
    AGC_ASSERT_EQ_INT(d.rc, AGC_ERR_NOT_IMPLEMENTED);
    AGC_ASSERT(d.message != NULL);

    agc_clear_error();
    AGC_INIT(&d);
    AGC_ASSERT_OK(agc_last_error(&d));
    AGC_ASSERT_EQ_INT(d.rc, AGC_OK);
}

static void test_last_error_null(void)
{
    AGC_ASSERT_EQ_INT(agc_last_error(NULL), AGC_ERR_INVALID_ARGUMENT);

    agc_error_detail not_init;
    memset(&not_init, 0, sizeof(not_init)); /* struct_size == 0: forgot AGC_INIT */
    AGC_ASSERT_EQ_INT(agc_last_error(&not_init), AGC_ERR_INVALID_ARGUMENT);
}

/* Proves AGC_FIELD_FITS actually clamps writes to struct_size: allocate the
 * FULL real struct's storage (so no out-of-bounds access ever occurs even if
 * the implementation were buggy), poison it, then claim via struct_size that
 * only the fields up to and including `message` exist. Fields at or after
 * `domain` must be left untouched. */
static void test_field_fits_clamping(void)
{
    trigger_known_error();

    uint8_t storage[sizeof(agc_error_detail)];
    memset(storage, 0xAA, sizeof(storage));
    agc_error_detail *fake = (agc_error_detail *)(void *)storage;
    fake->struct_size = offsetof(agc_error_detail, domain);

    AGC_ASSERT_OK(agc_last_error(fake));

    /* rc and message both lie within the claimed struct_size and must have
     * been written. */
    AGC_ASSERT_EQ_INT(fake->rc, AGC_ERR_NOT_IMPLEMENTED);
    AGC_ASSERT(fake->message != NULL);

    /* domain lies at/after the claimed struct_size and must remain
     * untouched -- still the 0xAA poison pattern. */
    uint8_t domain_bytes[sizeof(fake->domain)];
    memcpy(domain_bytes, &fake->domain, sizeof(domain_bytes));
    for (size_t i = 0; i < sizeof(domain_bytes); i++) {
        AGC_ASSERT_EQ_INT(domain_bytes[i], 0xAA);
    }
}

static void *thread_sets_its_own_error(void *arg)
{
    (void)arg;
    trigger_known_error();
    agc_error_detail d;
    AGC_INIT(&d);
    agc_last_error(&d);
    return (void *)(intptr_t)(d.rc == AGC_ERR_NOT_IMPLEMENTED);
}

static void test_error_is_thread_local(void)
{
    agc_clear_error();

    pthread_t t;
    AGC_ASSERT(pthread_create(&t, NULL, thread_sets_its_own_error, NULL) == 0);
    void *thread_result = NULL;
    pthread_join(t, &thread_result);
    AGC_ASSERT((intptr_t)thread_result == 1);

    /* The main thread never called trigger_known_error() after the last
     * agc_clear_error(), so its own record must still read AGC_OK even
     * though another thread just set AGC_ERR_NOT_IMPLEMENTED on itself. */
    agc_error_detail d;
    AGC_INIT(&d);
    AGC_ASSERT_OK(agc_last_error(&d));
    AGC_ASSERT_EQ_INT(d.rc, AGC_OK);
}

int main(void)
{
    test_last_error_roundtrip();
    test_last_error_null();
    test_field_fits_clamping();
    test_error_is_thread_local();
    AGC_PASS("test_error");
}
