/* SPDX-License-Identifier: Apache-2.0 */
#include "agc_internal.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

/* One record per thread, overwritten by the next failing call on that
 * thread. Strings are duplicated into thread-local storage owned here so
 * the caller of agc_last_error() gets pointers that outlive the call that
 * produced the failure (but not the next failure on the same thread).
 *
 * This uses pthread_key_t rather than a plain `_Thread_local` struct
 * deliberately: `_Thread_local` storage is reclaimed as raw memory when a
 * thread exits, with no hook to free heap pointers living inside it, which
 * leaked one record per thread that had ever recorded an error (caught by
 * LeakSanitizer while exercising test_error.c's thread-local test). A
 * pthread_key_t destructor runs on thread exit and closes that gap. */

struct agc__error_state {
    agc_rc rc;
    char  *message;
    char  *domain;
    char  *reason;
    char  *provider_id;
    int64_t provider_code;
    char  *failed_check;
};

static pthread_key_t g_err_key;
static pthread_once_t g_err_key_once = PTHREAD_ONCE_INIT;

static void free_state_contents(struct agc__error_state *st)
{
    free(st->message);
    free(st->domain);
    free(st->reason);
    free(st->provider_id);
    free(st->failed_check);
}

static void err_destructor(void *p)
{
    if (!p) return;
    struct agc__error_state *st = p;
    free_state_contents(st);
    free(st);
}

static void make_key(void)
{
    pthread_key_create(&g_err_key, err_destructor);
}

/* Returns this thread's state, allocating it on first use if `create` is
 * non-zero. Returns NULL if `create` is zero and the thread has never
 * recorded an error, or on allocation failure. */
static struct agc__error_state *get_state(int create)
{
    pthread_once(&g_err_key_once, make_key);
    struct agc__error_state *st = pthread_getspecific(g_err_key);
    if (!st && create) {
        st = calloc(1, sizeof(*st));
        if (st) pthread_setspecific(g_err_key, st);
    }
    return st;
}

static char *dup_or_null(const char *s)
{
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *out = malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

void agc__set_error(agc_rc rc, const char *message, const char *domain,
                     const char *reason, const char *provider_id,
                     int64_t provider_code, const char *failed_check)
{
    struct agc__error_state *st = get_state(1);
    if (!st) return; /* allocation failure: the rc return value still carries
                       * the outcome, only the detail record is unavailable */

    free_state_contents(st);
    memset(st, 0, sizeof(*st));
    st->rc = rc;
    st->message = dup_or_null(message);
    st->domain = dup_or_null(domain);
    st->reason = dup_or_null(reason);
    st->provider_id = dup_or_null(provider_id);
    st->provider_code = provider_code;
    st->failed_check = dup_or_null(failed_check);
}

void agc__clear_error_for_call(void)
{
    struct agc__error_state *st = get_state(0);
    if (st) {
        free_state_contents(st);
        memset(st, 0, sizeof(*st));
    }
}

agc_rc agc_last_error(agc_error_detail *out)
{
    if (!out) return AGC_ERR_INVALID_ARGUMENT;
    if (out->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;  /* forgot AGC_INIT */

    struct agc__error_state *st = get_state(0);
    static const struct agc__error_state empty; /* AGC_OK, every pointer NULL */
    const struct agc__error_state *src = st ? st : &empty;

    if (AGC_FIELD_FITS(out, rc))            out->rc = src->rc;
    if (AGC_FIELD_FITS(out, message))       out->message = src->message;
    if (AGC_FIELD_FITS(out, domain))        out->domain = src->domain;
    if (AGC_FIELD_FITS(out, reason))        out->reason = src->reason;
    if (AGC_FIELD_FITS(out, provider_id))   out->provider_id = src->provider_id;
    if (AGC_FIELD_FITS(out, provider_code)) out->provider_code = src->provider_code;
    if (AGC_FIELD_FITS(out, failed_check))  out->failed_check = src->failed_check;
    return AGC_OK;
}

void agc_clear_error(void)
{
    agc__clear_error_for_call();
}
