/* SPDX-License-Identifier: Apache-2.0
 * Exercises the public session surface (commit 5). Session CREATION is an
 * internal-only API (agc__session_create) used by the streaming family
 * implementations landing in commit 9 -- there is no public way to open a
 * session until a concrete operation (agc_encrypt_init, agc_sign_init, ...)
 * exists to open one "for". What is public and testable now is the
 * attach/cancel/free surface's behaviour on a context with no live
 * sessions, which is exercised here; full session lifecycle (create via a
 * real family, Update, Final, ctx-close force-closing an open session) is
 * covered in commit 9's test_streaming.c once those entry points exist.
 */
#include "agilecrypto.h"
#include "test_helpers.h"

int main(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    AGC_ASSERT_OK(agc_ctx_open(&cfg, &ctx));

    /* Attaching an unknown operation_id is the well-defined failure the
     * proto's own semantics call for (a stale/foreign id, not a crash). */
    agc_session *s = (agc_session *)0x1;
    AGC_ASSERT_EQ_INT(agc_session_attach(ctx, "no-such-operation", &s),
                       AGC_ERR_CRYPTO_OPERATION_EXPIRED);
    AGC_ASSERT(s == NULL);

    AGC_ASSERT_EQ_INT(agc_session_attach(NULL, "x", &s), AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT_EQ_INT(agc_session_attach(ctx, NULL, &s), AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT_EQ_INT(agc_session_attach(ctx, "x", NULL), AGC_ERR_INVALID_ARGUMENT);

    /* NULL-safety: cancelling/freeing/inspecting a NULL handle must not
     * crash and must behave as the documented idempotent no-op. */
    AGC_ASSERT_OK(agc_session_cancel(NULL, "no session to cancel"));
    agc_session_free(NULL);
    AGC_ASSERT(agc_session_id(NULL) == NULL);
    AGC_ASSERT_EQ_INT(agc_session_operation(NULL), AGC_CRYPTO_OPERATION_UNSPECIFIED);
    AGC_ASSERT(agc_session_selected_template(NULL) == NULL);

    agc_ctx_close(ctx);
    AGC_PASS("test_session");
}
