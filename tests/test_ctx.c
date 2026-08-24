/* SPDX-License-Identifier: Apache-2.0
 * Exercises agc_ctx lifecycle (commit 5): open/close, mode enforcement,
 * struct_size validation, and agc_ctx_reinit_after_fork()'s precondition.
 */
#include "agilecrypto.h"
#include "test_helpers.h"

static void test_embedded_open_close(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    cfg.default_policy = "prod-encryption";

    agc_ctx *ctx = NULL;
    AGC_ASSERT_OK(agc_ctx_open(&cfg, &ctx));
    AGC_ASSERT(ctx != NULL);
    AGC_ASSERT_EQ_INT(agc_ctx_mode(ctx), AGC_MODE_EMBEDDED);

    agc_ctx_close(ctx); /* must not crash; idempotent on NULL too */
    agc_ctx_close(NULL);
}

static void test_local_remote_rejected(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_LOCAL;
    agc_ctx *ctx = (agc_ctx *)0x1; /* sentinel: must be reset to NULL on failure */
    AGC_ASSERT_EQ_INT(agc_ctx_open(&cfg, &ctx), AGC_ERR_NOT_IMPLEMENTED);
    AGC_ASSERT(ctx == NULL);

    cfg.mode = AGC_MODE_REMOTE;
    ctx = (agc_ctx *)0x1;
    AGC_ASSERT_EQ_INT(agc_ctx_open(&cfg, &ctx), AGC_ERR_NOT_IMPLEMENTED);
    AGC_ASSERT(ctx == NULL);
}

static void test_invalid_arguments(void)
{
    agc_ctx *ctx = NULL;
    AGC_ASSERT_EQ_INT(agc_ctx_open(NULL, &ctx), AGC_ERR_INVALID_ARGUMENT);

    agc_ctx_config cfg; /* deliberately NOT AGC_INIT'd: struct_size == garbage-or-0 */
    memset(&cfg, 0, sizeof(cfg)); /* zero counts as "forgot AGC_INIT" -> struct_size == 0 */
    AGC_ASSERT_EQ_INT(agc_ctx_open(&cfg, &ctx), AGC_ERR_INVALID_ARGUMENT);

    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    AGC_ASSERT_EQ_INT(agc_ctx_open(&cfg, NULL), AGC_ERR_INVALID_ARGUMENT);
}

static void test_reinit_requires_poisoned(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    AGC_ASSERT_OK(agc_ctx_open(&cfg, &ctx));

    /* Not actually forked, so this ctx is not poisoned -- reinit must refuse. */
    agc_ctx *reinited = NULL;
    AGC_ASSERT_EQ_INT(agc_ctx_reinit_after_fork(ctx, &reinited), AGC_ERR_INVALID_ARGUMENT);
    AGC_ASSERT(reinited == NULL);

    agc_ctx_close(ctx);
}

static void test_config_strings_copied(void)
{
    /* The config's agc_str fields must be copied by agc_ctx_open: the
     * caller must not be required to keep them alive afterward. */
    agc_ctx *ctx = NULL;
    {
        char policy[] = "on-stack-policy";
        agc_ctx_config cfg;
        AGC_INIT(&cfg);
        cfg.mode = AGC_MODE_EMBEDDED;
        cfg.default_policy = policy;
        AGC_ASSERT_OK(agc_ctx_open(&cfg, &ctx));
        memset(policy, 'X', sizeof(policy) - 1); /* stomp the caller's copy */
    }
    /* If agc_ctx_open had merely borrowed the pointer, ctx would now be
     * corrupted; there is no public accessor for default_policy yet
     * (added alongside agc_create_key in commit 7), so simply surviving
     * to a clean close without a crash/ASan report is the assertion here. */
    agc_ctx_close(ctx);
}

int main(void)
{
    test_embedded_open_close();
    test_local_remote_rejected();
    test_invalid_arguments();
    test_reinit_requires_poisoned();
    test_config_strings_copied();
    AGC_PASS("test_ctx");
}
