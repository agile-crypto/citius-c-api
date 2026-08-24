/* SPDX-License-Identifier: Apache-2.0
 * Exercises real fork() poisoning (commit 5, D18). This is the one behaviour
 * in the whole reconciliation with no proto analogue at all -- a gRPC client
 * does not inherit DRBG state, but an in-process library's open agc_ctx is
 * duplicated into the child by fork(2) whether anyone asked for that or not.
 */
#define _POSIX_C_SOURCE 200809L /* fork, waitpid */
#include "agilecrypto.h"
#include "test_helpers.h"

#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    agc_ctx_config cfg;
    AGC_INIT(&cfg);
    cfg.mode = AGC_MODE_EMBEDDED;
    agc_ctx *ctx = NULL;
    AGC_ASSERT_OK(agc_ctx_open(&cfg, &ctx));

    pid_t pid = fork();
    AGC_ASSERT(pid >= 0);

    if (pid == 0) {
        /* Child: `ctx` is a byte-for-byte copy of the parent's, and the
         * pthread_atfork child handler installed by ctx.c must already have
         * flipped its poisoned flag before fork() returned here. The only
         * currently-public witness to that flag is
         * agc_ctx_reinit_after_fork(), which refuses a non-poisoned ctx
         * (proven in test_ctx.c) and accepts a poisoned one. */
        agc_ctx *reinited = NULL;
        agc_rc rc = agc_ctx_reinit_after_fork(ctx, &reinited);
        if (rc != AGC_OK || reinited == NULL) _exit(1);
        if (agc_ctx_mode(reinited) != AGC_MODE_EMBEDDED) _exit(2);
        agc_ctx_close(reinited);
        /* Deliberately do NOT call agc_ctx_close(ctx) here: the poisoned
         * parent context's mutex/session list must never be touched again
         * post-fork (see ctx.c's atfork_child comment) -- closing it would
         * be exactly the "child reuses inherited state" hazard this
         * mechanism exists to prevent. */
        _exit(0);
    }

    int status = 0;
    AGC_ASSERT(waitpid(pid, &status, 0) == pid);
    AGC_ASSERT(WIFEXITED(status));
    AGC_ASSERT_EQ_INT(WEXITSTATUS(status), 0);

    /* The parent's own ctx was never forked *into* -- it is the original,
     * unpoisoned, and still fully usable. */
    AGC_ASSERT_EQ_INT(agc_ctx_mode(ctx), AGC_MODE_EMBEDDED);
    agc_ctx_close(ctx);

    AGC_PASS("test_fork");
}
