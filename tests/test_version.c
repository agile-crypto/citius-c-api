/* SPDX-License-Identifier: Apache-2.0
 * Smoke test for commit 1: the scaffold builds, links, and the version
 * symbols resolve.
 */
#include "agilecrypto.h"
#include "test_helpers.h"

int main(void)
{
    int major = -1, minor = -1, patch = -1;
    agc_version(&major, &minor, &patch);
    AGC_ASSERT_EQ_INT(major, AGC_API_VERSION_MAJOR);
    AGC_ASSERT_EQ_INT(minor, AGC_API_VERSION_MINOR);
    AGC_ASSERT_EQ_INT(patch, AGC_API_VERSION_PATCH);

    const char *vs = agc_version_string();
    AGC_ASSERT(vs != NULL);
    AGC_ASSERT(strncmp(vs, "1.0", 3) == 0);

    const char *bi = agc_build_info();
    AGC_ASSERT(bi != NULL);

    AGC_PASS("test_version");
}
