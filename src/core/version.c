/* SPDX-License-Identifier: Apache-2.0 */
#include "agc_core.h"

#include <stddef.h>

void agc_version(int *major, int *minor, int *patch)
{
    if (major) *major = AGC_API_VERSION_MAJOR;
    if (minor) *minor = AGC_API_VERSION_MINOR;
    if (patch) *patch = AGC_API_VERSION_PATCH;
}

const char *agc_version_string(void)
{
    return AGC_API_VERSION_STRING ".0";
}

const char *agc_build_info(void)
{
    return "agilecrypto " AGC_API_VERSION_STRING ".0; provider=stub; fips=0";
}
