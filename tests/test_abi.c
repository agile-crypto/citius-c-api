/* SPDX-License-Identifier: Apache-2.0
 * Exercises the scalar/presence types and the AGC_INIT idiom (commit 3).
 */
#include "agilecrypto.h"
#include "test_helpers.h"

typedef struct { size_t struct_size; int x; agc_str name; } fake_params;

int main(void)
{
    /* AGC_INIT zeroes and stamps struct_size */
    fake_params p;
    p.x = 99;
    p.name = "stale";
    AGC_INIT(&p);
    AGC_ASSERT_EQ_INT(p.struct_size, sizeof(p));
    AGC_ASSERT_EQ_INT(p.x, 0);
    AGC_ASSERT(p.name == NULL);

    /* AGC_FIELD_FITS: a field fits only if it lies wholly within the
     * caller's struct_size (an older, smaller struct lacks the tail). */
    AGC_ASSERT(AGC_FIELD_FITS(fake_params, &p, name));
    p.struct_size = offsetof(fake_params, name);
    AGC_ASSERT(AGC_FIELD_FITS(fake_params, &p, x));
    AGC_ASSERT(!AGC_FIELD_FITS(fake_params, &p, name));
    p.struct_size = sizeof(p);

    /* agc_tribool: UNSET is the zero value, so a zeroed struct means
     * "no filters" rather than "must be false" -- this is the exact bug
     * documented in C_API_COMPARISON.md finding A4 for the citius_* draft. */
    agc_tribool zeroed = (agc_tribool)0;
    AGC_ASSERT_EQ_INT(zeroed, AGC_UNSET);
    AGC_ASSERT(AGC_UNSET != AGC_FALSE);
    AGC_ASSERT(AGC_UNSET != AGC_TRUE);

    /* agc_slice: borrowed, distinguishes empty (len=0) from a real pointer */
    const uint8_t bytes[3] = {1, 2, 3};
    agc_slice s = { bytes, 3 };
    AGC_ASSERT_EQ_INT(s.len, 3);
    AGC_ASSERT(s.data == bytes);
    agc_slice empty = { NULL, 0 };
    AGC_ASSERT_EQ_INT(empty.len, 0);

    /* agc_optional_slice: absent vs. present-but-empty are distinguishable,
     * which agc_slice alone cannot do (needed for HKDF/PBKDF2/Argon2 salt). */
    agc_optional_slice absent = { {NULL, 0}, 0 };
    agc_optional_slice present_empty = { {NULL, 0}, 1 };
    AGC_ASSERT(absent.present == 0);
    AGC_ASSERT(present_empty.present != 0);

    /* agc_buf: NULL data is the two-call size-query sentinel */
    agc_buf query = {0};
    AGC_ASSERT(query.data == NULL);
    AGC_ASSERT_EQ_INT(query.cap, 0);

    /* agc_kv_list over a small map */
    agc_kv kvs[2] = { {"a", "1"}, {"b", "2"} };
    agc_kv_list kvl = { kvs, 2 };
    AGC_ASSERT_EQ_INT(kvl.count, 2);
    AGC_ASSERT_EQ_STR(kvl.items[1].key, "b");

    /* agc_timestamp: explicit presence, not a lossy string (contrast with
     * C_API_COMPARISON.md's note on AuditReport.report_date staying a
     * string while KeyMetadata.created_time needs real presence) */
    agc_timestamp absent_ts = {0};
    AGC_ASSERT_EQ_INT(absent_ts.present, 0);
    agc_timestamp present_ts = { 1700000000, 0, 1 };
    AGC_ASSERT(present_ts.present != 0);
    AGC_ASSERT_EQ_INT(present_ts.seconds, 1700000000);

    AGC_PASS("test_abi");
}
