/* SPDX-License-Identifier: Apache-2.0
 *
 * Minimal assertion helpers shared by the CTest binaries. Deliberately not a
 * framework: each test is a plain `main()` that exits non-zero on failure,
 * which is all CTest needs.
 */
#ifndef AGC_TEST_HELPERS_H
#define AGC_TEST_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AGC_ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "ASSERT FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while (0)

#define AGC_ASSERT_OK(rc) do { \
    int _rc = (int)(rc); \
    if (_rc != 0) { \
        fprintf(stderr, "ASSERT_OK FAILED %s:%d: rc=%d\n", __FILE__, __LINE__, _rc); \
        exit(1); \
    } \
} while (0)

#define AGC_ASSERT_EQ_INT(a, b) do { \
    long long _a = (long long)(a), _b = (long long)(b); \
    if (_a != _b) { \
        fprintf(stderr, "ASSERT_EQ FAILED %s:%d: %lld != %lld\n", __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } \
} while (0)

#define AGC_ASSERT_EQ_STR(a, b) do { \
    const char *_a = (a), *_b = (b); \
    if (strcmp(_a, _b) != 0) { \
        fprintf(stderr, "ASSERT_EQ_STR FAILED %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, _a, _b); \
        exit(1); \
    } \
} while (0)

#define AGC_ASSERT_MEM_EQ(a, b, n) do { \
    if (memcmp((a), (b), (n)) != 0) { \
        fprintf(stderr, "ASSERT_MEM_EQ FAILED %s:%d\n", __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define AGC_PASS(name) do { printf("%s: PASSED\n", (name)); return 0; } while (0)

#endif /* AGC_TEST_HELPERS_H */
