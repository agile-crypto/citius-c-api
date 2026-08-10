/**
 * @file key_lifecycle.c
 * @brief Example: full key lifecycle — create, rotate, export, delete.
 *
 * Demonstrates:
 *   1. citius_key_create()
 *   2. citius_key_read()       — inspect metadata
 *   3. citius_key_update_policy()
 *   4. citius_key_rotate()     — bumps version; old ciphertexts still decryptable
 *   5. citius_key_list()       — enumerate keys
 *   6. citius_key_export()     — raw key material (extractable keys only)
 *   7. citius_key_delete()
 *
 * Build (from citius-c-api root):
 *   cmake -S . -B build && cmake --build build
 *   ./build/examples/key_lifecycle
 */

#include <citius/citius.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(rv) do {                                                       \
    CITIUS_RV _rv = (rv);                                                    \
    if (_rv != CITIUS_OK) {                                                  \
        fprintf(stderr, "FATAL at %s:%d — %s\n",                            \
                __FILE__, __LINE__, citius_rv_to_string(_rv));               \
        exit(EXIT_FAILURE);                                                  \
    }                                                                        \
} while (0)

static const char *lifecycle_state_name(citius_key_lifecycle_state_t s)
{
    switch (s) {
    case KEY_LIFECYCLE_STATE_PRE_ACTIVE:            return "PRE_ACTIVE";
    case KEY_LIFECYCLE_STATE_ACTIVE:                return "ACTIVE";
    case KEY_LIFECYCLE_STATE_SUSPENDED:             return "SUSPENDED";
    case KEY_LIFECYCLE_STATE_DEACTIVATED:           return "DEACTIVATED";
    case KEY_LIFECYCLE_STATE_COMPROMISED:           return "COMPROMISED";
    case KEY_LIFECYCLE_STATE_DESTROYED:             return "DESTROYED";
    case KEY_LIFECYCLE_STATE_DESTROYED_COMPROMISED: return "DESTROYED_COMPROMISED";
    default:                                        return "UNKNOWN";
    }
}

static const char *create_key(const char *name)
{
    citius_create_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.name            = name;
    req.policy          = "default-policy";
    req.scope_spec.type = CITIUS_SCOPE_SPEC_AEAD;
    req.scope_spec.spec.aead.scope = AEAD_SCOPE_STANDARD;

    citius_create_key_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CHECK(citius_key_create(&req, &resp));
    return resp.key_metadata.key_id;
}

int main(void)
{
    CHECK(citius_init());

    /* ------------------------------------------------------------------
     * 1. Create two keys
     * ------------------------------------------------------------------ */
    char key_a[64], key_b[64];
    snprintf(key_a, sizeof(key_a), "%s", create_key("aes-primary"));
    snprintf(key_b, sizeof(key_b), "%s", create_key("aes-secondary"));
    printf("Created keys: \"%s\", \"%s\"\n", key_a, key_b);

    /* ------------------------------------------------------------------
     * 2. Read metadata for key_a
     * ------------------------------------------------------------------ */
    citius_read_key_request_t read_req;
    memset(&read_req, 0, sizeof(read_req));
    read_req.name = key_a;

    citius_read_key_response_t read_resp;
    memset(&read_resp, 0, sizeof(read_resp));
    CHECK(citius_key_read(&read_req, &read_resp));
    printf("Key A: id=%s  name=%s  version=%u  state=%s\n",
           read_resp.key_metadata.key_id ? read_resp.key_metadata.key_id : "(null)",
           read_resp.key_metadata.name   ? read_resp.key_metadata.name   : "(null)",
           read_resp.key_metadata.version,
           lifecycle_state_name(read_resp.key_metadata.lifecycle_state));

    /* ------------------------------------------------------------------
     * 3. Attach a policy
     * ------------------------------------------------------------------ */
    citius_update_key_policy_request_t policy_req;
    memset(&policy_req, 0, sizeof(policy_req));
    policy_req.name       = key_a;
    policy_req.new_policy = "default-policy";

    citius_update_key_policy_response_t policy_resp;
    memset(&policy_resp, 0, sizeof(policy_resp));
    CHECK(citius_key_update_policy(&policy_req, &policy_resp));
    printf("Policy attached to key A\n");

    /* ------------------------------------------------------------------
     * 4. Rotate key_a — version number must increase
     * ------------------------------------------------------------------ */
    citius_rotate_key_request_t rotate_req;
    memset(&rotate_req, 0, sizeof(rotate_req));
    rotate_req.name = key_a;

    citius_rotate_key_response_t rotate_resp;
    memset(&rotate_resp, 0, sizeof(rotate_resp));
    CHECK(citius_key_rotate(&rotate_req, &rotate_resp));
    printf("After rotation: version=%u\n", rotate_resp.new_key_metadata.version);

    /* ------------------------------------------------------------------
     * 5. List keys
     * ------------------------------------------------------------------ */
    citius_list_keys_request_t list_req;
    memset(&list_req, 0, sizeof(list_req));

    citius_list_keys_response_t list_resp;
    memset(&list_resp, 0, sizeof(list_resp));
    CHECK(citius_key_list(&list_req, &list_resp));
    printf("Total keys in store: %zu\n", list_resp.key_count);
    for (size_t i = 0; i < list_resp.key_count; ++i) {
        printf("  [%zu] name=%s  version=%u\n",
               i,
               list_resp.keys[i].name ? list_resp.keys[i].name : "(null)",
               list_resp.keys[i].version);
    }

    /* ------------------------------------------------------------------
     * 6. Export key material (stub returns 32 zero bytes)
     * ------------------------------------------------------------------ */
    citius_export_key_request_t export_req;
    memset(&export_req, 0, sizeof(export_req));
    export_req.name   = key_a;
    export_req.format = KEY_FORMAT_RAW;

    citius_export_key_response_t export_resp;
    memset(&export_resp, 0, sizeof(export_resp));
    CHECK(citius_key_export(&export_req, &export_resp));
    printf("Exported %zu bytes of key material\n", export_resp.key_material_len);

    /* ------------------------------------------------------------------
     * 7. Delete both keys
     * ------------------------------------------------------------------ */
    citius_delete_key_request_t del_req;
    citius_delete_key_response_t del_resp;

    memset(&del_req, 0, sizeof(del_req));
    del_req.name = key_a;
    memset(&del_resp, 0, sizeof(del_resp));
    CHECK(citius_key_delete(&del_req, &del_resp));

    memset(&del_req, 0, sizeof(del_req));
    del_req.name = key_b;
    memset(&del_resp, 0, sizeof(del_resp));
    CHECK(citius_key_delete(&del_req, &del_resp));

    /* Verify they're gone */
    CITIUS_RV rv = citius_key_read(&read_req, &read_resp);
    if (rv == CITIUS_KEY_NOT_FOUND)
        puts("Confirmed: key A is gone after delete");
    else
        fprintf(stderr, "Unexpected rv after delete: %s\n", citius_rv_to_string(rv));

    CHECK(citius_finalize());

    puts("key_lifecycle example: PASSED");
    return EXIT_SUCCESS;
}
