/**
 * @file test_key_management.c
 * @brief Tests for the key lifecycle functions.
 */

#include "test_helpers.h"

static void test_create_and_read(void)
{
    citius_test_init();
    const char *key = citius_test_create_key("my-test-key");

    citius_read_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.name = key;

    citius_read_key_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_key_read(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.key_metadata.key_id != NULL);
    CITIUS_ASSERT(resp.key_metadata.lifecycle_state == KEY_LIFECYCLE_STATE_ACTIVE);
    CITIUS_ASSERT(resp.key_metadata.version == 1);

    citius_test_cleanup();
}

static void test_read_nonexistent(void)
{
    citius_test_init();

    citius_read_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.name = "no-such-key";

    citius_read_key_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_key_read(&req, &resp), CITIUS_KEY_NOT_FOUND);
    citius_test_cleanup();
}

static void test_list_keys(void)
{
    citius_test_init();
    citius_test_create_key("k1");
    citius_test_create_key("k2");
    citius_test_create_key("k3");

    citius_list_keys_request_t req;
    memset(&req, 0, sizeof(req));

    citius_list_keys_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_key_list(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.key_count == 3);
    CITIUS_ASSERT(resp.keys[0].name != NULL);

    citius_test_cleanup();
}

static void test_delete(void)
{
    citius_test_init();
    const char *key = citius_test_create_key("to-delete");

    citius_delete_key_request_t del_req;
    citius_delete_key_response_t del_resp;

    memset(&del_req, 0, sizeof(del_req));
    del_req.name = key;
    memset(&del_resp, 0, sizeof(del_resp));
    CITIUS_ASSERT_RV(citius_key_delete(&del_req, &del_resp), CITIUS_OK);

    /* Reading after delete should return KEY_NOT_FOUND */
    citius_read_key_request_t read_req;
    citius_read_key_response_t read_resp;
    memset(&read_req, 0, sizeof(read_req));
    read_req.name = key;
    memset(&read_resp, 0, sizeof(read_resp));
    CITIUS_ASSERT_RV(citius_key_read(&read_req, &read_resp), CITIUS_KEY_NOT_FOUND);

    /* Deleting again should also return KEY_NOT_FOUND */
    CITIUS_ASSERT_RV(citius_key_delete(&del_req, &del_resp), CITIUS_KEY_NOT_FOUND);
    citius_test_cleanup();
}

static void test_rotate(void)
{
    citius_test_init();
    const char *key = citius_test_create_key("to-rotate");

    citius_rotate_key_request_t rot_req;
    memset(&rot_req, 0, sizeof(rot_req));
    rot_req.name = key;

    citius_rotate_key_response_t rot_resp;
    memset(&rot_resp, 0, sizeof(rot_resp));
    CITIUS_ASSERT_RV(citius_key_rotate(&rot_req, &rot_resp), CITIUS_OK);
    CITIUS_ASSERT(rot_resp.new_key_metadata.version == 2);

    citius_test_cleanup();
}

static void test_import_export(void)
{
    citius_test_init();

    citius_import_key_request_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.name        = "imported";
    ip.template_id = "aes-256-gcm";
    ip.format      = KEY_FORMAT_RAW;
    uint8_t fake_key_bytes[32] = {0};
    ip.key_material     = fake_key_bytes;
    ip.key_material_len = 32;

    citius_import_key_response_t ip_resp;
    memset(&ip_resp, 0, sizeof(ip_resp));
    CITIUS_ASSERT_RV(citius_key_import(&ip, &ip_resp), CITIUS_OK);
    const char *key = ip_resp.key_metadata.key_id;
    CITIUS_ASSERT(key != NULL);

    /* Export */
    citius_export_key_request_t exp_req;
    memset(&exp_req, 0, sizeof(exp_req));
    exp_req.name   = key;
    exp_req.format = KEY_FORMAT_RAW;

    citius_export_key_response_t exp_resp;
    memset(&exp_resp, 0, sizeof(exp_resp));
    CITIUS_ASSERT_RV(citius_key_export(&exp_req, &exp_resp), CITIUS_OK);
    CITIUS_ASSERT(exp_resp.key_material_len == 64);

    citius_test_cleanup();
}

static void test_update_policy_and_migrate(void)
{
    citius_test_init();
    const char *key = citius_test_create_key("policy-key");

    citius_update_key_policy_request_t pol_req;
    citius_update_key_policy_response_t pol_resp;

    memset(&pol_req, 0, sizeof(pol_req));
    pol_req.name       = key;
    pol_req.new_policy = "my-policy";
    memset(&pol_resp, 0, sizeof(pol_resp));
    CITIUS_ASSERT_RV(citius_key_update_policy(&pol_req, &pol_resp), CITIUS_OK);

    citius_migrate_key_request_t mig_req;
    memset(&mig_req, 0, sizeof(mig_req));
    mig_req.name                        = key;
    mig_req.target_type                 = CITIUS_MIGRATE_TARGET_INSTANCE_ID;
    mig_req.target.target_instance_id   = "stub";
    mig_req.strategy                    = CITIUS_MIGRATION_STRATEGY_PROVIDER_SWITCH;

    citius_migrate_key_response_t mig_resp;
    memset(&mig_resp, 0, sizeof(mig_resp));
    CITIUS_ASSERT_RV(citius_key_migrate(&mig_req, &mig_resp), CITIUS_OK);
    CITIUS_ASSERT(mig_resp.key_metadata.key_id != NULL);

    citius_test_cleanup();
}

int main(void)
{
    test_create_and_read();
    test_read_nonexistent();
    test_list_keys();
    test_delete();
    test_rotate();
    test_import_export();
    test_update_policy_and_migrate();
    printf("test_key_management: all tests passed\n");
    return 0;
}
