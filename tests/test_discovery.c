/**
 * @file test_discovery.c
 * @brief Tests for template/scope discovery functions.
 */

#include "test_helpers.h"

static void test_list_templates_empty(void)
{
    citius_test_init();

    citius_list_templates_request_t req;
    memset(&req, 0, sizeof(req));

    citius_list_templates_response_t resp;
    memset(&resp, 0, sizeof(resp));
    /* Stub returns 0 templates */
    CITIUS_ASSERT_RV(citius_list_templates(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.template_count == 0);

    citius_test_cleanup();
}

static void test_list_templates_with_filter(void)
{
    citius_test_init();

    citius_list_templates_request_t req;
    memset(&req, 0, sizeof(req));
    req.scope_spec.type            = CITIUS_SCOPE_SPEC_SIGNATURE;
    req.scope_spec.spec.signature.security.quantum_safe = 1;

    citius_template_status_t active = TEMPLATE_STATUS_ACTIVE;
    req.allowed_statuses.statuses = &active;
    req.allowed_statuses.count    = 1;

    citius_list_templates_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_list_templates(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.template_count == 0); /* Stub has no templates */

    citius_test_cleanup();
}

static void test_list_scopes(void)
{
    citius_test_init();

    citius_list_scopes_request_t req;
    memset(&req, 0, sizeof(req));

    citius_list_scopes_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_list_scopes(&req, &resp), CITIUS_OK);
    CITIUS_ASSERT(resp.scopes.count == 0); /* Stub returns empty */

    citius_test_cleanup();
}

static void test_get_template_not_found(void)
{
    citius_test_init();

    citius_get_template_request_t req;
    memset(&req, 0, sizeof(req));
    req.template_id = "aes-256-gcm-96-128";

    citius_get_template_response_t resp;
    memset(&resp, 0, sizeof(resp));
    CITIUS_ASSERT_RV(citius_get_template(&req, &resp), CITIUS_TEMPLATE_NOT_FOUND);

    citius_test_cleanup();
}

int main(void)
{
    test_list_templates_empty();
    test_list_templates_with_filter();
    test_list_scopes();
    test_get_template_not_found();
    printf("test_discovery: all tests passed\n");
    return 0;
}
