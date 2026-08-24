/* SPDX-License-Identifier: Apache-2.0
 *
 * discovery.c — AlgorithmDiscoveryService over a small STATIC catalog: one
 * template per scope kind, named identically to what
 * agc__derive_stub_template_id() (keystore.c) already produces for a key
 * created by scope_spec alone, so agc_get_template(agc_read_key(...)'s
 * template_id) resolves to a real catalog entry rather than a name nothing
 * else recognises.
 */
#define _POSIX_C_SOURCE 200809L /* strdup */
#include "agc_internal.h"
#include "agc_discovery.h"

#include <stdlib.h>
#include <string.h>

typedef struct catalog_entry {
    const char           *id;
    const char           *display_name;
    const char           *description;
    agc_crypto_primitive  primitive;
    agc_scope_kind        scope_kind;
} catalog_entry;

/* Labels must match scope_kind_label() in keystore.c exactly, since that is
 * what agc__derive_stub_template_id() uses to build "stub-<label>-v1". */
static const catalog_entry k_catalog[] = {
    {"stub-signature-v1", "Stub Signature", "Deterministic signature construction for API testing.",
     AGC_CRYPTO_PRIMITIVE_SIGNATURE, AGC_SCOPE_KIND_SIGNATURE},
    {"stub-aead-v1", "Stub AEAD", "XOR-keystream AEAD construction for API testing.",
     AGC_CRYPTO_PRIMITIVE_AE, AGC_SCOPE_KIND_AEAD},
    {"stub-mac-v1", "Stub MAC", "Deterministic keyed MAC construction for API testing.",
     AGC_CRYPTO_PRIMITIVE_MAC, AGC_SCOPE_KIND_MAC},
    {"stub-kem-v1", "Stub KEM", "Non-lattice placeholder KEM for API testing.",
     AGC_CRYPTO_PRIMITIVE_KEM, AGC_SCOPE_KIND_KEM},
    {"stub-key-agreement-v1", "Stub Key Agreement", "Deterministic two-party agreement for API testing.",
     AGC_CRYPTO_PRIMITIVE_KEY_AGREE, AGC_SCOPE_KIND_KEY_AGREEMENT},
    {"stub-kdf-v1", "Stub KDF", "Deterministic key derivation for API testing.",
     AGC_CRYPTO_PRIMITIVE_KDF, AGC_SCOPE_KIND_KDF},
    {"stub-hash-v1", "Stub Hash", "Deterministic digest/XOF construction for API testing.",
     AGC_CRYPTO_PRIMITIVE_HASH, AGC_SCOPE_KIND_HASH},
    {"stub-key-wrapping-v1", "Stub Key Wrap", "AEAD-shaped key wrapping for API testing.",
     AGC_CRYPTO_PRIMITIVE_KEY_WRAP, AGC_SCOPE_KIND_KEY_WRAPPING},
    {"stub-symmetric-cipher-v1", "Stub Symmetric Cipher", "XOR-keystream block/stream cipher for API testing.",
     AGC_CRYPTO_PRIMITIVE_BLOCK_CIPHER, AGC_SCOPE_KIND_SYMMETRIC_CIPHER},
    {"stub-generic-secret-v1", "Stub Generic Secret", "Opaque secret material for API testing.",
     AGC_CRYPTO_PRIMITIVE_OTHER, AGC_SCOPE_KIND_GENERIC_SECRET},
    {"stub-disk-encryption-v1", "Stub Disk Encryption", "XTS-shaped construction for API testing.",
     AGC_CRYPTO_PRIMITIVE_BLOCK_CIPHER, AGC_SCOPE_KIND_DISK_ENCRYPTION},
    {"stub-asymmetric-encryption-v1", "Stub Asymmetric Encryption", "Placeholder public-key encryption for API testing.",
     AGC_CRYPTO_PRIMITIVE_PKE, AGC_SCOPE_KIND_ASYMMETRIC_ENCRYPTION},
};
#define K_CATALOG_COUNT (sizeof(k_catalog) / sizeof(k_catalog[0]))

struct agc_template_info {
    char                 *id;
    char                 *display_name;
    char                 *description;
    agc_template_status   status;
    char                 *standard; /* single entry: "stub-catalog" */
    agc_crypto_primitive  primitive;
    agc_scope_kind        capability_scope_kind;
};

static int ctx_usable(agc_ctx *ctx) { return ctx != NULL && !agc__ctx_is_poisoned(ctx); }

static agc_template_info *snapshot_template(const catalog_entry *e)
{
    struct agc_template_info *ti = calloc(1, sizeof(*ti));
    if (!ti) return NULL;
    ti->id = strdup(e->id);
    ti->display_name = strdup(e->display_name);
    ti->description = strdup(e->description);
    ti->status = AGC_TEMPLATE_STATUS_ACTIVE;
    ti->standard = strdup("stub-catalog");
    ti->primitive = e->primitive;
    ti->capability_scope_kind = e->scope_kind;
    return ti;
}

void agc_template_info_free(agc_template_info *ti)
{
    if (!ti) return;
    free(ti->id);
    free(ti->display_name);
    free(ti->description);
    free(ti->standard);
    free(ti);
}

const char *agc_template_info_id(const agc_template_info *ti) { return ti ? ti->id : NULL; }
const char *agc_template_info_display_name(const agc_template_info *ti) { return ti ? ti->display_name : NULL; }
const char *agc_template_info_description(const agc_template_info *ti) { return ti ? ti->description : NULL; }
agc_template_status agc_template_info_status(const agc_template_info *ti)
{
    return ti ? ti->status : AGC_TEMPLATE_STATUS_UNSPECIFIED;
}
size_t agc_template_info_standards_count(const agc_template_info *ti) { return ti ? 1u : 0u; }
const char *agc_template_info_standard_at(const agc_template_info *ti, size_t i)
{
    return (ti && i == 0) ? ti->standard : NULL;
}
agc_crypto_primitive agc_template_info_primitive(const agc_template_info *ti)
{
    return ti ? ti->primitive : AGC_CRYPTO_PRIMITIVE_UNSPECIFIED;
}

size_t agc_template_info_capability_count(const agc_template_info *ti) { return ti ? 1u : 0u; }

agc_rc agc_template_info_capability_scope(const agc_template_info *ti, size_t i, agc_scope_spec *out)
{
    if (!ti || i != 0 || !out) return AGC_ERR_INVALID_ARGUMENT;
    AGC_INIT(out);
    out->kind = ti->capability_scope_kind;
    return AGC_OK;
}

static int template_matches(const catalog_entry *e, const agc_list_templates_params *p)
{
    if (p->scope_spec && p->scope_spec->kind != AGC_SCOPE_KIND_NONE && p->scope_spec->kind != e->scope_kind) {
        return 0;
    }
    if (p->allowed_statuses_count > 0) {
        int found = 0;
        for (size_t i = 0; i < p->allowed_statuses_count; i++) {
            if (p->allowed_statuses[i] == AGC_TEMPLATE_STATUS_ACTIVE) found = 1;
        }
        if (!found) return 0; /* every catalog entry is ACTIVE */
    }
    /* required_standards: every catalog entry has exactly {"stub-catalog"} */
    for (size_t i = 0; i < p->required_standards.count; i++) {
        if (strcmp(p->required_standards.items[i], "stub-catalog") != 0) return 0;
    }
    return 1;
}

struct agc_template_iter {
    agc_generic_iter *inner;
};

agc_rc agc_list_templates(agc_ctx *ctx, const agc_list_templates_params *p, agc_template_iter **out_iter)
{
    if (!ctx_usable(ctx) || !out_iter) return AGC_ERR_INVALID_ARGUMENT;
    *out_iter = NULL;
    if (p && p->struct_size == 0) return AGC_ERR_INVALID_ARGUMENT;

    agc_template_info **items = calloc(K_CATALOG_COUNT, sizeof(*items));
    if (!items) return AGC_ERR_OUT_OF_MEMORY;
    size_t n = 0;
    for (size_t i = 0; i < K_CATALOG_COUNT; i++) {
        if (p && !template_matches(&k_catalog[i], p)) continue;
        items[n] = snapshot_template(&k_catalog[i]);
        if (!items[n]) {
            for (size_t j = 0; j < n; j++) agc_template_info_free(items[j]);
            free(items);
            return AGC_ERR_OUT_OF_MEMORY;
        }
        n++;
    }

    struct agc_template_iter *it = calloc(1, sizeof(*it));
    if (!it) {
        for (size_t j = 0; j < n; j++) agc_template_info_free(items[j]);
        free(items);
        return AGC_ERR_OUT_OF_MEMORY;
    }
    agc_rc rc = agc__iter_create((void **)items, n, (agc_generic_item_free_fn)agc_template_info_free, &it->inner);
    if (rc != AGC_OK) {
        for (size_t j = 0; j < n; j++) agc_template_info_free(items[j]);
        free(items);
        free(it);
        return rc;
    }
    *out_iter = it;
    return AGC_OK;
}

agc_rc agc_template_iter_next(agc_template_iter *it, agc_template_info **out)
{
    if (!it || !out) return AGC_ERR_INVALID_ARGUMENT;
    void *item = NULL;
    agc_rc rc = agc__iter_next(it->inner, &item);
    *out = item;
    return rc;
}

void agc_template_iter_free(agc_template_iter *it)
{
    if (!it) return;
    agc__iter_free(it->inner);
    free(it);
}

agc_rc agc_get_template(agc_ctx *ctx, const char *template_id, agc_template_info **out_template)
{
    if (!ctx_usable(ctx) || !template_id || !*template_id || !out_template) return AGC_ERR_INVALID_ARGUMENT;
    *out_template = NULL;
    for (size_t i = 0; i < K_CATALOG_COUNT; i++) {
        if (strcmp(k_catalog[i].id, template_id) == 0) {
            *out_template = snapshot_template(&k_catalog[i]);
            return *out_template ? AGC_OK : AGC_ERR_OUT_OF_MEMORY;
        }
    }
    return AGC_ERR_CRYPTO_TEMPLATE_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * ListScopes
 * -------------------------------------------------------------------------- */

struct agc_scope_info {
    char           *name;
    char           *description;
    agc_scope_kind  kind;
};

agc_rc agc_scope_info_specification(const agc_scope_info *si, agc_scope_spec *out)
{
    if (!si || !out) return AGC_ERR_INVALID_ARGUMENT;
    AGC_INIT(out);
    out->kind = si->kind;
    return AGC_OK;
}
const char *agc_scope_info_name(const agc_scope_info *si) { return si ? si->name : NULL; }
const char *agc_scope_info_description(const agc_scope_info *si) { return si ? si->description : NULL; }

agc_rc agc_list_scopes(agc_ctx *ctx, agc_scope_info ***out_scopes, size_t *out_count)
{
    if (!ctx_usable(ctx) || !out_scopes || !out_count) return AGC_ERR_INVALID_ARGUMENT;
    *out_scopes = NULL;
    *out_count = 0;

    agc_scope_info **scopes = calloc(K_CATALOG_COUNT, sizeof(*scopes));
    if (!scopes) return AGC_ERR_OUT_OF_MEMORY;
    for (size_t i = 0; i < K_CATALOG_COUNT; i++) {
        struct agc_scope_info *si = calloc(1, sizeof(*si));
        if (!si) {
            for (size_t j = 0; j < i; j++) { free(scopes[j]->name); free(scopes[j]->description); free(scopes[j]); }
            free(scopes);
            return AGC_ERR_OUT_OF_MEMORY;
        }
        si->name = strdup(k_catalog[i].display_name);
        si->description = strdup(k_catalog[i].description);
        si->kind = k_catalog[i].scope_kind;
        scopes[i] = si;
    }
    *out_scopes = scopes;
    *out_count = K_CATALOG_COUNT;
    return AGC_OK;
}

void agc_scope_info_list_free(agc_scope_info **scopes, size_t count)
{
    if (!scopes) return;
    for (size_t i = 0; i < count; i++) {
        if (scopes[i]) { free(scopes[i]->name); free(scopes[i]->description); free(scopes[i]); }
    }
    free(scopes);
}
