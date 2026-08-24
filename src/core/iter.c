/* SPDX-License-Identifier: Apache-2.0 */
#include "agc_internal.h"

#include <stdlib.h>

struct agc_generic_iter {
    void                    **items;
    size_t                    count;
    size_t                    next_index;
    agc_generic_item_free_fn  free_fn;
};

agc_rc agc__iter_create(void **items, size_t count, agc_generic_item_free_fn free_fn,
                         agc_generic_iter **out)
{
    if (!out) return AGC_ERR_INVALID_ARGUMENT;
    *out = NULL;
    if (count > 0 && !items) return AGC_ERR_INVALID_ARGUMENT;

    struct agc_generic_iter *it = calloc(1, sizeof(*it));
    if (!it) return AGC_ERR_OUT_OF_MEMORY;

    it->items = items;
    it->count = count;
    it->next_index = 0;
    it->free_fn = free_fn;

    *out = it;
    return AGC_OK;
}

agc_rc agc__iter_next(agc_generic_iter *it, void **out_item)
{
    if (!it || !out_item) return AGC_ERR_INVALID_ARGUMENT;
    *out_item = NULL;
    if (it->next_index >= it->count) return AGC_ERR_ITERATOR_EXHAUSTED;

    /* Ownership of the item transfers to the caller: NULL the slot so
     * agc__iter_free() does not double-free it if called afterward. */
    *out_item = it->items[it->next_index];
    it->items[it->next_index] = NULL;
    it->next_index++;
    return AGC_OK;
}

void agc__iter_free(agc_generic_iter *it)
{
    if (!it) return;
    if (it->free_fn) {
        for (size_t i = 0; i < it->count; i++) {
            if (it->items[i]) it->free_fn(it->items[i]);
        }
    }
    free(it->items);
    free(it);
}
