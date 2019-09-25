/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#include "internal/cryptlib.h"
#include "ssl_locl.h"
#include "record/record_locl.h"
#include "statem/statem_locl.h"
#include <openssl/rand.h>
#include <openssl/tlmsp.h>

/* API functions.  */

/* Internal functions.  */

void
tlmsp_context_index_init(TLMSP_ContextIndexed *indexed)
{
    indexed->stack = NULL;
}

void
tlmsp_context_index_free(TLMSP_ContextIndexed *indexed, size_t size)
{
    TLMSP_ContextIndex *idx;
    int i;

    if (indexed->stack == NULL)
        return;

    for (i = 0; i < sk_TLMSP_ContextIndex_num(indexed->stack); i++) {
        idx = sk_TLMSP_ContextIndex_value(indexed->stack, i);
        OPENSSL_clear_free(idx->data, size);
        OPENSSL_free(idx);
    }
    sk_TLMSP_ContextIndex_free(indexed->stack);
    indexed->stack = NULL;
}

const TLMSP_ContextIndex *
tlmsp_context_index_lookup(const TLMSP_ContextIndexed *indexed, tlmsp_context_id_t cid)
{
    const TLMSP_ContextIndex *idx;
    int i;

    if (indexed->stack == NULL)
        return NULL;

    for (i = 0; i < sk_TLMSP_ContextIndex_num(indexed->stack); i++) {
        idx = sk_TLMSP_ContextIndex_value(indexed->stack, i);
        if (idx->cid != cid)
            continue;
        return idx;
    }

    return NULL;
}

TLMSP_ContextIndex *
tlmsp_context_index_insert(TLMSP_ContextIndexed *indexed, tlmsp_context_id_t cid, size_t size)
{
    TLMSP_ContextIndex *idx;

    if (indexed->stack == NULL) {
        indexed->stack = sk_TLMSP_ContextIndex_new_null();
        if (indexed->stack == NULL)
            return NULL;
    }

    idx = OPENSSL_zalloc(sizeof *idx);
    if (idx == NULL)
        return NULL;
    idx->cid = cid;
    idx->data = OPENSSL_zalloc(size);
    if (idx->data == NULL) {
        OPENSSL_free(idx);
        return NULL;
    }

    if (!sk_TLMSP_ContextIndex_push(indexed->stack, idx)) {
        OPENSSL_free(idx->data);
        OPENSSL_free(idx);
        return NULL;
    }

    return idx;
}

/* Local functions.  */

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
