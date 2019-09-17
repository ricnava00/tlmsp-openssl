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

/* Internal functions.  */

void
tlmsp_buffer_init(struct tlmsp_buffer *b)
{
    b->bmem = NULL;
}

void
tlmsp_buffer_clear(struct tlmsp_buffer *b)
{
    if (b->bmem == NULL)
        return;
    BUF_MEM_free(b->bmem);
    b->bmem = NULL;
}

int
tlmsp_buffer_copy(struct tlmsp_buffer *dst, const struct tlmsp_buffer *src)
{
    const void *p;
    size_t plen;

    tlmsp_buffer_clear(dst);

    p = tlmsp_buffer_data(src, &plen);
    if (p == NULL)
        return 1;

    return tlmsp_buffer_append(dst, p, plen);
}

const void *
tlmsp_buffer_data(const struct tlmsp_buffer *b, size_t *blenp)
{
    if (b->bmem == NULL || b->bmem->length == 0) {
        *blenp = 0;
        return NULL;
    }

    *blenp = b->bmem->length;
    return b->bmem->data;
}

int
tlmsp_buffer_empty(const struct tlmsp_buffer *b)
{
    size_t blen;

    if (tlmsp_buffer_data(b, &blen) != NULL)
        return 0;
    return 1;
}

int
tlmsp_buffer_append(struct tlmsp_buffer *b, const void *p, size_t plen)
{
    size_t olen;

    if (plen == 0)
        return 1;
    if (b->bmem == NULL) {
        /*
         * We always use the secure heap out of an abundance of caution,
         * although most things we buffer for TLMSP are not extremely
         * sensitive.
         *
         * That can change without realizing the risk, so just do the safe
         * thing here.
         */
        b->bmem = BUF_MEM_new_ex(BUF_MEM_FLAG_SECURE);
        if (b->bmem == NULL)
            return 0;
    }
    olen = b->bmem->length;
    if (!BUF_MEM_grow(b->bmem, olen + plen))
        return 0;
    memcpy(b->bmem->data + olen, p, plen);
    return 1;
}

/* Local functions.  */

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
