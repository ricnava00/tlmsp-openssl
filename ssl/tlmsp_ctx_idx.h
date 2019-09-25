/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_CTX_IDX_H
# define HEADER_TLMSP_CTX_IDX_H

struct tlmsp_context_index {
    tlmsp_context_id_t cid;
    void *data;
};

typedef struct tlmsp_context_index TLMSP_ContextIndex;

DEFINE_STACK_OF(TLMSP_ContextIndex)
typedef struct {
    STACK_OF(TLMSP_ContextIndex) *stack;
} TLMSP_ContextIndexed;

# define TLMSP_CONTEXT_INDEXED(type, tag) \
    typedef struct { TLMSP_ContextIndexed indexed; } tag; \
    static inline void tag ## _init(tag *t) \
    { \
        tlmsp_context_index_init(&t->indexed); \
    } \
    static inline type *tag ## _lookup(const tag *t, tlmsp_context_id_t cid) \
    { \
        const TLMSP_ContextIndex *idx = tlmsp_context_index_lookup(&t->indexed, cid); \
        if (idx == NULL) \
            return NULL; \
        return idx->data; \
    } \
    static inline type *tag ## _insert(tag *t, tlmsp_context_id_t cid) \
    { \
        TLMSP_ContextIndex *idx = tlmsp_context_index_insert(&t->indexed, cid, sizeof (type)); \
        if (idx == NULL) \
            return NULL; \
        return idx->data; \
    } \
    static inline void tag ## _free(tag *t) \
    { \
        tlmsp_context_index_free(&t->indexed, sizeof (type)); \
    } \
    struct hack

void tlmsp_context_index_init(TLMSP_ContextIndexed *);
void tlmsp_context_index_free(TLMSP_ContextIndexed *, size_t);

const TLMSP_ContextIndex *tlmsp_context_index_lookup(const TLMSP_ContextIndexed *, tlmsp_context_id_t);
TLMSP_ContextIndex *tlmsp_context_index_insert(TLMSP_ContextIndexed *, tlmsp_context_id_t, size_t);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
