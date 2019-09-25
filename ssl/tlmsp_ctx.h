/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_CTX_H
# define HEADER_TLMSP_CTX_H

struct tlmsp_middlebox_instance_st;
typedef struct tlmsp_middlebox_instance_st TLMSP_MiddleboxInstance;

# include "tlmsp_key.h"

struct tlmsp_context_access_st {
    tlmsp_context_auth_t contexts[TLMSP_CONTEXT_COUNT];
};

struct tlmsp_context_state {
    int present;
    tlmsp_context_audit_t audit;
    uint8_t purpose[255];
    size_t purposelen;
};

struct tlmsp_context_instance_state {
    struct tlmsp_context_key_block key_block;
    struct tlmsp_context_state state;
};

struct tlmsp_context_st {
    tlmsp_context_id_t cid;
    struct tlmsp_context_state state;
};

int tlmsp_context_access(const SSL *, tlmsp_context_id_t, tlmsp_context_auth_t, const TLMSP_MiddleboxInstance *);
int tlmsp_context_audit(const SSL *, tlmsp_context_id_t, tlmsp_context_audit_t *);
int tlmsp_context_present(const SSL *, tlmsp_context_id_t);

void tlmsp_context_free(TLMSP_Context *);

void tlmsp_context_access_clear(TLMSP_ContextAccess *);
int tlmsp_context_access_equal(const TLMSP_ContextAccess *, const TLMSP_ContextAccess *);

int tlmsp_context_state_init(struct tlmsp_context_state *, const char *, tlmsp_context_audit_t);

int tlmsp_context_generate_contributions(SSL *, unsigned);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
