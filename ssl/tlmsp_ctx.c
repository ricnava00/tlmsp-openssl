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

int
TLMSP_set_current_context(SSL *s, tlmsp_context_id_t cid)
{
    if (!SSL_IS_TLMSP(s))
        return 0;
    if (TLMSP_IS_MIDDLEBOX(s))
        return 0;
    if (!tlmsp_context_present(s, cid))
        return 0;
    s->tlmsp.current_context = cid;
    return 1;
}

int
TLMSP_get_current_context(SSL *s, tlmsp_context_id_t *cidp)
{
    if (!SSL_IS_TLMSP(s))
        return 0;
    if (TLMSP_IS_MIDDLEBOX(s))
        return 0;
    if (cidp == NULL)
        return 0;
    *cidp = s->tlmsp.current_context;
    return 1;
}

int
TLMSP_get_last_read_context(SSL *s, tlmsp_context_id_t *cidp)
{
    if (!SSL_IS_TLMSP(s))
        return 0;
    if (TLMSP_IS_MIDDLEBOX(s))
        return 0;
    if (cidp == NULL)
        return 0;
    /* We never service a byte-read out of a context 0 container.  */
    if (s->tlmsp.read_last_context == TLMSP_CONTEXT_CONTROL)
        return 0;
    *cidp = s->tlmsp.read_last_context;
    return 1;
}

int
TLMSP_set_contexts(SSL_CTX *ctx, const TLMSP_Contexts *contexts)
{
    struct tlmsp_context_state *tcs;
    unsigned i, j;

    if (contexts == NULL)
        return 0;

    /* Reset all contexts except context 0.  */
    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        if (j == TLMSP_CONTEXT_CONTROL)
            continue;
        ctx->tlmsp.context_states[j].present = 0;
    }

    /* Now set the provided contexts.  */
    for (i = 0; i < (unsigned)sk_TLMSP_Context_num(contexts); i++) {
        const TLMSP_Context *context = sk_TLMSP_Context_value(contexts, i);
        if (context->cid == TLMSP_CONTEXT_CONTROL)
            return 0;
        if (!context->state.present)
            return 0;
        tcs = &ctx->tlmsp.context_states[context->cid];
        if (tcs->present)
            return 0;
        *tcs = context->state;
    }

    return 1;
}

int
TLMSP_set_contexts_instance(SSL *s, const TLMSP_Contexts *contexts)
{
    struct tlmsp_context_state *tcs;
    unsigned i, j;

    if (contexts == NULL)
        return 0;

    /* Reset all contexts except context 0.  */
    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        if (j == TLMSP_CONTEXT_CONTROL)
            continue;
        s->tlmsp.context_states[j].state.present = 0;
    }

    /* Now set the provided contexts.  */
    for (i = 0; i < (unsigned)sk_TLMSP_Context_num(contexts); i++) {
        const TLMSP_Context *context = sk_TLMSP_Context_value(contexts, i);
        if (context->cid == TLMSP_CONTEXT_CONTROL)
            return 0;
        if (!context->state.present)
            return 0;
        tcs = &s->tlmsp.context_states[context->cid].state;
        if (tcs->present)
            return 0;
        *tcs = context->state;
    }

    return 1;
}

int
TLMSP_context_add(TLMSP_Contexts **contextsp, tlmsp_context_id_t cid, const char *purpose, tlmsp_context_audit_t audit)
{
    TLMSP_Contexts *contexts;
    TLMSP_Context *context;

    contexts = *contextsp;
    if (contexts == NULL) {
        contexts = sk_TLMSP_Context_new_null();
        if (contexts == NULL)
            return 0;
        *contextsp = contexts;
    }

    context = OPENSSL_zalloc(sizeof *context);
    context->cid = cid;
    if (!tlmsp_context_state_init(&context->state, purpose, audit)) {
        OPENSSL_free(context);
        return 0;
    }
    if (!sk_TLMSP_Context_push(contexts, context)) {
        OPENSSL_free(context);
        return 0;
    }
    return 1;
}

void
TLMSP_contexts_free(TLMSP_Contexts *contexts)
{
    if (contexts == NULL)
        return;
    sk_TLMSP_Context_pop_free(contexts, tlmsp_context_free);
}

int
TLMSP_context_access_add(TLMSP_ContextAccess **contextsp, tlmsp_context_id_t id, tlmsp_context_auth_t auth)
{
    TLMSP_ContextAccess *contexts;

    contexts = *contextsp;
    if (contexts == NULL) {
        contexts = OPENSSL_zalloc(sizeof *contexts);
        if (contexts == NULL) {
            SSLerr(SSL_F_TLMSP_CONTEXT_ACCESS_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        *contextsp = contexts;
    }

    if (contexts->contexts[id] != 0) {
        if (contexts->contexts[id] == auth)
            return 1;
        /* XXX Do we want to just allow modification silently?  */
        SSLerr(SSL_F_TLMSP_CONTEXT_ACCESS_ADD, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    contexts->contexts[id] = auth;

    return 1;
}

void
TLMSP_context_access_free(TLMSP_ContextAccess *contexts)
{
    OPENSSL_free(contexts);
}

int
TLMSP_context_access_first(const TLMSP_ContextAccess *contexts, tlmsp_context_id_t *cidp)
{
    *cidp = TLMSP_CONTEXT_CONTROL;
    return TLMSP_context_access_next(contexts, cidp);
}

int
TLMSP_context_access_next(const TLMSP_ContextAccess *contexts, tlmsp_context_id_t *cidp)
{
    unsigned j;

    for (j = (unsigned)*cidp + 1; j < TLMSP_CONTEXT_COUNT; j++) {
        if (contexts->contexts[j] == 0)
            continue;
        *cidp = (tlmsp_context_id_t)j;
        return 1;
    }

    return 0;
}

tlmsp_context_auth_t
TLMSP_context_access_auth(const TLMSP_ContextAccess *context, tlmsp_context_id_t cid)
{
    return context->contexts[cid];
}

/* Internal functions.  */

int
tlmsp_context_access(const SSL *s, tlmsp_context_id_t cid, tlmsp_context_auth_t auth, const TLMSP_MiddleboxInstance *tmis)
{
    const tlmsp_context_auth_t *authp;
    const TLMSP_ContextAccess *ca;

    ca = &tmis->state.access;
    authp = &ca->contexts[cid];

    if (!tlmsp_context_present(s, cid))
        return 0;

    /*
     * Endpoints have access to all contexts.
     */
    if (TLMSP_MIDDLEBOX_ID_ENDPOINT(tmis->state.id))
        return 1;

    if (cid == TLMSP_CONTEXT_CONTROL) {
        /*
         * XXX
         * As long as it is not forbidden, which should be caught in lots of
         * other ways and places, a middlebox has all access to context 0.
         *
         * We can check forbidden here if desired, depending on the operational
         * profile in the face of forbidden middleboxes.
         */
        return 1;
    }

    switch (auth) {
    case TLMSP_CONTEXT_AUTH_READ:
        switch (*authp) {
        case TLMSP_CONTEXT_AUTH_READ:
        case TLMSP_CONTEXT_AUTH_WRITE:
            return 1;
        default:
            return 0;
        }
        break;
    case TLMSP_CONTEXT_AUTH_WRITE:
        switch (*authp) {
        case TLMSP_CONTEXT_AUTH_WRITE:
            return 1;
        default:
            return 0;
        }
    default:
        return 0;
    }
}

int
tlmsp_context_audit(const SSL *s, tlmsp_context_id_t cid, tlmsp_context_audit_t *auditp)
{
    const struct tlmsp_context_instance_state *tcis;

    tcis = &s->tlmsp.context_states[cid];
    if (!tcis->state.present)
        return 0;
    *auditp = tcis->state.audit;
    return 1;
}

int
tlmsp_context_present(const SSL *s, tlmsp_context_id_t cid)
{
    const struct tlmsp_context_instance_state *tcis;

    tcis = &s->tlmsp.context_states[cid];
    return (tcis->state.present);
}

void
tlmsp_context_free(TLMSP_Context *context)
{
    OPENSSL_free(context);
}

void
tlmsp_context_access_clear(TLMSP_ContextAccess *contexts)
{
    memset(contexts->contexts, 0, sizeof contexts->contexts);
}

int
tlmsp_context_access_equal(const TLMSP_ContextAccess *contexts1, const TLMSP_ContextAccess *contexts2)
{
    return (memcmp(contexts1->contexts, contexts2->contexts, sizeof contexts1->contexts) == 0);
}

int
tlmsp_context_state_init(struct tlmsp_context_state *tcs, const char *purpose, tlmsp_context_audit_t audit)
{
    if (tcs->present)
        return 0;
    tcs->present = 1;
    switch (audit) {
    case TLMSP_CONTEXT_AUDIT_UNCONFIRMED:
    case TLMSP_CONTEXT_AUDIT_CONFIRMED:
        break;
    default:
        return 0;
    }
    tcs->audit = audit;

    tcs->purposelen = strlen(purpose);
    if (tcs->purposelen > sizeof tcs->purpose)
        return 0;
    memcpy(tcs->purpose, purpose, tcs->purposelen);

    return 1;
}

int
tlmsp_context_generate_contributions(SSL *s, unsigned contrib)
{
    size_t keylen;
    unsigned j;

    keylen = tlmsp_key_size(s);

    switch (contrib) {
    case TLMSP_CONTRIBUTION_SERVER:
    case TLMSP_CONTRIBUTION_CLIENT:
        break;
    default:
        return 0;
    }

    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        struct tlmsp_context_instance_state *tcis;
        struct tlmsp_context_contributions *tcc;

        tcis = &s->tlmsp.context_states[j];
        if (!tcis->state.present)
            continue;
        tcc = &tcis->key_block.contributions[contrib];

        if (j == TLMSP_CONTEXT_CONTROL) {
            if (RAND_priv_bytes(tcc->synch, keylen) <= 0)
                return 0;
        }
        if (RAND_priv_bytes(tcc->reader, keylen) <= 0 ||
            RAND_priv_bytes(tcc->writer, keylen) <= 0) {
            return 0;
        }
    }

    return 1;
}

/* Local functions.  */

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
