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

#define TLMSP_MAX_MIDDLEBOXES   (TLMSP_MIDDLEBOX_ID_LAST - TLMSP_MIDDLEBOX_ID_FIRST + 1)

static TLMSP_Middlebox *tlmsp_middlebox_dup_static(const TLMSP_Middlebox *);
static TLMSP_Middlebox *tlmsp_middlebox_create(const struct tlmsp_middlebox_configuration *);
static int tlmsp_middlebox_instance_copy(TLMSP_MiddleboxInstance *, const TLMSP_MiddleboxInstance *);
static TLMSP_MiddleboxInstance *tlmsp_middlebox_instance_dup(const TLMSP_MiddleboxInstance *);
static TLMSP_MiddleboxInstance *tlmsp_middlebox_insert_after_list(TLMSP_MiddleboxInstances **, const TLMSP_MiddleboxInstance *, tlmsp_middlebox_id_t);
static TLMSP_MiddleboxInstance *tlmsp_middlebox_next_list(const SSL *, TLMSP_MiddleboxInstances *, const TLMSP_MiddleboxInstance *);
static TLMSP_MiddleboxInstance *tlmsp_middlebox_previous_list(const SSL *, TLMSP_MiddleboxInstances *, const TLMSP_MiddleboxInstance *);
static TLMSP_MiddleboxInstance *tlmsp_middlebox_first_list(const TLMSP_MiddleboxInstances *);
static TLMSP_MiddleboxInstance *tlmsp_middlebox_last_list(const TLMSP_MiddleboxInstances *);
static int tlmsp_middlebox_handshake_error(int, int);
static int tlmsp_middlebox_handshake_half(SSL *, SSL *, int, int *);
static int tlmsp_middlebox_handshake_half_check_error(SSL *, int, int *);
static int tlmsp_middlebox_handshake_half_flush(SSL *, int, int *);
static int tlmsp_middlebox_handshake_final_flush(SSL *, SSL *, int *);

/* API functions.  */

int
TLMSP_middlebox_handshake(SSL *toclient, SSL *toserver, int *errorp)
{
    int error[2];
    int rv[2];

    toclient->server = 1;
    if (toserver != NULL)
        toserver->server = 0;

    if (toclient->handshake_func == NULL)
        toclient->handshake_func = toclient->method->ssl_accept;
    if (toserver != NULL && toserver->handshake_func == NULL)
        toserver->handshake_func = toserver->method->ssl_connect;

    /*
     * While at least one SSL is in handshake state, and until one side yields
     * an error, process.
     */
    while (SSL_in_init(toclient) || (toserver == NULL || SSL_in_init(toserver))) {
        rv[0] = tlmsp_middlebox_handshake_half(toclient, toserver, 0, &error[0]);

        /*
         * If we don't have a to-server connection yet, we just return the status
         * of polling the handshake function of the to-client connection, which
         * will eventually process the ClientHello and return WANT_OUTBOUND_CONN,
         * the caller will set up the toserver connection based on querying the
         * next hop, and then the handshake will proceed.
         */
        if (toserver == NULL) {
            *errorp = error[0];
            return rv[0];
        }

        /*
         * XXX TODO XXX
         * We should assert that this does not happen.
         * Loops forever if resolving packet doesn't arrive, handle
         */
        if (toserver->tlmsp.self == NULL && toclient->tlmsp.self != NULL) {
            //fprintf(stderr, "%s: connection to client knows middlebox id, but to server does not.\n", __func__);
            continue;
        }

        rv[1] = tlmsp_middlebox_handshake_half(toserver, toclient, 1, &error[1]);

        /*
         * If both sides were successful, keep going.
         */
        if (rv[0] == 1 && rv[1] == 1)
            continue;

        /*
         * If only one side is successful, we keep going with the other.
         */
        if (rv[0] == 1) {
            *errorp = error[1];
            return rv[1];
        }
        if (rv[1] == 1) {
            *errorp = error[0];
            return rv[0];
        }

        /*
         * If both sides have an error, but only one of them is
         * SSL_ERROR_WANT_READ, yield the other error.
         *
         * An SSL will generally always want to read, so we need to treat that
         * as the lowest priority error.
         */
        if (rv[0] < 0 && rv[1] < 0) {
            if (error[0] == SSL_ERROR_WANT_READ) {
                if (error[1] != SSL_ERROR_WANT_READ) {
                    *errorp = error[1];
                    return rv[1];
                }
            } else {
                if (error[1] == SSL_ERROR_WANT_READ) {
                    *errorp = error[0];
                    return rv[0];
                }
            }
        }

        /*
         * If one side has an error, yield error.
         */
        if (rv[0] < 0) {
            *errorp = error[0];
            return rv[0];
        }
        if (rv[1] < 0) {
            *errorp = error[1];
            return rv[1];
        }

        /*
         * Both sides returned 0, keep going.
         */
        *errorp = SSL_ERROR_NONE; /* XXX Confirm.  */
        return -1;
    }

    /*
     * Do a final flush before completing the handshake.
     */
    if (!tlmsp_middlebox_handshake_final_flush(toclient, toserver, errorp))
        return -1;

    return 1;
}

int
TLMSP_set_initial_middleboxes(SSL_CTX *ctx, const TLMSP_Middleboxes *middleboxes)
{
    if (ctx->tlmsp.middlebox_states != NULL) {
        TLMSP_middleboxes_free(ctx->tlmsp.middlebox_states);
        ctx->tlmsp.middlebox_states = NULL;
    }

    if (middleboxes == NULL || sk_TLMSP_Middlebox_num(middleboxes) == 0)
        return 1;

    if (sk_TLMSP_Middlebox_num(middleboxes) >= TLMSP_MAX_MIDDLEBOXES)
        return 0;

    ctx->tlmsp.middlebox_states = sk_TLMSP_Middlebox_deep_copy(middleboxes,
        tlmsp_middlebox_dup_static, tlmsp_middlebox_free);
    if (ctx->tlmsp.middlebox_states == NULL)
        return 0;

    return 1;
}

int
TLMSP_set_initial_middleboxes_instance(SSL *s, const TLMSP_Middleboxes *middleboxes)
{
    if (!tlmsp_set_middlebox_list(&s->tlmsp.current_middlebox_list, middleboxes))
        return 0;

    /* ids assigned here */
    if (!tlmsp_middlebox_table_compile_current(s))
        return 0;

    if (s->tlmsp.current_middlebox_list != NULL) {
        /* copy current, not set from the source, so assigned ids are preserved */
        if (!tlmsp_middleboxes_dup(&s->tlmsp.initial_middlebox_list, s->tlmsp.current_middlebox_list))
            return 0;

        if (!tlmsp_middlebox_table_compile_initial(s))
            return 0;
    }

    return 1;
}

int
TLMSP_middlebox_add(TLMSP_Middleboxes **mboxesp, const struct tlmsp_middlebox_configuration *cfg)
{
    TLMSP_Middleboxes *mboxes;
    TLMSP_Middlebox *mbox;

    mboxes = *mboxesp;
    if (mboxes == NULL) {
        mboxes = sk_TLMSP_Middlebox_new_null();
        if (mboxes == NULL) {
            SSLerr(SSL_F_TLMSP_MIDDLEBOX_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        *mboxesp = mboxes;
    }

    mbox = tlmsp_middlebox_create(cfg);
    if (mbox == NULL)
        return 0;

    if (!sk_TLMSP_Middlebox_push(mboxes, mbox)) {
        tlmsp_middlebox_free(mbox);
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

void
TLMSP_middleboxes_free(TLMSP_Middleboxes *mboxes)
{
    if (mboxes == NULL)
        return;
    sk_TLMSP_Middlebox_pop_free(mboxes, tlmsp_middlebox_free);
}

TLMSP_Middlebox *
TLMSP_middleboxes_first(const TLMSP_Middleboxes *mboxes)
{
    return sk_TLMSP_Middlebox_value(mboxes, 0);
}

TLMSP_Middlebox *
TLMSP_middleboxes_last(const TLMSP_Middleboxes *mboxes)
{
    if (mboxes == NULL || sk_TLMSP_Middlebox_num(mboxes) == 0)
        return NULL;
    return sk_TLMSP_Middlebox_value(mboxes, sk_TLMSP_Middlebox_num(mboxes) - 1);
}

TLMSP_Middlebox *
TLMSP_middleboxes_next(const TLMSP_Middleboxes *mboxes, const TLMSP_Middlebox *mbox)
{
    int n;

    if (mboxes == NULL)
        return NULL;

    n = sk_TLMSP_Middlebox_find((TLMSP_Middleboxes *)mboxes, (TLMSP_Middlebox *)mbox);
    if (n == -1)
        return NULL;
    n++;
    if (sk_TLMSP_Middlebox_num(mboxes) == n)
        return NULL;
    return sk_TLMSP_Middlebox_value(mboxes, n);
}

int
TLMSP_middleboxes_insert_before(TLMSP_Middleboxes *mboxes, const TLMSP_Middlebox *cursor, const struct tlmsp_middlebox_configuration *cfg)
{
    TLMSP_Middlebox *mbox;
    int n;

    mbox = tlmsp_middlebox_create(cfg);
    if (mbox == NULL)
        return 0;

    n = sk_TLMSP_Middlebox_find(mboxes, (TLMSP_Middlebox *)cursor);
    if (n == -1) {
        if (cursor != NULL)
            return 0;
        /* Just insert at the beginning.  */
        if (!sk_TLMSP_Middlebox_insert(mboxes, mbox, 0)) {
            tlmsp_middlebox_free(mbox);
            return 0;
        }
        return 1;
    }
    if (!sk_TLMSP_Middlebox_insert(mboxes, mbox, n)) {
        tlmsp_middlebox_free(mbox);
        return 0;
    }
    return 1;
}

int
TLMSP_middleboxes_insert_after(TLMSP_Middleboxes *mboxes, const TLMSP_Middlebox *cursor, const struct tlmsp_middlebox_configuration *cfg)
{
    TLMSP_Middlebox *mbox;
    int n;

    mbox = tlmsp_middlebox_create(cfg);
    if (mbox == NULL)
        return 0;

    n = sk_TLMSP_Middlebox_find(mboxes, (TLMSP_Middlebox *)cursor);
    if (n == -1) {
        if (cursor != NULL)
            return 0;
        /* Just insert at the beginning.  */
        if (!sk_TLMSP_Middlebox_insert(mboxes, mbox, 0)) {
            tlmsp_middlebox_free(mbox);
            return 0;
        }
        return 1;
    }
    if (!sk_TLMSP_Middlebox_insert(mboxes, mbox, n + 1)) {
        tlmsp_middlebox_free(mbox);
        return 0;
    }
    return 1;
}

int
TLMSP_get_middlebox_address(const TLMSP_Middlebox *middlebox, int *address_type, uint8_t **outbuf, size_t *outlen)
{
    return tlmsp_address_get(&middlebox->address, address_type, outbuf, outlen);
}

const TLMSP_ContextAccess *
TLMSP_middlebox_context_access(const TLMSP_Middlebox *mbox)
{
    return &mbox->access;
}

int
TLMSP_middlebox_dynamic(const TLMSP_Middlebox *mbox)
{
    return (mbox->inserted == 1);
}

int
TLMSP_middlebox_forbid(TLMSP_Middlebox *middlebox)
{
    /* XXX */
    return 0;
}

/* Internal functions.  */

int
tlmsp_middlebox_add(TLMSP_Middleboxes **mboxesp, const TLMSP_Middlebox *mbox)
{
    TLMSP_Middleboxes *mboxes;
    TLMSP_Middlebox *new_mbox;

    mboxes = *mboxesp;
    if (mboxes == NULL) {
        mboxes = sk_TLMSP_Middlebox_new_null();
        if (mboxes == NULL) {
            SSLerr(SSL_F_TLMSP_MIDDLEBOX_ADD, ERR_R_MALLOC_FAILURE);
            return 0;
        }
        *mboxesp = mboxes;
    }

    if (mbox == NULL)
        return 1;

    new_mbox = OPENSSL_zalloc(sizeof *new_mbox);
    if (new_mbox == NULL) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    *new_mbox = *mbox;

    if (!sk_TLMSP_Middlebox_push(mboxes, new_mbox)) {
        tlmsp_middlebox_free(new_mbox);
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_ADD, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return 1;
}

void
tlmsp_middlebox_free(TLMSP_Middlebox *middlebox)
{
    OPENSSL_free(middlebox);
}

void
tlmsp_middlebox_instance_cleanup(TLMSP_MiddleboxInstance *tmis)
{
    TLMSP_ContextConfirmationTable_free(&tmis->confirmations);
    tlmsp_finish_clear(&tmis->finish_state);

    if (tmis->cert_chain != NULL) {
        sk_X509_pop_free(tmis->cert_chain, X509_free);
        tmis->cert_chain = NULL;
    }

    if (tmis->to_client_pkey != NULL) {
        EVP_PKEY_free(tmis->to_client_pkey);
        tmis->to_client_pkey = NULL;
    }

    if (tmis->to_server_pkey != NULL) {
        EVP_PKEY_free(tmis->to_server_pkey);
        tmis->to_server_pkey = NULL;
    }

    /*
     * We could just clear sensitive portions, but this is conservative and
     * reasonable since most of the instance state is sensitive.
     */
    OPENSSL_cleanse(tmis, sizeof *tmis);
}

void
tlmsp_middlebox_instance_free(TLMSP_MiddleboxInstance *tmis)
{
    tlmsp_middlebox_instance_cleanup(tmis);
    OPENSSL_free(tmis);
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_first_initial(const SSL *s)
{
    return tlmsp_middlebox_first_list(s->tlmsp.initial_middlebox_list);
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_next_initial(const SSL *s, const TLMSP_MiddleboxInstance *cursor)
{
    return tlmsp_middlebox_next_list(s, s->tlmsp.initial_middlebox_list, cursor);
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_lookup_initial(const SSL *s, tlmsp_middlebox_id_t id)
{
    /*
     * XXX
     * We could keep client and server entries in the table, too.
     */
    switch (id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        return (TLMSP_MiddleboxInstance *)&s->tlmsp.client_middlebox;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        return (TLMSP_MiddleboxInstance *)&s->tlmsp.server_middlebox;
    default:
        return s->tlmsp.initial_middlebox_table[id];
    }
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_insert_after_initial(SSL *s, const TLMSP_MiddleboxInstance *cursor, tlmsp_middlebox_id_t id)
{
    return tlmsp_middlebox_insert_after_list(&s->tlmsp.initial_middlebox_list, cursor, id);
}

int
tlmsp_middlebox_table_compile_initial(SSL *s)
{
    TLMSP_MiddleboxInstance *tmis;

    for (tmis = tlmsp_middlebox_first_initial(s); tmis != NULL;
         tmis = tlmsp_middlebox_next_initial(s, tmis)) {
        /* Check for invalid entries.  */
        switch (tmis->state.id) {
        case TLMSP_MIDDLEBOX_ID_NONE:
        case TLMSP_MIDDLEBOX_ID_CLIENT:
        case TLMSP_MIDDLEBOX_ID_SERVER:
            return 0;
        default:
            break;
        }

        if (tmis->state.id == TLMSP_MIDDLEBOX_ID_NONE) {
            tmis->state.id = tlmsp_middlebox_free_id(s);
            if (tmis->state.id == TLMSP_MIDDLEBOX_ID_NONE)
                return 0;
        } else if (s->tlmsp.initial_middlebox_table[tmis->state.id] != NULL) {
            /* Duplicate entry */
            return 0;
        }

        s->tlmsp.initial_middlebox_table[tmis->state.id] = tmis;
    }

    return 1;
}

void
tlmsp_middleboxes_clear_initial(SSL *s)
{
    if (s->tlmsp.initial_middlebox_list != NULL) {
        tlmsp_middleboxes_free(s->tlmsp.initial_middlebox_list);
        s->tlmsp.initial_middlebox_list = NULL;
        memset(s->tlmsp.initial_middlebox_table, 0, sizeof s->tlmsp.initial_middlebox_table);
    }
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_first(const SSL *s)
{
    return tlmsp_middlebox_first_list(s->tlmsp.current_middlebox_list);
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_next(const SSL *s, const TLMSP_MiddleboxInstance *cursor)
{
    return tlmsp_middlebox_next_list(s, s->tlmsp.current_middlebox_list, cursor);
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_next_direction(const SSL *s, const TLMSP_MiddleboxInstance *cursor, enum tlmsp_direction d)
{
    switch (d) {
    case TLMSP_D_CTOS:
        return tlmsp_middlebox_next_list(s, s->tlmsp.current_middlebox_list, cursor);
    case TLMSP_D_STOC:
        return tlmsp_middlebox_previous_list(s, s->tlmsp.current_middlebox_list, cursor);
    default:
        /* Unreachable */
        return NULL;
    }
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_lookup(const SSL *s, tlmsp_middlebox_id_t id)
{
    /*
     * XXX
     * We could keep client and server entries in the table, too.
     */
    switch (id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        return (TLMSP_MiddleboxInstance *)&s->tlmsp.client_middlebox;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        return (TLMSP_MiddleboxInstance *)&s->tlmsp.server_middlebox;
    default:
        return s->tlmsp.current_middlebox_table[id];
    }
}

TLMSP_MiddleboxInstance *
tlmsp_middlebox_insert_after(SSL *s, const TLMSP_MiddleboxInstance *cursor, tlmsp_middlebox_id_t id)
{
    return tlmsp_middlebox_insert_after_list(&s->tlmsp.current_middlebox_list, cursor, id);
}

int
tlmsp_middlebox_table_compile_current(SSL *s)
{
    TLMSP_MiddleboxInstance *tmis;

    for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
         tmis = tlmsp_middlebox_next(s, tmis)) {
        /* Check for invalid entries.  */
        switch (tmis->state.id) {
        case TLMSP_MIDDLEBOX_ID_CLIENT:
        case TLMSP_MIDDLEBOX_ID_SERVER:
            return 0;
        case TLMSP_MIDDLEBOX_ID_NONE:
        default:
            break;
        }

        if (tmis->state.id == TLMSP_MIDDLEBOX_ID_NONE) {
            tmis->state.id = tlmsp_middlebox_free_id(s);
            if (tmis->state.id == TLMSP_MIDDLEBOX_ID_NONE)
                return 0;
        } else if (s->tlmsp.current_middlebox_table[tmis->state.id] != NULL) {
            /* Duplicate entry */
            return 0;
        }

        s->tlmsp.current_middlebox_table[tmis->state.id] = tmis;
    }

    return 1;
}

void
tlmsp_middleboxes_clear_current(SSL *s)
{
    if (s->tlmsp.current_middlebox_list != NULL) {
        tlmsp_middleboxes_free(s->tlmsp.current_middlebox_list);
        s->tlmsp.current_middlebox_list = NULL;
        memset(s->tlmsp.current_middlebox_table, 0, sizeof s->tlmsp.current_middlebox_table);
    }
}

int
tlmsp_middleboxes_dup(TLMSP_MiddleboxInstances **dst, const TLMSP_MiddleboxInstances *src)
{
    TLMSP_MiddleboxInstances *copy;

    if (src == NULL) {
        *dst = NULL;
        return 1;
    }

    copy = sk_TLMSP_MiddleboxInstance_deep_copy(src, tlmsp_middlebox_instance_dup, tlmsp_middlebox_instance_free);
    if (copy == NULL)
        return 0;

    *dst = copy;
    return 1;
}

void
tlmsp_middleboxes_free(const TLMSP_MiddleboxInstances *list)
{
    sk_TLMSP_MiddleboxInstance_pop_free((TLMSP_MiddleboxInstances *)list, tlmsp_middlebox_instance_free);
}

int
tlmsp_middlebox_establish_id(SSL *s)
{
    TLMSP_MiddleboxInstance *tmis;
    const struct tlmsp_address *adr;

    if (s->tlmsp.middlebox_config.address_match_callback == NULL)
        return 0;

    for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
         tmis = tlmsp_middlebox_next(s, tmis)) {
        adr = &tmis->state.address;

        switch (s->tlmsp.middlebox_config.address_match_callback(s, adr->address_type, adr->address, adr->address_len, s->tlmsp.middlebox_config.address_match_arg)) {
        case -1:
            return 0;
        case 0:
            continue;
        case 1:
            s->tlmsp.self = tmis;
            return 1;
        }
    }

    return 0;
}

/*
 * We prefer to assign a random middlebox identifier where possible to keep
 * applications from relying on things which may be true but are not
 * guaranteeably true about identifiers, say, being sequential.
 */
tlmsp_middlebox_id_t
tlmsp_middlebox_free_id(const SSL *s)
{
    tlmsp_middlebox_id_t id;
    unsigned n;

    /*
     * Try to find an unused random identifier.
     */
    for (n = 0; n < 4; n++) {
        if (!RAND_bytes(&id, sizeof id))
            continue;
        if ((id < TLMSP_MIDDLEBOX_ID_FIRST) ||
            (id > TLMSP_MIDDLEBOX_ID_LAST))
            continue;
        if (s->tlmsp.current_middlebox_table[id] != NULL)
            continue;
        return id;
    }

    /*
     * Fall back to a linear scan.
     */
    for (n = TLMSP_MIDDLEBOX_ID_FIRST; n <= TLMSP_MIDDLEBOX_ID_LAST; n++) {
        if (s->tlmsp.current_middlebox_table[n] != NULL)
            continue;
        return n;
    }

    return TLMSP_MIDDLEBOX_ID_NONE;
}

int
tlmsp_middlebox_accept(SSL *s)
{
    return tlmsp_middlebox_handshake_process(s, 0);
}

int
tlmsp_middlebox_connect(SSL *s)
{
    return tlmsp_middlebox_handshake_process(s, 1);
}

/*
 * Synchronize middlebox states from src to dst.
 */
int
tlmsp_middlebox_synchronize(SSL *dst, const SSL *src, int include_middleboxes)
{
    if (!tlmsp_middlebox_instance_copy(&dst->tlmsp.client_middlebox, &src->tlmsp.client_middlebox))
        return 0;
    if (!tlmsp_middlebox_instance_copy(&dst->tlmsp.server_middlebox, &src->tlmsp.server_middlebox))
        return 0;

    if (include_middleboxes) {
        if (dst->tlmsp.current_middlebox_list != NULL)
            tlmsp_middleboxes_clear_current(dst);
        if (src->tlmsp.current_middlebox_list != NULL) {
            if (!tlmsp_middleboxes_dup(&dst->tlmsp.current_middlebox_list, src->tlmsp.current_middlebox_list))
                return 0;

            /*
             * Now compile the middlebox_table.
             */
            if (!tlmsp_middlebox_table_compile_current(dst))
                return 0;

            if (src->tlmsp.self != NULL) {
                dst->tlmsp.self = tlmsp_middlebox_lookup(dst, src->tlmsp.self->state.id);
                if (dst->tlmsp.self == NULL)
                    return 0;
            }
        }
    }

    return 1;
}

int
tlmsp_middlebox_certificate(SSL *s, TLMSP_MiddleboxInstance *tmis, X509 **certp)
{
    /*
     * We do not store our own certificate in the middlebox structure on
     * middleboxes and endpoints both, but in the common parts of the TLS data
     * structures.
     */
    if (tmis == s->tlmsp.self) {
        if (s->cert != NULL && s->cert->key != NULL &&
            s->cert->key->x509 != NULL) {
            *certp = s->cert->key->x509;
            return 1;
        }
        /* No certificate, continue.  */
        *certp = NULL;
        return 1;
    }

    /*
     * Endpoints access their certificates for themselves their peer endpoints
     * in the common TLS data structures, rather than through the middlebox
     * structure.
     */
    if (!TLMSP_IS_MIDDLEBOX(s) && TLMSP_MIDDLEBOX_ID_ENDPOINT(tmis->state.id)) {
        if (s->session != NULL && s->session->peer != NULL) {
            *certp = s->session->peer;
            return 1;
        }
        /* No certificate, continue.  */
        *certp = NULL;
        return 1;
    }

    /*
     * All other certificates are found in the middlebox structures.
     */
    if (tmis->cert_chain != NULL && sk_X509_num(tmis->cert_chain) != 0) {
        *certp = sk_X509_value(tmis->cert_chain, 0);
        return 1;
    }

    /*
     * If we are a middlebox, and we have no certificate in our SSL, the other
     * half of the middlebox might have one.
     */
    if (TLMSP_IS_MIDDLEBOX(s) && s->tlmsp.middlebox_other_ssl != NULL) {
        TLMSP_MiddleboxInstance *other;

        other = tlmsp_middlebox_lookup(s->tlmsp.middlebox_other_ssl, tmis->state.id);
        if (other == NULL)
            return 0;
        if (other->cert_chain != NULL && sk_X509_num(other->cert_chain) != 0) {
            *certp = sk_X509_value(other->cert_chain, 0);
            return 1;
        }
    }

    /* No certificate, continue.  */
    *certp = NULL;
    return 1;
}

int
tlmsp_middlebox_choose_certificate(SSL *s)
{
    /*
     * We already have a list of the peer's (client's) supported signature
     * algorithms.  For now, we assume the client list is authoritative.
     *
     * Now choose a signature algorithm (and certificate) given the shared
     * signature algorithm list.
     */
    if (!tls_choose_sigalg(s, 1))
        return 0;

    return 1;
}

/*
 * There may be other helpful or necessary aspects here which could be found in
 * tls_process_server_certificate.
 */
int
tlmsp_middlebox_verify_certificate(SSL *s, TLMSP_MiddleboxInstance *tmis)
{
    int r;

    if (tmis->cert_chain == NULL || sk_X509_num(tmis->cert_chain) == 0)
        return 0;

    r = ssl_verify_cert_chain(s, tmis->cert_chain);
    if (r <= 0 && s->verify_mode != SSL_VERIFY_NONE) {
        SSLfatal(s, ssl_x509err2alert(s->verify_result), SSL_F_TLMSP_MIDDLEBOX_VERIFY_CERTIFICATE,
                 SSL_R_CERTIFICATE_VERIFY_FAILED);
        return 0;
    } else if (r > 1) {
        SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLMSP_MIDDLEBOX_VERIFY_CERTIFICATE, r);
        return 0;
    }
    ERR_clear_error();

    /*
     * XXX
     * Verify that we have a certificate appropriate to the cipher suite and
     * signature algorithms.
     *
     * Set the certificate in use by the peer, so that we have easy access to
     * it when verifying key exchanges?
     */

    return 1;
}

int
tlmsp_get_middleboxes_list(TLMSP_Middleboxes **mboxes, const TLMSP_MiddleboxInstances *list)
{
    TLMSP_Middlebox *mbox;
    TLMSP_MiddleboxInstance *tmis;
    int num_mboxes, i;

    *mboxes = sk_TLMSP_Middlebox_new_null();
    if (*mboxes == NULL) {
        SSLerr(SSL_F_TLMSP_GET_MIDDLEBOXES_LIST, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    num_mboxes = sk_TLMSP_MiddleboxInstance_num(list);
    for (i = 0; i < num_mboxes; i++) {
        /* we don't call middlebox_create() here because we don't need the init */
        mbox = OPENSSL_zalloc(sizeof *mbox);
        if (mbox == NULL) {
            TLMSP_middleboxes_free(*mboxes);
            SSLerr(SSL_F_TLMSP_GET_MIDDLEBOXES_LIST, ERR_R_MALLOC_FAILURE);
            return 0;
        }

        tmis = sk_TLMSP_MiddleboxInstance_value(list, i);
        *mbox = tmis->state;
        if (!sk_TLMSP_Middlebox_push(*mboxes, mbox)) {
            tlmsp_middlebox_free(mbox);
            TLMSP_middleboxes_free(*mboxes);
            SSLerr(SSL_F_TLMSP_GET_MIDDLEBOXES_LIST, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }

    return 1;
}

int
tlmsp_set_middlebox_list(TLMSP_MiddleboxInstances **listp, const TLMSP_Middleboxes *middleboxes)
{
    TLMSP_MiddleboxInstance *last;
    int i;

    if (middleboxes == NULL || sk_TLMSP_Middlebox_num(middleboxes) == 0)
        return 1;

    if (sk_TLMSP_Middlebox_num(middleboxes) >= TLMSP_MAX_MIDDLEBOXES)
        return 0;

    last = NULL;
    for (i = 0; i < sk_TLMSP_Middlebox_num(middleboxes); i++) {
        TLMSP_MiddleboxInstance *tmis;
        TLMSP_Middlebox *middlebox;

        middlebox = sk_TLMSP_Middlebox_value(middleboxes, i);
        tmis = tlmsp_middlebox_insert_after_list(listp, last, middlebox->id);
        if (tmis == NULL)
            return 0;
        tmis->state = *middlebox;
        last = tmis;
    }

    return 1;
}

/*
 * Compare the middleboxes in mboxes to those in list.
 *
 * If strictly_equal is true, then both sets of middleboxes must have the
 * same number of middleboxes with the same attributes in the same order.
 * If this criteria is met, 1 is returned, otherwise 0 is returned.
 *
 * If strictly_equal is false, then middleboxes that appear in both sets
 * must have the same attributes (except that the inserted attribute in
 * mboxes may be set to forbidden) - if this criteria is met, 1 is returned,
 * otherwise 0 is returned.  If 1 is returned and the network path
 * represented by mboxes is different than the one represented by list,
 * path_changed is set to true, otherwise it is set to false.
 */
int
tlmsp_middleboxes_compare(const TLMSP_MiddleboxInstances *list, const TLMSP_Middleboxes *mboxes, int strictly_equal, int *path_changed)
{
    int list_entries, num_mboxes;
    int i;
    int paths_are_different;
    TLMSP_MiddleboxInstance *tmis;
    TLMSP_Middlebox *mbox, *list_mbox;
    TLMSP_Middlebox *list_id_map[TLMSP_MIDDLEBOX_COUNT];
    TLMSP_Middlebox *mboxes_id_map[TLMSP_MIDDLEBOX_COUNT];
    tlmsp_middlebox_id_t list_order[TLMSP_MIDDLEBOX_COUNT];
    tlmsp_middlebox_id_t mboxes_order[TLMSP_MIDDLEBOX_COUNT];
    
    list_entries = sk_TLMSP_MiddleboxInstance_num(list);
    if (list_entries < 0)
        list_entries = 0;

    num_mboxes = sk_TLMSP_Middlebox_num(mboxes);
    if (num_mboxes < 0)
        num_mboxes = 0;

    memset(list_id_map, 0, sizeof list_id_map);
    memset(mboxes_id_map, 0, sizeof mboxes_id_map);
    memset(list_order, 0, sizeof list_order);
    memset(mboxes_order, 0, sizeof mboxes_order);

    for (i = 0; i < list_entries; i++) {
        tmis = sk_TLMSP_MiddleboxInstance_value(list, i);
        list_id_map[tmis->state.id] = &tmis->state;
        list_order[i] = tmis->state.id;
    }

    for (i = 0; i < num_mboxes; i++) {
        mbox = sk_TLMSP_Middlebox_value(mboxes, i);
        mboxes_id_map[mbox->id] = mbox;
        mboxes_order[i] = mbox->id;
    }

    if (strictly_equal) {
        if (num_mboxes != list_entries)
            return 0;

        /*
         * Each set is the same size, check that they have the same IDs in
         * the same order.
         */
        if (memcmp(list_order, mboxes_order, sizeof(list_order[0]) * list_entries) != 0)
            return 0;
    }

    paths_are_different = 0;
    for (i = TLMSP_MIDDLEBOX_ID_FIRST; i <= TLMSP_MIDDLEBOX_ID_LAST; i++) {
        list_mbox = list_id_map[i];
        mbox = mboxes_id_map[i];

        if (!list_mbox && !mbox)
            continue;

        if (list_mbox && !mbox) {
            if (!list_mbox->transparent) {
                /* mboxes lacks a non-transparent that is in list */
                paths_are_different = 1;
            }
            continue;
        }

        if (!list_mbox && mbox) {
            if (!mbox->transparent) {
                /* mboxes has a non-transparent that is not in list */
                paths_are_different = 1;
            }
            if (mbox->inserted == 0) {
                /* mboxes can't have an additional entry marked 'static' */
                return 0;
            }
            continue;
        }

        if ((list_mbox->inserted != mbox->inserted) &&
            (strictly_equal || (mbox->inserted != 2))) {
            /*
             * Only allow mismatched inserted attribute values if
             * strictly_equal is false and mbox->inserted is 'forbidden'
             */
            return 0;
        }

        if (list_mbox->transparent != mbox->transparent)
            return 0;

        if (!tlmsp_context_access_equal(&list_mbox->access, &mbox->access))
            return 0;

        if (!tlmsp_address_equal(&list_mbox->address, &mbox->address))
            return 0;
    }

    if (!strictly_equal)
        *path_changed = paths_are_different;
    
    return 1;
}

/* Local functions.  */

static TLMSP_Middlebox *
tlmsp_middlebox_dup_static(const TLMSP_Middlebox *tms)
{
    TLMSP_Middlebox *mbox;

    mbox = OPENSSL_zalloc(sizeof *mbox);
    if (mbox == NULL) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_DUP_STATIC, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    memcpy(mbox, tms, sizeof(*mbox));
    mbox->inserted = 0; /* static */
    
    return mbox;
}

static TLMSP_Middlebox *
tlmsp_middlebox_create(const struct tlmsp_middlebox_configuration *cfg)
{
    TLMSP_Middlebox *mbox;

    if (cfg == NULL) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_CREATE, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    mbox = OPENSSL_zalloc(sizeof *mbox);
    if (mbox == NULL) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_CREATE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    /*
     * XXX
     * Initialize mbox fields.
     *
     * ca_file_or_dir
     * ...
     */
    if (cfg->contexts != NULL)
        mbox->access = *cfg->contexts;
    mbox->inserted = 1; /* default to dynamic */
    mbox->transparent = cfg->transparent;
    if (!tlmsp_address_set(&mbox->address, cfg->address_type, (const uint8_t *)cfg->address, strlen(cfg->address))) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_CREATE, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(mbox);
        return NULL;
    }

    return mbox;
}

static int
tlmsp_middlebox_instance_copy(TLMSP_MiddleboxInstance *dst, const TLMSP_MiddleboxInstance *src)
{
    tlmsp_middlebox_instance_cleanup(dst);

    if (src->state.id == TLMSP_MIDDLEBOX_ID_NONE) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_INSTANCE_COPY, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    dst->state.id = src->state.id;

    memcpy(dst->to_client_random, src->to_client_random, sizeof dst->to_client_random);
    memcpy(dst->to_server_random, src->to_server_random, sizeof dst->to_server_random);
    memcpy(dst->master_secret, src->master_secret, sizeof dst->master_secret);

    dst->state = src->state;

    memcpy(&dst->key_block, &src->key_block, sizeof dst->key_block);
    memcpy(&dst->advance_key_block, &src->advance_key_block, sizeof dst->advance_key_block);

    if (!tlmsp_finish_copy(&dst->finish_state, &src->finish_state)) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_INSTANCE_COPY, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    tlmsp_sequence_copy(dst, src);

    if (src->cert_chain != NULL) {
        dst->cert_chain = X509_chain_up_ref(src->cert_chain);
        if (dst->cert_chain == NULL)
            return 0;
    }

    if (src->to_client_pkey != NULL) {
        EVP_PKEY_up_ref(src->to_client_pkey);
        dst->to_client_pkey = src->to_client_pkey;
    }

    if (src->to_server_pkey != NULL) {
        EVP_PKEY_up_ref(src->to_server_pkey);
        dst->to_server_pkey = src->to_server_pkey;
    }

    return 1;
}

static TLMSP_MiddleboxInstance *
tlmsp_middlebox_instance_dup(const TLMSP_MiddleboxInstance *tmis)
{
    TLMSP_MiddleboxInstance *mbox;

    mbox = OPENSSL_zalloc(sizeof *mbox);
    if (mbox == NULL) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_INSTANCE_DUP, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (!tlmsp_middlebox_instance_copy(mbox, tmis)) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_INSTANCE_DUP, ERR_R_INTERNAL_ERROR);
        tlmsp_middlebox_instance_free(mbox);
        return NULL;
    }

    return mbox;
}

static TLMSP_MiddleboxInstance *
tlmsp_middlebox_first_list(const TLMSP_MiddleboxInstances *list)
{
    if (list == NULL)
        return NULL;
    return sk_TLMSP_MiddleboxInstance_value(list, 0);
}

static TLMSP_MiddleboxInstance *
tlmsp_middlebox_last_list(const TLMSP_MiddleboxInstances *list)
{
    int num;

    if (list == NULL)
        return NULL;
    num = sk_TLMSP_MiddleboxInstance_num(list);
    if (num == 0)
        return NULL;
    return sk_TLMSP_MiddleboxInstance_value(list, num - 1);
}

static TLMSP_MiddleboxInstance *
tlmsp_middlebox_next_list(const SSL *s, TLMSP_MiddleboxInstances *list, const TLMSP_MiddleboxInstance *cursor)
{
    int idx;

    if (cursor == &s->tlmsp.client_middlebox)
        return tlmsp_middlebox_first_list(list);
    if (cursor == &s->tlmsp.server_middlebox)
        return NULL;
    if (list == NULL)
        return NULL;
    idx = sk_TLMSP_MiddleboxInstance_find(list, (TLMSP_MiddleboxInstance *)cursor);
    /* XXX Should not fail.  */
    if (idx == -1)
        return NULL;
    if (sk_TLMSP_MiddleboxInstance_num(list) == idx + 1)
        return NULL;
    return sk_TLMSP_MiddleboxInstance_value(list, idx + 1);
}

static TLMSP_MiddleboxInstance *
tlmsp_middlebox_previous_list(const SSL *s, TLMSP_MiddleboxInstances *list, const TLMSP_MiddleboxInstance *cursor)
{
    int idx;

    if (cursor == &s->tlmsp.client_middlebox)
        return NULL;
    if (cursor == &s->tlmsp.server_middlebox)
        return tlmsp_middlebox_last_list(list);
    if (list == NULL)
        return NULL;
    idx = sk_TLMSP_MiddleboxInstance_find(list, (TLMSP_MiddleboxInstance *)cursor);
    /* XXX Should not fail.  */
    if (idx == -1)
        return NULL;
    if (idx == 0)
        return NULL;
    return sk_TLMSP_MiddleboxInstance_value(list, idx - 1);
}

static TLMSP_MiddleboxInstance *
tlmsp_middlebox_insert_after_list(TLMSP_MiddleboxInstances **list, const TLMSP_MiddleboxInstance *cursor, tlmsp_middlebox_id_t id)
{
    TLMSP_MiddleboxInstance *tmis;
    int idx;

    switch (id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
    case TLMSP_MIDDLEBOX_ID_SERVER:
        return NULL;
    default:
        break;
    }

    if (*list == NULL) {
        *list = sk_TLMSP_MiddleboxInstance_new_null();
        if (*list == NULL)
            return NULL;
    }
    if (cursor != NULL) {
        idx = sk_TLMSP_MiddleboxInstance_find(*list, (TLMSP_MiddleboxInstance *)cursor);
        if (idx == -1)
            return NULL;
        if (sk_TLMSP_MiddleboxInstance_num(*list) == idx + 1)
            idx = -1;
    } else {
        idx = 0;
    }
    tmis = OPENSSL_zalloc(sizeof *tmis);
    if (tmis == NULL)
        return NULL;
    if (sk_TLMSP_MiddleboxInstance_insert(*list, tmis, idx) == 0) {
        tlmsp_middlebox_instance_free(tmis);
        return NULL;
    }

    tmis->state.id = id;
    TLMSP_ContextConfirmationTable_init(&tmis->confirmations);
    tlmsp_finish_init(&tmis->finish_state);
    tlmsp_sequence_init(tmis);

    return tmis;
}

static int
tlmsp_middlebox_handshake_error(int error, int server)
{
    switch (error) {
    case SSL_ERROR_WANT_WRITE:
        if (server)
            return SSL_ERROR_WANT_SERVER_WRITE;
        return SSL_ERROR_WANT_CLIENT_WRITE;
    default:
        return error;
    }
}

static int
tlmsp_middlebox_handshake_half(SSL *self, SSL *other, int server, int *errorp)
{
    int error;
    int rv;

    if (!SSL_in_init(self)) {
        *errorp = SSL_ERROR_NONE;
        return 1;
    }

    if (!tlmsp_middlebox_handshake_half_check_error(self, server, errorp))
        return -1;

    self->tlmsp.middlebox_handshake_error = SSL_ERROR_NONE;

    if (other != NULL) {
        self->tlmsp.middlebox_other_ssl = other;
        other->tlmsp.middlebox_other_ssl = self;

        if (!tlmsp_middlebox_handshake_half_flush(self, server, errorp))
            return -1;
        if (!tlmsp_middlebox_handshake_half_check_error(other, !server, errorp))
            return -1;

        if (!tlmsp_middlebox_handshake_half_flush(other, !server, errorp))
            return -1;
        if (!tlmsp_middlebox_handshake_half_check_error(self, server, errorp))
            return -1;
    }

    ossl_statem_set_in_handshake(self, 1);
    rv = self->handshake_func(self);
    ossl_statem_set_in_handshake(self, 0);

    if (!tlmsp_middlebox_handshake_half_check_error(self, server, errorp))
        return -1;

    if (other != NULL) {
        if (!tlmsp_middlebox_handshake_half_flush(self, server, errorp))
            return -1;
        if (!tlmsp_middlebox_handshake_half_check_error(other, !server, errorp))
            return -1;
        if (!tlmsp_middlebox_handshake_half_flush(other, !server, errorp))
            return -1;
        if (!tlmsp_middlebox_handshake_half_check_error(self, server, errorp))
            return -1;
        self->tlmsp.middlebox_other_ssl = NULL;
        other->tlmsp.middlebox_other_ssl = NULL;
    }

    if (rv == 1) {
        error = SSL_ERROR_NONE;
    } else {
        if (self->tlmsp.middlebox_handshake_error != SSL_ERROR_NONE) {
            error = self->tlmsp.middlebox_handshake_error;
        } else {
            if (!tlmsp_middlebox_handshake_half_check_error(self, server, errorp))
                return -1;
            error = SSL_get_error(self, rv);
        }
    }
    *errorp = tlmsp_middlebox_handshake_error(error, server);

    return rv;
}

static int
tlmsp_middlebox_handshake_half_check_error(SSL *self, int server, int *errorp)
{
    unsigned l;

    /*
     * Check if this SSL is in error state.
     */
    if (self->statem.state != MSG_FLOW_ERROR)
        return 1;

    /*
     * XXX
     * No per-SSL errors yet.
     */
    if ((l = ERR_peek_error()) == 0)
        return 1;
    if (ERR_GET_LIB(l) == ERR_LIB_SYS)
        *errorp = SSL_ERROR_SYSCALL;
    else
        *errorp = SSL_ERROR_SSL;
    return 0;
}

static int
tlmsp_middlebox_handshake_half_flush(SSL *self, int server, int *errorp)
{
    int done;

    ossl_statem_set_in_handshake(self->tlmsp.middlebox_other_ssl, 1);
    done = tlmsp_middlebox_handshake_flush(self);
    ossl_statem_set_in_handshake(self->tlmsp.middlebox_other_ssl, 0);
    if (!done) {
        /*
         * If we are flushing the queue of writes generated on the server
         * side, and we have more to write, we want to wait for the client
         * side to become writable, and vice versa.
         *
         * If there is an actual error, however, we must indicate such.
         *
         * Likewise, if the underlying BIO doesn't want us to write to it, we
         * treat that as a BIO/SYSCALL level error.
         */
        if (!tlmsp_middlebox_handshake_half_check_error(self, server, errorp))
            return 0;
        if (BIO_should_write(self->wbio)) {
            if (server)
                *errorp = SSL_ERROR_WANT_CLIENT_WRITE;
            else
                *errorp = SSL_ERROR_WANT_SERVER_WRITE;
        } else {
            *errorp = SSL_ERROR_SYSCALL;
        }
        return 0;
    }
    return 1;
}

static int
tlmsp_middlebox_handshake_final_flush(SSL *toclient, SSL *toserver, int *errorp)
{
    int done;

    toclient->tlmsp.middlebox_other_ssl = toserver;
    done = tlmsp_middlebox_handshake_half_flush(toclient, 0, errorp);
    toclient->tlmsp.middlebox_other_ssl = NULL;

    if (!done)
        return 0;

    toserver->tlmsp.middlebox_other_ssl = toclient;
    done = tlmsp_middlebox_handshake_half_flush(toserver, 1, errorp);
    toserver->tlmsp.middlebox_other_ssl = NULL;

    if (!done)
        return 0;

    return 1;
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
