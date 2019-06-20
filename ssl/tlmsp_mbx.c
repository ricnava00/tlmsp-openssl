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

#pragma clang diagnostic error "-Wmissing-prototypes"

#define TLMSP_MAX_MIDDLEBOXES   ((TLMSP_MIDDLEBOX_COUNT - 1) - TLMSP_MIDDLEBOX_ID_FIRST)

static TLMSP_Middlebox *tlmsp_middlebox_create(const struct tlmsp_middlebox_configuration *);
static int tlmsp_middlebox_establish_id(SSL *);
static int tlmsp_middlebox_handshake_error(int, int);
static int tlmsp_middlebox_handshake_half(SSL *, SSL *, int, int *);
static int tlmsp_middlebox_handshake_half_check_error(SSL *, int, int *);
static int tlmsp_middlebox_handshake_half_flush(SSL *, int, int *);
static int tlmsp_middlebox_handshake_final_flush(SSL *, SSL *, int *);

/* API functions.  */

/*
 * XXX
 * We need to ensure that so long as we are not done with the handshake we do
 * not return 1, even though internally we use 1 to represent success.
 *
 * We want to return 1 only if both halves are finished.
 *
 * XXX
 * We need to be sure that if there are actual errors queued on either toclient
 * or toserver that we return whichever of those at whatever point.  Currently
 * errors don't actually error.
 */
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
         * If we are ready to connect onward and have not yet established the
         * middlebox ID, this is a good time to do it.
         */
        if (rv[0] == -1 &&
            error[0] == SSL_ERROR_WANT_OUTBOUND_CONN &&
            toclient->tlmsp.self_id == TLMSP_MIDDLEBOX_ID_NONE) {
            /*
             * If we are ready to connect onward, and don't yet know our
             * id, this is a good time to establish it.
             */
            toclient->tlmsp.peer_id = TLMSP_MIDDLEBOX_ID_CLIENT;
            if (!tlmsp_middlebox_establish_id(toclient)) {
                *errorp = SSL_ERROR_SSL;
                return -1;
            }
        }

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
         * If the server ID has not yet been established but the client ID has, we
         * can absorb it now.
         */
        if (toserver->tlmsp.self_id == TLMSP_MIDDLEBOX_ID_NONE &&
            toclient->tlmsp.self_id != TLMSP_MIDDLEBOX_ID_NONE) {
            toserver->tlmsp.peer_id = TLMSP_MIDDLEBOX_ID_SERVER;
            toserver->tlmsp.self_id = toclient->tlmsp.self_id;
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
    unsigned i;

    if (sk_TLMSP_Middlebox_num(middleboxes) == 0)
        return 1;
    if (sk_TLMSP_Middlebox_num(middleboxes) >= TLMSP_MAX_MIDDLEBOXES)
        return 0;

    for (i = 0; i < sk_TLMSP_Middlebox_num(middleboxes); i++) {
        struct tlmsp_middlebox_state *tms;
        TLMSP_Middlebox *middlebox;
        tlmsp_middlebox_id_t id;

        middlebox = sk_TLMSP_Middlebox_value(middleboxes, i);

        id = TLMSP_MIDDLEBOX_ID_FIRST + i;
        tms = &ctx->tlmsp.middlebox_states[id];
        *tms = middlebox->state;
    }

    return 1;
}

int
TLMSP_set_initial_middleboxes_instance(SSL *s, const TLMSP_Middleboxes *middleboxes)
{
    unsigned i;

    if (sk_TLMSP_Middlebox_num(middleboxes) == 0)
        return 1;
    if (sk_TLMSP_Middlebox_num(middleboxes) >= TLMSP_MAX_MIDDLEBOXES)
        return 0;

    for (i = 0; i < sk_TLMSP_Middlebox_num(middleboxes); i++) {
        struct tlmsp_middlebox_instance_state *tmis;
        TLMSP_Middlebox *middlebox;
        tlmsp_middlebox_id_t id;

        middlebox = sk_TLMSP_Middlebox_value(middleboxes, i);

        id = TLMSP_MIDDLEBOX_ID_FIRST + i;
        tmis = &s->tlmsp.middlebox_states[id];
        tmis->state = middlebox->state;
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
    if (sk_TLMSP_Middlebox_num(mboxes) == 0)
        return NULL;
    return sk_TLMSP_Middlebox_value(mboxes, sk_TLMSP_Middlebox_num(mboxes) - 1);
}

TLMSP_Middlebox *
TLMSP_middleboxes_next(const TLMSP_Middleboxes *mboxes, const TLMSP_Middlebox *mbox)
{
    int n;

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
        /* Just insert at the end.  */
        if (!sk_TLMSP_Middlebox_insert(mboxes, mbox, -1)) {
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
    return tlmsp_address_get(&middlebox->state.address, address_type, outbuf, outlen);
}

const TLMSP_ContextAccess *
TLMSP_middlebox_context_access(const TLMSP_Middlebox *mbox)
{
    return &mbox->state.access;
}

int
TLMSP_middlebox_forbid(TLMSP_Middlebox *middlebox)
{
    /* XXX */
    return (0);
}

/* Internal functions.  */

void
tlmsp_middlebox_free(TLMSP_Middlebox *middlebox)
{
    OPENSSL_free(middlebox);
}

/* XXX _first and _next_ should use network topological order.  */
tlmsp_middlebox_id_t
tlmsp_middlebox_first(const SSL *s)
{
    if (!tlmsp_middlebox_present(s, TLMSP_MIDDLEBOX_ID_FIRST))
        return TLMSP_MIDDLEBOX_ID_NONE;
    return TLMSP_MIDDLEBOX_ID_FIRST;
}

tlmsp_middlebox_id_t
tlmsp_middlebox_next(const SSL *s, tlmsp_middlebox_id_t id)
{
    if (id == TLMSP_MIDDLEBOX_ID_CLIENT)
        return tlmsp_middlebox_first(s);
    if (id == TLMSP_MIDDLEBOX_ID_SERVER)
        return TLMSP_MIDDLEBOX_ID_NONE;
    if (TLMSP_MIDDLEBOX_COUNT - 1 == id)
        return TLMSP_MIDDLEBOX_ID_NONE;
    if (!tlmsp_middlebox_present(s, id + 1))
        return TLMSP_MIDDLEBOX_ID_NONE;
    return id + 1;
}

int
tlmsp_middlebox_present(const SSL *s, tlmsp_middlebox_id_t id)
{
    const struct tlmsp_middlebox_instance_state *tmis;

    switch (s->tlmsp.self_id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
    case TLMSP_MIDDLEBOX_ID_SERVER:
        break;
    default:
        /*
         * XXX
         * Do we need to support this case?
         *
         * Will a middlebox ever check for its own presence?
         *
         * Middleboxes don't have A_to_A keys.
         *
         * Maybe some general logic will want this.
         */
        if (s->tlmsp.self_id == id)
            return 1;
        break;
    }
    tmis = &s->tlmsp.middlebox_states[id];
    return (tmis->state.present);
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

/* Local functions.  */

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
    mbox->state.present = 1;
    if (cfg->contexts != NULL)
        mbox->state.access = *cfg->contexts;
    mbox->state.transparent = cfg->transparent;
    if (!tlmsp_address_set(&mbox->state.address, cfg->address_type, (const uint8_t *)cfg->address, strlen(cfg->address))) {
        SSLerr(SSL_F_TLMSP_MIDDLEBOX_CREATE, ERR_R_INTERNAL_ERROR);
        OPENSSL_free(mbox);
        return NULL;
    }

    return mbox;
}

static int
tlmsp_middlebox_establish_id(SSL *s)
{
    const struct tlmsp_middlebox_instance_state *tmis;
    const struct tlmsp_address *adr;
    unsigned i;

    if (s->tlmsp.middlebox_config.address_match_callback == NULL)
        return 0;

    for (i = TLMSP_MIDDLEBOX_ID_FIRST; i < TLMSP_MIDDLEBOX_COUNT; i++) {
        tmis = &s->tlmsp.middlebox_states[i];
        if (!tmis->state.present)
            continue;
        adr = &tmis->state.address;
        switch (s->tlmsp.middlebox_config.address_match_callback(s, adr->address_type, adr->address, adr->address_len, s->tlmsp.middlebox_config.address_match_arg)) {
        case -1:
            return 0;
        case 0:
            continue;
        case 1:
            s->tlmsp.self_id = i;
            return 1;
        }
    }
    return 0;
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
         */
        if (server)
            *errorp = SSL_ERROR_WANT_CLIENT_WRITE;
        else
            *errorp = SSL_ERROR_WANT_SERVER_WRITE;
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
