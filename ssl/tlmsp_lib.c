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

/* API functions.  */

int
TLMSP_get_sid(const SSL *s, tlmsp_sid_t *sidp)
{
    if (!s->tlmsp.have_sid)
        return 0;
    *sidp = s->tlmsp.sid;
    return 1;
}

void
TLMSP_set_discovery_cb(SSL_CTX *ctx, TLMSP_discovery_cb_fn cb, void *arg)
{
    /* XXX */
}

void TLMSP_set_discovery_cb_instance(SSL *s, TLMSP_discovery_cb_fn cb, void *arg)
{
    /* XXX */
}

int
TLMSP_discovery_get_hash(SSL *s, unsigned char *buf, size_t buflen)
{
    /* XXX we are relying on caller to be separately aware of which hash is in use in order to size buffer / result */
    return (0);
}

const TLMSP_ReconnectState *
TLMSP_get_reconnect_state(SSL *s)
{
    /* XXX */
    return (NULL);
}

int
TLMSP_set_reconnect_state(SSL *s, const TLMSP_ReconnectState *reconnect)
{
    /* XXX */
    return (0);
}

void
TLMSP_reconnect_state_free(const TLMSP_ReconnectState *reconnect)
{
    if (reconnect == NULL)
        return;
    /* XXX */
}

/* Internal functions.  */

int
tlmsp_state_init(SSL_CTX *ctx)
{
    ctx->tlmsp.default_context = TLMSP_CONTEXT_DEFAULT;

    /*
     * Context 0 is always present, unaudited, and unpurposed.
     */
    if (!tlmsp_context_state_init(&ctx->tlmsp.context_states[TLMSP_CONTEXT_CONTROL], "control context", TLMSP_CONTEXT_AUDIT_UNCONFIRMED))
        return 0;

    /*
     * Provide a default context also; this will be removed by
     * TLMSP_set_contexts or TLMSP_set_contexts_instance.
     */
    if (!tlmsp_context_state_init(&ctx->tlmsp.context_states[TLMSP_CONTEXT_DEFAULT], "default context", TLMSP_CONTEXT_AUDIT_UNCONFIRMED))
        return 0;

    /*
     * The client and server are always present.
     */
    ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].present = 1;
    ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].present = 1;

    memset(&ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].address, 0, sizeof ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].address);
    memset(&ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].address, 0, sizeof ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].address);

    return 1;
}

void
tlmsp_state_free(SSL_CTX *ctx)
{
}

int
tlmsp_instance_state_init(SSL *s, SSL_CTX *ctx)
{
    unsigned j;

    if (ctx != NULL) {
        /*
         * Copy all present contexts from the SSL_CTX.
         */
        for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
            struct tlmsp_context_instance_state *tcis;
            struct tlmsp_context_state *tcs;

            tcs = &ctx->tlmsp.context_states[j];
            tcis = &s->tlmsp.context_states[j];

            memset(tcis, 0, sizeof *tcis);

            if (!tcs->present)
                continue;
            tcis->state = *tcs;
        }

        /*
         * Copy all present middleboxes from the SSL_CTX.
         */
        for (j = 0; j < TLMSP_MIDDLEBOX_COUNT; j++) {
            struct tlmsp_middlebox_instance_state *tmis;
            struct tlmsp_middlebox_state *tms;

            tms = &ctx->tlmsp.middlebox_states[j];
            tmis = &s->tlmsp.middlebox_states[j];

            memset(tmis, 0, sizeof *tmis);

            if (!tms->present)
                continue;
            tmis->state = *tms;
        }
    }

    /*
     * Copy middlebox configuration parameters.
     */
    s->tlmsp.middlebox_config = ctx->tlmsp.middlebox_config;

    if (!tlmsp_instance_state_reset(s))
        return 0;

    return 1;
}

int
tlmsp_instance_state_reset(SSL *s)
{
    struct tlmsp_middlebox_instance_state *tmis;
    unsigned i;
    unsigned j;

    /*
     * We always keep hash and cipher contexts around.  They never hold key or
     * even algorithm information for us to reuse, and are initialized before
     * each use unlike OpenSSL.  As a result, they can be long-lived, and do
     * not require resets.  This is especially helpful because we sometimes
     * need them before the first ChangeCipherSpec (e.g. for encrypting key
     * material sent to a middlebox), and we want to be able to use a context
     * freely at that point.
     */
    if (s->enc_read_ctx == NULL) {
        s->enc_read_ctx = EVP_CIPHER_CTX_new();
        if (s->enc_read_ctx == NULL)
            return 0;
    }
    if (s->enc_write_ctx == NULL) {
        s->enc_write_ctx = EVP_CIPHER_CTX_new();
        if (s->enc_write_ctx == NULL)
            return 0;
    }
    if (s->read_hash == NULL) {
        s->read_hash = EVP_MD_CTX_new();
        if (s->read_hash == NULL)
            return 0;
    }
    if (s->write_hash == NULL) {
        s->write_hash = EVP_MD_CTX_new();
        if (s->write_hash == NULL)
            return 0;
    }

    s->tlmsp.self_id = TLMSP_MIDDLEBOX_ID_NONE;
    s->tlmsp.peer_id = TLMSP_MIDDLEBOX_ID_NONE;

    s->tlmsp.have_sid = 0;
    s->tlmsp.record_sid = 0;
    s->tlmsp.alert_container = 0;

    s->tlmsp.current_context = s->ctx->tlmsp.default_context;

    s->tlmsp.stream_read_offset = 0;
    if (s->tlmsp.stream_read_container != NULL) {
        TLMSP_container_free(s, s->tlmsp.stream_read_container);
        s->tlmsp.stream_read_container = NULL;
    }
    s->tlmsp.read_last_context = TLMSP_CONTEXT_CONTROL;

    s->tlmsp.container_read_offset = 0;
    s->tlmsp.container_read_length = 0;

    /*
     * If we are a server, reset all contexts except for context 0.  We receive
     * our context list from the client.
     */
    if (s->server) {
        for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
            if (j == TLMSP_CONTEXT_CONTROL)
                continue;
            s->tlmsp.context_states[j].state.present = 0;
        }
    }

    /*
     * We currently leave all middlebox states in place.
     *
     * TODO How do we want to handle these on reset?
     */

    /*
     * Middleboxes and servers propulate client and server addresses from
     * the ClientHello, so clear them here.
     */
    if (TLMSP_IS_MIDDLEBOX(s) || s->server) {
        s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].state.address.address_len = 0;
        s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address.address_len = 0;
    }

    s->tlmsp.send_middlebox_key_material = 1;
    s->tlmsp.next_middlebox_key_material_middlebox = TLMSP_MIDDLEBOX_ID_NONE;

    for (i = 0; i < TLMSP_MIDDLEBOX_COUNT; i++) {
        tmis = &s->tlmsp.middlebox_states[i];
        if (!tmis->state.present)
            continue;
        if (tmis->to_client_pkey != NULL) {
            EVP_PKEY_free(tmis->to_client_pkey);
            tmis->to_client_pkey = NULL;
        }
        if (tmis->to_server_pkey != NULL) {
            EVP_PKEY_free(tmis->to_server_pkey);
            tmis->to_server_pkey = NULL;
        }
    }

    tlmsp_middlebox_handshake_free(s);

    return 1;
}

void
tlmsp_instance_state_free(SSL *s)
{
    /* Use the reset function to get rid of anything temporary.  */
    (void)tlmsp_instance_state_reset(s);

    /* Now clear away anything persistent.  */

    if (s->enc_read_ctx != NULL) {
        EVP_CIPHER_CTX_free(s->enc_read_ctx);
        s->enc_read_ctx = NULL;
    }

    if (s->enc_write_ctx != NULL) {
        EVP_CIPHER_CTX_free(s->enc_write_ctx);
        s->enc_write_ctx = NULL;
    }

    if (s->read_hash != NULL) {
        EVP_MD_CTX_free(s->read_hash);
        s->read_hash = NULL;
    }

    if (s->write_hash != NULL) {
        EVP_MD_CTX_free(s->write_hash);
        s->write_hash = NULL;
    }
}

int
tlmsp_read_sid(SSL *s, PACKET *pkt)
{
    unsigned long sid;

    if (!PACKET_get_net_4(pkt, &sid))
        return 0;

    if (s->tlmsp.have_sid) {
        /* XXX Sid mismatch.  Alert?  */
        if (s->tlmsp.sid != sid)
            return 0;
    } else {
        /* XXX Server should establish Sid before reading one.  Alert?  */
        if (s->server)
            return 0;
        s->tlmsp.sid = sid;
        s->tlmsp.have_sid = 1;
    }
    return 1;
}

int
tlmsp_write_sid(SSL *s, WPACKET *pkt)
{
    if (!s->tlmsp.have_sid) {
        /* XXX No Sid established.  Alert?  */
        if (!s->server)
            return 0;
        /* Generate a Sid.  */
        if (RAND_bytes((void *)&s->tlmsp.sid, sizeof s->tlmsp.sid) <= 0)
            return 0;
        s->tlmsp.have_sid = 1;
    }

    if (!WPACKET_put_bytes_u32(pkt, s->tlmsp.sid))
        return 0;

    return 1;
}

int
tlmsp_read_bytes(SSL *s, int type, int *rtypep, unsigned char *buf, size_t buflen, int peek, size_t *readp)
{
    const uint8_t *d;
    size_t resid;
    int rv;

    if (tlmsp_record_context0(s, type)) {
        /* Not containerized, context 0.  */
        return ssl3_read_bytes(s, type, rtypep, buf, buflen, peek, readp);
    }

    if (type != SSL3_RT_APPLICATION_DATA) {
        fprintf(stderr, "Unexpected %s with type %d!\n", __func__, type);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_BYTES,
                 ERR_R_INTERNAL_ERROR);
        return -1;
    }

    if (s->tlmsp.stream_read_container == NULL) {
        rv = TLMSP_container_read(s, &s->tlmsp.stream_read_container);
        if (rv <= 0)
            return rv;
        if (s->tlmsp.stream_read_container == NULL) {
            *readp = 0;
            return 1;
        }
        if (TLMSP_container_length(s->tlmsp.stream_read_container) == 0) {
            TLMSP_container_free(s, s->tlmsp.stream_read_container);
            s->tlmsp.stream_read_container = NULL;
            s->tlmsp.stream_read_offset = 0;

            *readp = 0;
            return 1;
        }
        /*
         * Continue with this container readable.
         */
    }

    resid = TLMSP_container_length(s->tlmsp.stream_read_container) -
        s->tlmsp.stream_read_offset;
    if (resid == 0) {
        TLMSP_container_free(s, s->tlmsp.stream_read_container);
        s->tlmsp.stream_read_container = NULL;
        s->tlmsp.stream_read_offset = 0;

        *readp = 0;

        return 1;
    }

    s->tlmsp.read_last_context = s->tlmsp.stream_read_container->contextId;
    d = TLMSP_container_get_data(s->tlmsp.stream_read_container);
    d += s->tlmsp.stream_read_offset;
    if (buflen < resid) {
        memcpy(buf, d, buflen);

        s->tlmsp.stream_read_offset += buflen;

        *readp = buflen;
    } else {
        memcpy(buf, d, resid);

        TLMSP_container_free(s, s->tlmsp.stream_read_container);
        s->tlmsp.stream_read_container = NULL;
        s->tlmsp.stream_read_offset = 0;

        *readp = resid;
    }

    return 1;
}

int
tlmsp_write_bytes(SSL *s, int type, const void *buf, size_t buflen, size_t *writtenp)
{
    TLMSP_Container *c;
    int rv;

    if (type != SSL3_RT_APPLICATION_DATA) {
        fprintf(stderr, "Unexpected %s with type %d!\n", __func__, type);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_BYTES,
                 ERR_R_INTERNAL_ERROR);
        return -1;
    }

    /*
     * XXX
     * Should we be creating empty containers?
     *
     * XXX
     * How about when nonzero write is used to drive handshake?
     */
    if (buflen == 0)
        return ssl3_write_bytes(s, type, buf, buflen, writtenp);

    /*
     * XXX
     * We actually need to calculate/derive the effective maximum container
     * fragment length for this session and context.
     *
     * XXX
     * Or we just always do a partial write so we don't end up with the return
     * status (if not 1) referring to a write after a successful write.
     */
    if (buflen > TLMSP_CONTAINER_MAX_SIZE) {
        const unsigned char *bp;
        size_t resid;
        int rv;

        bp = buf;
        resid = buflen;
        while (resid != 0) {
            size_t written;
            size_t nwrite;
            if (resid >= TLMSP_CONTAINER_MAX_SIZE)
                nwrite = TLMSP_CONTAINER_MAX_SIZE;
            else
                nwrite = resid;
            rv = tlmsp_write_bytes(s, type, bp, nwrite, &written);
            if (rv != 1) {
                /* XXX Should we indicate success with what we wrote so far?  */
                return rv;
            }
            bp += written;
            resid -= written;
        }

        *writtenp = buflen;
        return 1;
    }

    if (!TLMSP_container_create(s, &c, s->tlmsp.current_context, buf, buflen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_BYTES,
                 ERR_R_INTERNAL_ERROR);
        return -1;
    }

    rv = TLMSP_container_write(s, c);
    if (rv != 1) {
        TLMSP_container_free(s, c);
        return rv;
    }

    *writtenp = buflen;
    return 1;
}

/* Local functions.  */

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
