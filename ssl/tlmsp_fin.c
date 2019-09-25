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

static int tlmsp_finish_append_Lcontrib(SSL *, struct tlmsp_finish_state *, TLMSP_MiddleboxInstance *);
static int tlmsp_finish_append_bytes(SSL *, struct tlmsp_finish_state *, const void *, size_t);
static int tlmsp_finish_construct_Lcontrib(SSL *, TLMSP_MiddleboxInstance *, struct tlmsp_buffer *);
static int tlmsp_finish_generate(SSL *, TLMSP_MiddleboxInstance *, const char *, void *, size_t);
static const char *tlmsp_finish_verify_label(const TLMSP_MiddleboxInstance *, const TLMSP_MiddleboxInstance *);

/*
 * XXX
 * These values are not specified in the TLMSP spec and so have been created
 * here as placeholders, and potentially proposed values.
 *
 * See section 7.4.9 of RFC5246.
 */
#define TLMSP_FINISH_LABEL_CTOM "client-middlebox finished"
#define TLMSP_FINISH_LABEL_MTOC "middlebox-client finished"
#define TLMSP_FINISH_LABEL_STOM "server-middlebox finished"
#define TLMSP_FINISH_LABEL_MTOS "middlebox-server finished"

/* Internal functions.  */

void
tlmsp_finish_init(struct tlmsp_finish_state *fin)
{
    tlmsp_buffer_init(&fin->buf);
}

void
tlmsp_finish_clear(struct tlmsp_finish_state *fin)
{
    tlmsp_buffer_clear(&fin->buf);
}

int
tlmsp_finish_copy(struct tlmsp_finish_state *dst, const struct tlmsp_finish_state *src)
{
    return tlmsp_buffer_copy(&dst->buf, &src->buf);
}

int
tlmsp_finish_construct(SSL *s, TLMSP_MiddleboxInstance *tmis, WPACKET *pkt)
{
    uint8_t verify_data[TLS1_FINISH_MAC_LENGTH];
    const char *verify_label;

    verify_label = tlmsp_finish_verify_label(s->tlmsp.self, tmis);
    if (verify_label == NULL)
        return 0;

    if (!tlmsp_finish_generate(s, tmis, verify_label, verify_data, sizeof verify_data))
        return 0;

    if (!WPACKET_memcpy(pkt, verify_data, sizeof verify_data))
        return 0;

    return 1;
}

int
tlmsp_finish_verify(SSL *s, TLMSP_MiddleboxInstance *tmis, const void *wire_verify_data, size_t wire_verify_datalen)
{
    uint8_t verify_data[TLS1_FINISH_MAC_LENGTH];
    const char *verify_label;

    if (wire_verify_datalen != sizeof verify_data)
        return 0;

    verify_label = tlmsp_finish_verify_label(tmis, s->tlmsp.self);
    if (verify_label == NULL)
        return 0;

    if (!tlmsp_finish_generate(s, tmis, verify_label, verify_data, sizeof verify_data))
        return 0;

    if (CRYPTO_memcmp(verify_data, wire_verify_data, sizeof verify_data) != 0)
        return 0;

    return 1;
}

int
tlmsp_finish_append(SSL *s, int originated, int rt, const void *m, size_t mlen)
{
    TLMSP_MiddleboxInstance *target, *tmis;
    tlmsp_middlebox_id_t tid;
    int include_other, include_other_only, include_Lcontrib, mt;

    if (rt != SSL3_RT_HANDSHAKE)
        return 1; /* Not included.  */

    if (mlen < 1)
        return 0;
    mt = ((const uint8_t *)m)[0];

    /*
     * On endpoints, we must buffer the ClientHello and ServerHello, and then
     * process them as soon as we get some other message.  We cannot handle them
     * when they come in as we have to finish receiving the ServerHello on the
     * client and the ClientHello on the server before we have a complete set of
     * middleboxes that will be configured, and thus can be able to put it into
     * the finish state for each of them.
     *
     * We keep the logic the same on both endpoints for consistency, it could
     * be more conservative on the server side when sending ServerHello.
     *
     * Middleboxes are not so afflicted as they only keep finish state with
     * each endpoint.
     */
    if (!TLMSP_IS_MIDDLEBOX(s)) {
        const void *hd;
        size_t hdlen;

        switch (mt) {
        case SSL3_MT_CLIENT_HELLO:
            if (!tlmsp_buffer_empty(&s->tlmsp.client_hello_buffer))
                break;
            return tlmsp_buffer_append(&s->tlmsp.client_hello_buffer, m, mlen);
        case SSL3_MT_SERVER_HELLO:
            if (!tlmsp_buffer_empty(&s->tlmsp.server_hello_buffer))
                break;
            return tlmsp_buffer_append(&s->tlmsp.server_hello_buffer, m, mlen);
        default:
            /*
             * We have something other than ClientHello and ServerHello, time to
             * process them.
             */
            if (!tlmsp_buffer_empty(&s->tlmsp.client_hello_buffer)) {
                hd = tlmsp_buffer_data(&s->tlmsp.client_hello_buffer, &hdlen);
                if (hd == NULL)
                    return 0;
                if (!tlmsp_finish_append(s, !s->server, SSL3_RT_HANDSHAKE, hd, hdlen))
                    return 0;
                tlmsp_buffer_clear(&s->tlmsp.client_hello_buffer);
            }
            if (!tlmsp_buffer_empty(&s->tlmsp.server_hello_buffer)) {
                hd = tlmsp_buffer_data(&s->tlmsp.server_hello_buffer, &hdlen);
                if (hd == NULL)
                    return 0;
                if (!tlmsp_finish_append(s, s->server, SSL3_RT_HANDSHAKE, hd, hdlen))
                    return 0;
                tlmsp_buffer_clear(&s->tlmsp.server_hello_buffer);
            }
            break;
        }
    }

    if (!TLMSP_IS_MIDDLEBOX(s)) {
        if (!TLMSP_HAVE_MIDDLEBOXES(s))
            return 1; /* Nothing to do.  */
    }

    target = NULL;
    include_other = 0;
    include_other_only = 0;
    include_Lcontrib = 0;

    /*
     * TODO
     * CertificateRequest
     * MboxCertificateRequest
     * CertificateMbox
     * ClientMboxKeyExchange
     */
    switch (mt) {
        /* Things only sent by clients.  */
    case SSL3_MT_CLIENT_HELLO:
    case SSL3_MT_CLIENT_KEY_EXCHANGE:
        if (originated) {
            if (TLMSP_IS_MIDDLEBOX(s) || s->server)
                return 0;
        } else {
            if (!TLMSP_IS_MIDDLEBOX(s) && !s->server)
                return 0;
        }
        include_other = 1;
        break;

        /* Things only sent by servers.  */
    case SSL3_MT_SERVER_HELLO:
    case SSL3_MT_SERVER_KEY_EXCHANGE:
    case SSL3_MT_SERVER_DONE:
        if (originated) {
            if (TLMSP_IS_MIDDLEBOX(s) || !s->server)
                return 0;
        } else {
            if (!TLMSP_IS_MIDDLEBOX(s) && s->server)
                return 0;
        }
        include_other = 1;
        break;

        /* Things sent by clients or servers.  */
    case SSL3_MT_CERTIFICATE:
        if (originated && TLMSP_IS_MIDDLEBOX(s))
            return 0;
        include_other = 1;
        break;

        /* Things sent only by middleboxes and which go into a specific .  */
    case TLMSP_MT_MIDDLEBOX_CERT:
    case TLMSP_MT_MIDDLEBOX_HELLO:
    case TLMSP_MT_MIDDLEBOX_HELLO_DONE:
        if (originated && !TLMSP_IS_MIDDLEBOX(s))
            return 0;
        if (!originated && TLMSP_IS_MIDDLEBOX(s))
            return 1; /* Not included.  */
        if (!TLMSP_IS_MIDDLEBOX(s)) {
            if (mlen < 5)
                return 0;
            tid = ((const uint8_t *)m)[4];
            if (TLMSP_MIDDLEBOX_ID_ENDPOINT(tid))
                return 0;
            target = tlmsp_middlebox_lookup(s, tid);
            if (target == NULL)
                return 0;
        }
        include_other = 0;
        break;

        /* Things sent only by endpoints, and only included if targeting other endpoints.  */
    case TLMSP_MT_MIDDLEBOX_KEY_MATERIAL:
        if (originated && TLMSP_IS_MIDDLEBOX(s))
            return 0;
        if (mlen < 5)
            return 0;
        tid = ((const uint8_t *)m)[4];
        if (!TLMSP_MIDDLEBOX_ID_ENDPOINT(tid))
            return 1; /* Not included.  */
        include_other = 1;
        break;

        /* Finished is special.  */
    case SSL3_MT_FINISHED:
        /*
         * If we are a middlebox, we include the client Finished message in our
         * MiddleboxFinished hash with both the client and the server.
         */
        if (TLMSP_IS_MIDDLEBOX(s)) {
            if (originated)
                return 0;
            if (TLMSP_MIDDLEBOX_ID_PEER(s) == TLMSP_MIDDLEBOX_ID_CLIENT)
                include_Lcontrib = 1;
            else
                include_other_only = 1;
            include_other = 1;
        } else {
            /*
             * If we are the server, we do not include the Finished message we
             * originate, but do include Lcontrib, a concatenation of the
             * entire set of key material contributions provided to each
             * middlebox, before the client-provided Finished message.
             */
            if (s->server) {
                if (originated)
                    return 1; /* Not included.  */
                include_Lcontrib = 1;
            }
        }
        break;

        /* Everything else in the handshake.  */
    default:
        return 1; /* Not included.  */
    }

    /*
     * If we are a middlebox, add this message to our buffer of handshake
     * messages with the peer.
     */
    if (TLMSP_IS_MIDDLEBOX(s)) {
        /*
         * If we are including this in the other direction also, do that here.
         */
        if (include_other) {
            SSL *other = s->tlmsp.middlebox_other_ssl;

            if (other == NULL)
                return 0;

            /*
             * In middlebox mode, when we receive the client Finished message,
             * we insert Lcontrib into the server-facing transcript ahead of
             * the Finished message itself.
             */
            if (include_Lcontrib) {
                if (!tlmsp_finish_append_Lcontrib(other, &other->tlmsp.middlebox_finish_state, other->tlmsp.self))
                    return 0;
            }
            if (!tlmsp_finish_append_bytes(other, &other->tlmsp.middlebox_finish_state, m, mlen))
                return 0;
        } else {
            if (include_Lcontrib)
                return 0;
        }

        if (!include_other_only) {
            if (!tlmsp_finish_append_bytes(s, &s->tlmsp.middlebox_finish_state, m, mlen))
                return 0;
        }

        return 1;
    }

    /*
     * We are an endpoint, we must add this message to either every middlebox,
     * or, if we have a specific target middlebox, to just that middlebox.
     */
    if (target == NULL) {
        for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
             tmis = tlmsp_middlebox_next(s, tmis)) {
            if (include_Lcontrib) {
                if (!tlmsp_finish_append_Lcontrib(s, &tmis->finish_state, tmis))
                    return 0;
            }
            if (!tlmsp_finish_append_bytes(s, &tmis->finish_state, m, mlen))
                return 0;
        }
    } else {
        if (include_Lcontrib)
            return 0;
        if (!tlmsp_finish_append_bytes(s, &target->finish_state, m, mlen))
            return 0;
    }

    return 1;
}

int
tlmsp_finish_endpoint_exclude(const SSL *s, int originated, int rt, const void *m, size_t mlen)
{
    tlmsp_middlebox_id_t tid;
    int mt;

    if (rt != SSL3_RT_HANDSHAKE)
        return 1; /* Not included.  */

    if (mlen < 1)
        return 1; /* Invalid, not included.  */
    mt = ((const uint8_t *)m)[0];

    switch (mt) {
    case TLMSP_MT_MIDDLEBOX_KEY_CONFIRMATION:
    case TLMSP_MT_MIDDLEBOX_FINISHED:
        return 1; /* Not included.  */

        /*
         * Only MiddleboxKeyMaterial messages which target an endpoint are
         * included in the Finished hash.
         */
    case TLMSP_MT_MIDDLEBOX_KEY_MATERIAL:
        if (mlen < 5)
            return 1; /* Invalid, not included.  */
        tid = ((const uint8_t *)m)[4];
        if (!TLMSP_MIDDLEBOX_ID_ENDPOINT(tid))
            return 1; /* Not included.  */
        return 0; /* Included.  */

    default:
        return 0; /* Included.  */
    }
}

/* Local functions.  */

static int
tlmsp_finish_append_Lcontrib(SSL *s, struct tlmsp_finish_state *fin, TLMSP_MiddleboxInstance *tmis)
{
    struct tlmsp_buffer Lcontrib;
    const void *d;
    size_t dlen;

    tlmsp_buffer_init(&Lcontrib);

    if (!tlmsp_finish_construct_Lcontrib(s, tmis, &Lcontrib)) {
        tlmsp_buffer_clear(&Lcontrib);
        return 0;
    }

    d = tlmsp_buffer_data(&Lcontrib, &dlen);
    if (d == NULL) {
        tlmsp_buffer_clear(&Lcontrib);
        return 0;
    }

    if (!tlmsp_finish_append_bytes(s, fin, d, dlen)) {
        tlmsp_buffer_clear(&Lcontrib);
        return 0;
    }

    tlmsp_buffer_clear(&Lcontrib);

    return 1;
}

static int
tlmsp_finish_append_bytes(SSL *s, struct tlmsp_finish_state *fin, const void *m, size_t mlen)
{
    if (!tlmsp_buffer_append(&fin->buf, m, mlen))
        return 0;
    return 1;
}

static int
tlmsp_finish_construct_Lcontrib(SSL *s, TLMSP_MiddleboxInstance *tmis, struct tlmsp_buffer *b)
{
    size_t keylen;
    unsigned j;

    keylen = tlmsp_key_size(s);

    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        const struct tlmsp_context_instance_state *tcis;
        const struct tlmsp_context_contributions *tccs, *cx, *sx;

        tcis = &s->tlmsp.context_states[j];
        if (!tcis->state.present)
            continue;
        tccs = tcis->key_block.contributions;
        cx = &tccs[TLMSP_CONTRIBUTION_CLIENT];
        sx = &tccs[TLMSP_CONTRIBUTION_SERVER];
        if (j == 0) {
            if (!tlmsp_buffer_append(b, cx->synch, keylen) ||
                !tlmsp_buffer_append(b, sx->synch, keylen))
                return 0;
        }
        if (tlmsp_context_access(s, j, TLMSP_CONTEXT_AUTH_READ, tmis)) {
            if (!tlmsp_buffer_append(b, cx->reader, keylen) ||
                !tlmsp_buffer_append(b, sx->reader, keylen))
                return 0;
        }
        if (tlmsp_context_access(s, j, TLMSP_CONTEXT_AUTH_WRITE, tmis)) {
            if (!tlmsp_buffer_append(b, cx->writer, keylen) ||
                !tlmsp_buffer_append(b, sx->writer, keylen))
                return 0;
        }
    }

    return 1;
}

static int
tlmsp_finish_generate(SSL *s, TLMSP_MiddleboxInstance *tmis, const char *verify_label, void *verify_data, size_t verify_datalen)
{
    uint8_t hash[EVP_MAX_MD_SIZE];
    unsigned int hashlen;
    const EVP_MD *md;
    const void *t;
    size_t tlen;

    if (TLMSP_IS_MIDDLEBOX(s))
        t = tlmsp_buffer_data(&s->tlmsp.middlebox_finish_state.buf, &tlen);
    else
        t = tlmsp_buffer_data(&tmis->finish_state.buf, &tlen);
    if (t == NULL)
        return 0;

    md = ssl_handshake_md(s);
    if (md == NULL)
        return 0;

    if (!EVP_Digest(t, tlen, hash, &hashlen, md, NULL))
        return 0;

    if (!tlmsp_prf_init(s, verify_label) ||
        !tlmsp_prf_update(s, hash, hashlen) ||
        !tlmsp_prf_finish(s, tmis->master_secret, sizeof tmis->master_secret, verify_data, verify_datalen))
        return 0;

    return 1;
}

static const char *
tlmsp_finish_verify_label(const TLMSP_MiddleboxInstance *src, const TLMSP_MiddleboxInstance *dst)
{
    switch (src->state.id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        if (TLMSP_MIDDLEBOX_ID_ENDPOINT(dst->state.id))
            return NULL;
        return TLMSP_FINISH_LABEL_CTOM;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        if (TLMSP_MIDDLEBOX_ID_ENDPOINT(dst->state.id))
            return NULL;
        return TLMSP_FINISH_LABEL_STOM;
    default:
        switch (dst->state.id) {
        case TLMSP_MIDDLEBOX_ID_CLIENT:
            return TLMSP_FINISH_LABEL_MTOC;
        case TLMSP_MIDDLEBOX_ID_SERVER:
            return TLMSP_FINISH_LABEL_MTOS;
        default:
            return NULL;
        }
    }
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
