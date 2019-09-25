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

static int tlmsp_read_container(SSL *, int, const void *, size_t, TLMSP_Container **, size_t *);
static int tlmsp_write_container(SSL *, WPACKET *, TLMSP_Container *);

static int tlmsp_read_m_info(SSL *, PACKET *, TLMSP_Container *);
static int tlmsp_write_m_info(SSL *, WPACKET *, const TLMSP_Container *);

static int tlmsp_read_fragment(SSL *, PACKET *, TLMSP_Container *);
static int tlmsp_write_fragment(SSL *, WPACKET *, TLMSP_Container *);

static int tlmsp_read_writer_mac(SSL *, PACKET *, TLMSP_Container *);
static int tlmsp_write_writer_mac(SSL *, WPACKET *, TLMSP_Container *);

static int tlmsp_read_forwarding_macs(SSL *, PACKET *, TLMSP_Container *);
static int tlmsp_read_forwarding_mac(SSL *, PACKET *, TLMSP_Container *, struct tlmsp_forwarding_mac *);
static int tlmsp_write_forwarding_macs(SSL *, WPACKET *, TLMSP_Container *);
static int tlmsp_write_forwarding_mac(SSL *, WPACKET *, const TLMSP_Container *, const struct tlmsp_forwarding_mac *);

static int tlmsp_verify_forwarding_check_mac(SSL *, const TLMSP_Container *, const struct tlmsp_forwarding_mac *);
static int tlmsp_verify_forwarding_reader_mac(SSL *, const TLMSP_Container *, const struct tlmsp_forwarding_mac *);
static int tlmsp_verify_reader_mac(SSL *, TLMSP_Container *, struct tlmsp_data *);

static int tlmsp_container_enc(SSL *, struct tlmsp_data *, const TLMSP_Container *);
static int tlmsp_container_mac(SSL *, const TLMSP_Container *, enum tlmsp_mac_kind, const void *, const void *, size_t, void *);

static int tlmsp_container_check_mac(SSL *, const TLMSP_Container *, const void *, const void *, const struct tlmsp_forwarding_mac *, void *);
static int tlmsp_container_forwarding_mac(SSL *, const TLMSP_Container *, const struct tlmsp_forwarding_mac *, struct tlmsp_forwarding_mac *);
static int tlmsp_container_reader_check_mac(SSL *, const TLMSP_Container *, tlmsp_middlebox_id_t, const void *, void *);

static const void *tlmsp_mac_input(SSL *, const TLMSP_Container *, tlmsp_middlebox_id_t, const void *, size_t, size_t *);

static int tlmsp_container_create(SSL *, TLMSP_Container **, int, tlmsp_context_id_t);
static int tlmsp_container_set_plaintext(TLMSP_Container *, const void *, size_t);

static tlmsp_middlebox_id_t tlmsp_container_origin(SSL *, const TLMSP_Container *);

static const struct tlmsp_forwarding_mac *tlmsp_container_forwarding_mac_by_order(SSL *, const TLMSP_Container *, int);
static const struct tlmsp_forwarding_mac *tlmsp_container_forwarding_mac_high_order(SSL *, const TLMSP_Container *);

int
TLMSP_container_read(SSL *s, TLMSP_Container **cp)
{
    size_t avail, csize;
    TLMSP_Container *c;
    int type;
    int rv;

    /*
     * Boilerplate checks for read path.
     */
    if (s->handshake_func == NULL) {
        SSLerr(SSL_F_TLMSP_CONTAINER_READ, SSL_R_UNINITIALIZED);
        return -1;
    }

    if (s->shutdown & SSL_RECEIVED_SHUTDOWN) {
        s->rwstate = SSL_NOTHING;
        return 0;
    }

    if (s->early_data_state == SSL_EARLY_DATA_CONNECT_RETRY
                || s->early_data_state == SSL_EARLY_DATA_ACCEPT_RETRY) {
        SSLerr(SSL_F_TLMSP_CONTAINER_READ, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    /*
     * If we are a client and haven't received the ServerHello etc then we
     * better do that
     */
    ossl_statem_check_finish_init(s, 0);

    clear_sys_error();
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s, 0);

    /*
     * Now actually consider doing the read.
     */

    avail = s->tlmsp.container_read_length - s->tlmsp.container_read_offset;
    if (avail == 0) {
        s->tlmsp.container_read_length = 0;
        s->tlmsp.container_read_offset = 0;
        rv = ssl3_read_bytes(s, SSL3_RT_APPLICATION_DATA, &type,
                             (void *)s->tlmsp.container_read_buffer,
                             sizeof s->tlmsp.container_read_buffer, 0,
                             &s->tlmsp.container_read_length);
        if (rv == 0)
            return 0;
        if (rv < 0)
            return rv;
        /* This is how we indicate a zero-length read?  */
        if (s->tlmsp.container_read_length == 0) {
            *cp = NULL;
            return 1;
        }
        avail = s->tlmsp.container_read_length;
    } else {
        /*
         * We cannot end up with buffered alerts, so in the case where we are
         * working with buffered data, we can only have application data.  Even
         * this probably doesn't happen since we have to read the whole
         * container and containers can't be split across records.
         */
        type = SSL3_RT_APPLICATION_DATA;
    }

    rv = tlmsp_read_container(s, type, s->tlmsp.container_read_buffer + s->tlmsp.container_read_offset, avail, &c, &csize);
    if (rv != 1)
        return -1;
    s->tlmsp.container_read_offset += csize;

    /*
     * On endpoints, alert delivery is automatic.
     *
     * We then proceed to doing the next read after an alert.
     */
    if (!TLMSP_IS_MIDDLEBOX(s) && c->type == SSL3_RT_ALERT) {
        if (TLMSP_container_alert(c, NULL) == -1) {
            SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_CONTAINER_READ,
                     SSL_R_INVALID_ALERT);
            return -1;
        }
        if (!tlmsp_container_deliver_alert(s, c)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_READ,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }
        return TLMSP_container_read(s, cp);
    }

    *cp = c;

    return 1;
}

int
TLMSP_container_write(SSL *s, TLMSP_Container *c)
{
    size_t written, blen;
    WPACKET pkt;
    int reflect;
    int rv;

    /*
     * Boilerplate checks for write path.
     */
    if (s->handshake_func == NULL) {
        SSLerr(SSL_F_TLMSP_CONTAINER_WRITE, SSL_R_UNINITIALIZED);
        return 0;
    }

    if (c->type != SSL3_RT_ALERT && s->shutdown & SSL_SENT_SHUTDOWN) {
        s->rwstate = SSL_NOTHING;
        SSLerr(SSL_F_TLMSP_CONTAINER_WRITE, SSL_R_PROTOCOL_IS_SHUTDOWN);
        return 0;
    }

    if (s->early_data_state == SSL_EARLY_DATA_CONNECT_RETRY
        || s->early_data_state == SSL_EARLY_DATA_ACCEPT_RETRY
        || s->early_data_state == SSL_EARLY_DATA_READ_RETRY) {
        SSLerr(SSL_F_TLMSP_CONTAINER_WRITE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    /* If we are a client and haven't sent the Finished we better do that */
    ossl_statem_check_finish_init(s, 1);

    clear_sys_error();
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s, 0);

    /*
     * When writing early data on the server side we could be "in_init" in
     * between receiving the EoED and the CF - but we don't want to handle those
     * messages yet.
     */
    if (SSL_in_init(s) && !ossl_statem_get_in_handshake(s)
        && s->early_data_state != SSL_EARLY_DATA_UNAUTH_WRITING) {
        int i;

        i = s->handshake_func(s);
        /* SSLfatal() already called */
        if (i < 0)
            return i;
        if (i == 0) {
            return -1;
        }
    }

    /*
     * Now actually consider doing the write.
     */

    if (!tlmsp_context_present(s, c->envelope.cid))
        return 0;

    /*
     * Prepare metadata for a delete.
     *
     * Presently we send one delete container per delete.
     */
    if (c->envelope.status == TLMSP_CS_DELETED) {
        struct tlmsp_delete_indicator *tdi;
        tlmsp_middlebox_id_t source_ID;

        if (!TLMSP_IS_MIDDLEBOX(s)) {
            fprintf(stderr, "%s: endpoint attempted to delete a container.\n", __func__);
            return 0;
        }

        /*
         * If the source is identified as our peer, that actually means the
         * opposite peer, as we are now on the write half of the middlebox, but
         * it is the peer on the read half.
         */
        source_ID = tlmsp_container_origin(s, c);
        switch (source_ID) {
        case TLMSP_MIDDLEBOX_ID_CLIENT:
            source_ID = TLMSP_MIDDLEBOX_ID_SERVER;
            break;
        case TLMSP_MIDDLEBOX_ID_SERVER:
            source_ID = TLMSP_MIDDLEBOX_ID_CLIENT;
            break;
        }

        /*
         * Set up M_INFO.
         */
        c->mInfo.m_id = TLMSP_MIDDLEBOX_ID_NONE;
        c->flags |= TLMSP_CONTAINER_FLAG_DELETED;
        c->audit_flags |= TLMSP_CONTAINER_FM_FLAG_DELETED;

        /*
         * Reset the forwarding MAC state.
         */
        TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, c->envelope.cid, s);
        c->nAF = 0;

        /*
         * Add a delete indicator.
         */
        if (c->mInfo.n != 0)
            return 0;
        tdi = &c->mInfo.delete_indicators[c->mInfo.n++];
        tdi->source_ID = source_ID;
        tdi->delete_count = 1;
    }

    if (!WPACKET_init_static_len(&pkt, s->tlmsp.write_packet_buffer, TLMSP_MAX_RECORD_PAYLOAD, 0))
        return 0;

    /*
     * We may send a container which was created early, before this connection
     * was established and we knew what our role was.  This is probably not
     * good practice generally, but it can happen.  In that case, we should
     * reinitialize the envelope.
     */
    if (c->envelope.src == TLMSP_MIDDLEBOX_ID_NONE) {
        TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, c->envelope.cid, s);
    }

    /*
     * Having an invalid source, destination, or context identifier is an
     * error.
     */
    if (c->envelope.src == TLMSP_MIDDLEBOX_ID_NONE ||
        c->envelope.dst == TLMSP_MIDDLEBOX_ID_NONE ||
        (c->type != SSL3_RT_ALERT &&
         c->envelope.cid == TLMSP_CONTEXT_CONTROL)) {
        return 0;
    }

    /*
     * If this container's envelope marks it to go in the opposite direction as
     * we're sending it, it must be a container we're simply reflecting
     * backwards, rather than forwarding.
     */
    reflect = 0;
    switch (tlmsp_envelope_direction(s, &c->envelope)) {
    case TLMSP_D_CTOS:
        if (TLMSP_MIDDLEBOX_ID_PEER(s) == TLMSP_MIDDLEBOX_ID_CLIENT) {
            reflect = 1;
            break;
        }
        break;
    case TLMSP_D_STOC:
        if (TLMSP_MIDDLEBOX_ID_PEER(s) == TLMSP_MIDDLEBOX_ID_SERVER) {
            reflect = 1;
            break;
        }
        break;
    }
    /*
     * If we are reflecting, we need to reestablish the envelope, reset the
     * audit log, and reset flags/M_INFO state.
     */
    if (reflect) {
        TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, c->envelope.cid, s);
        c->nAF = 0;
        c->flags &= ~(TLMSP_CONTAINER_FLAG_INSERTED | TLMSP_CONTAINER_FLAG_DELETED);
        c->audit_flags = 0;
        c->mInfo.m_id = TLMSP_MIDDLEBOX_ID_NONE;
        c->mInfo.n = 0;
    }

    /*
     * If we are not forwarding, we need write access to this context, unless
     * this is an alert in which case we only require read access to this
     * context.
     */
    if (!TLMSP_ENVELOPE_FORWARDING(&c->envelope)) {
        switch (c->type) {
        case SSL3_RT_APPLICATION_DATA:
            if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_WRITE, s->tlmsp.self)) {
                fprintf(stderr, "%s: attempted to write to context without write access.\n", __func__);
                return 0;
            }
            break;
        case SSL3_RT_ALERT:
            if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_READ, s->tlmsp.self)) {
                fprintf(stderr, "%s: attempted to write alert to context without read access.\n", __func__);
                return 0;
            }
            break;
        default:
            return 0;
        }
    }

    /*
     * Update sequence number.
     */
    if (!tlmsp_sequence_transmit(s, 0))
        return 0;
    if ((c->flags & TLMSP_CONTAINER_FLAG_DELETED) != 0) {
        const struct tlmsp_delete_indicator *tdi;
        size_t delete_count;
        unsigned i;

        delete_count = 0;
        for (i = 0; i < c->mInfo.n; i++) {
            tdi = &c->mInfo.delete_indicators[i];
            delete_count += tdi->delete_count;
        }
        if (!tlmsp_sequence_transmit(s, delete_count))
            return 0;
    }

    if (!tlmsp_write_container(s, &pkt, c)) {
        WPACKET_cleanup(&pkt);
        return 0;
    }

    if (!WPACKET_finish(&pkt)) {
        WPACKET_cleanup(&pkt);
        return 0;
    }

    if (!WPACKET_get_total_written(&pkt, &blen))
        return 0;

    rv = ssl3_write_bytes(s, c->type,
                          (const void *)s->tlmsp.write_packet_buffer, blen,
                          &written);
    if (rv != 1)
        return rv;

    if (written != blen)
        return 0;

    TLMSP_container_free(s, c);

    return 1;
}

int
TLMSP_container_delete(SSL *s, TLMSP_Container *c)
{
    if (c->type == SSL3_RT_ALERT)
        return 0;
    if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_WRITE, s->tlmsp.self))
        return 0;
    if (TLMSP_container_deleted(c))
        return 1;
    c->envelope.status = TLMSP_CS_DELETED;

    /*
     * Strip out plaintext and ciphertext.
     *
     * A middlebox may add back data if it wants.
     */
    if (!tlmsp_container_set_plaintext(c, NULL, 0))
        return 0;
    c->ciphertextlen = 0;

    return 1;
}

int
TLMSP_container_verify(SSL *s, const TLMSP_Container *c)
{
    /*
     * XXX
     *
     * Depending on the keys we have available, and our role, verify the
     * various MACs.
     *
     * This already happens on receive.  What would we want to do in addition?
     */
    return 0;
}

int
TLMSP_container_create(SSL *s, TLMSP_Container **cp, tlmsp_context_id_t cid, const void *d, size_t dlen)
{
    TLMSP_Container *c;

    if (cid == TLMSP_CONTEXT_CONTROL)
        return 0;

    if (!tlmsp_container_create(s, &c, SSL3_RT_APPLICATION_DATA, cid))
        return 0;

    if (!tlmsp_container_set_plaintext(c, d, dlen)) {
        TLMSP_container_free(s, c);
        return 0;
    }

    *cp = c;

    return 1;
}

int
TLMSP_container_create_alert(SSL *s, TLMSP_Container **cp, tlmsp_context_id_t cid, int alert)
{
    int alert_level, alert_desc;
    uint8_t alert_data[2];
    TLMSP_Container *c;

    if (alert < 0)
        return 0;

    alert_desc = SSL_alert_description(alert);
    alert_level = SSL_alert_level(alert);
    if (SSL_alert_value(alert_level, alert_desc) != alert)
        return 0;

    switch (alert_level) {
    case SSL3_AL_WARNING:
    case SSL3_AL_FATAL:
        break;
    default:
        return 0;
    }

    if (!tlmsp_container_create(s, &c, SSL3_RT_ALERT, cid))
        return 0;

    alert_data[0] = alert_level;
    alert_data[1] = alert_desc;

    if (!tlmsp_container_set_plaintext(c, alert_data, sizeof alert_data)) {
        TLMSP_container_free(s, c);
        return 0;
    }

    *cp = c;

    return 1;
}

void
TLMSP_container_free(SSL *s, TLMSP_Container *c)
{
    if (c == NULL)
        return;
    OPENSSL_clear_free(c, sizeof *c);
}

tlmsp_context_id_t
TLMSP_container_context(const TLMSP_Container *c)
{
    if (c == NULL)
        return 0;
    return c->envelope.cid;
}

size_t
TLMSP_container_length(const TLMSP_Container *c)
{
    if (c == NULL)
        return 0;
    if (c->envelope.status == TLMSP_CS_RECEIVED_NO_ACCESS)
        return 0;
    return c->plaintextlen;
}

int
TLMSP_container_alert(const TLMSP_Container *c, int *alertp)
{
    const uint8_t *alert_data;

    if (c->type != SSL3_RT_ALERT)
        return 0;
    if (c->plaintextlen != 2)
        return -1;
    alert_data = c->plaintext;
    if (alert_data == NULL)
        return -1;
    switch (alert_data[0]) {
    case SSL3_AL_WARNING:
    case SSL3_AL_FATAL:
        break;
    default:
        return -1;
    }
    if (alertp != NULL)
        *alertp = (alert_data[0] << 8) | alert_data[1];
    return 1;
}

int
TLMSP_container_deleted(const TLMSP_Container *c)
{
    if (c == NULL)
        return 0;
    if (c->envelope.status == TLMSP_CS_DELETED)
        return 1;
    if ((c->flags & TLMSP_CONTAINER_FLAG_DELETED) != 0)
        return 1;
    return 0;
}

int
TLMSP_container_readable(const TLMSP_Container *c)
{
    if (c == NULL)
        return 0;
    switch (c->envelope.status) {
    case TLMSP_CS_RECEIVED_NO_ACCESS:
        return 0;
    case TLMSP_CS_SENDING:
    case TLMSP_CS_RECEIVED_READONLY:
    case TLMSP_CS_RECEIVED_PRISTINE:
    case TLMSP_CS_RECEIVED_MODIFIED:
    case TLMSP_CS_DELETED:
        return 1;
    }

    /* Unreachable */
    return 0;
}

int
TLMSP_container_writable(const TLMSP_Container *c)
{
    if (c == NULL)
        return 0;

    if (c->type == SSL3_RT_ALERT)
        return 0;

    switch (c->envelope.status) {
    case TLMSP_CS_RECEIVED_NO_ACCESS:
    case TLMSP_CS_RECEIVED_READONLY:
    case TLMSP_CS_DELETED:
        return 0;
    case TLMSP_CS_SENDING:
    case TLMSP_CS_RECEIVED_PRISTINE:
    case TLMSP_CS_RECEIVED_MODIFIED:
        return 1;
    }

    /* Unreachable */
    return 0;
}

const void *
TLMSP_container_get_data(const TLMSP_Container *c)
{
    if (c == NULL || c->plaintextlen == 0)
        return NULL;
    if (c->envelope.status == TLMSP_CS_RECEIVED_NO_ACCESS)
        return NULL;
    return c->plaintext;
}

int
TLMSP_container_set_data(TLMSP_Container *c, const void *d, size_t dlen)
{
    if (c == NULL)
        return 0;

    if (c->type == SSL3_RT_ALERT)
        return 0;

    switch (c->envelope.status) {
    case TLMSP_CS_RECEIVED_NO_ACCESS:
    case TLMSP_CS_RECEIVED_READONLY:
        return 0;
    case TLMSP_CS_RECEIVED_PRISTINE:
        c->envelope.status = TLMSP_CS_RECEIVED_MODIFIED;
        break;
    case TLMSP_CS_SENDING:
    case TLMSP_CS_RECEIVED_MODIFIED:
    case TLMSP_CS_DELETED:
        break;
    }

    return tlmsp_container_set_plaintext(c, d, dlen);
}

static int
tlmsp_read_container(SSL *s, int type, const void *d, size_t dsize, TLMSP_Container **cp, size_t *csizep)
{
    tlmsp_context_audit_t audit;
    unsigned contextId, flags;
    TLMSP_Container *c;
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, d, dsize) ||
        !PACKET_get_1(&pkt, &contextId) ||
        !PACKET_get_net_2(&pkt, &flags)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Check that flags match the audit setting.
     */
    if (!tlmsp_context_audit(s, contextId, &audit)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    switch (audit) {
    case TLMSP_CONTEXT_AUDIT_UNCONFIRMED:
        if ((flags & TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS) != 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        break;
    case TLMSP_CONTEXT_AUDIT_CONFIRMED:
        if ((flags & TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS) == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    switch (type) {
    case SSL3_RT_APPLICATION_DATA:
        if (contextId == TLMSP_CONTEXT_CONTROL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        break;
    case SSL3_RT_ALERT:
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!tlmsp_container_create(s, &c, type, contextId)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    c->flags = flags;

    /*
     * We are reading this container, we need to adjust the envelope to show
     * the source and destination; reinitialize it accordingly.
     */
    TLMSP_ENVELOPE_INIT_SSL_READ(&c->envelope, contextId, s);

    if (!tlmsp_read_m_info(s, &pkt, c) ||
        !tlmsp_read_fragment(s, &pkt, c) ||
        !tlmsp_read_writer_mac(s, &pkt, c) ||
        !tlmsp_read_forwarding_macs(s, &pkt, c)) {
        TLMSP_container_free(s, c);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_CONTAINER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_READ, s->tlmsp.self)) {
        /*
         * We do not have read access, this is just an opaque container we can
         * forward.
         */
        c->envelope.status = TLMSP_CS_RECEIVED_NO_ACCESS;
    } else if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_WRITE, s->tlmsp.self)) {
        /*
         * We do not have write access; we can see the decrypted data, but we
         * must forward it and cannot delete or modify it.
         */
        c->envelope.status = TLMSP_CS_RECEIVED_READONLY;
    } else {
        /*
         * We have write access, but presently the packet is in its original,
         * unmodified form, and can be forwarded unless written to.
         */
        c->envelope.status = TLMSP_CS_RECEIVED_PRISTINE;
    }

    *cp = c;
    *csizep = dsize - PACKET_remaining(&pkt);

    return 1;
}

static int
tlmsp_write_container(SSL *s, WPACKET *pkt, TLMSP_Container *c)
{
    if (!WPACKET_put_bytes_u8(pkt, c->envelope.cid) ||
        !WPACKET_put_bytes_u16(pkt, c->flags) ||
        !tlmsp_write_m_info(s, pkt, c) ||
        !tlmsp_write_fragment(s, pkt, c) ||
        !tlmsp_write_writer_mac(s, pkt, c) ||
        !tlmsp_write_forwarding_macs(s, pkt, c))
        return 0;

    return 1;
}

static int
tlmsp_read_m_info(SSL *s, PACKET *pkt, TLMSP_Container *c)
{
    const TLMSP_MiddleboxInstance *tmis;
    struct tlmsp_delete_indicator *tdi;
    unsigned int id, n;
    unsigned i;

    if (!TLMSP_CONTAINER_HAVE_M_INFO(c))
        return 1;

    if (!PACKET_get_1(pkt, &id) ||
        !PACKET_get_1(pkt, &n)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_M_INFO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (id == s->tlmsp.self->state.id) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_M_INFO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_M_INFO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    c->mInfo.m_id = id;
    c->mInfo.n = n;

    for (i = 0; i < n; i++) {
        unsigned int source_ID, delete_count;

        if (!PACKET_get_1(pkt, &source_ID) ||
            !PACKET_get_net_2(pkt, &delete_count)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_M_INFO,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * XXX
         * We could also validate that source_ID is upstream of the originator,
         * and that the originator is upstream of us.  The spec does not
         * mention this, but it could be done to prevent middleboxes issuing
         * deletes for originators that are downstream of them erroneously.
         */
        if (source_ID == s->tlmsp.self->state.id) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_M_INFO,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        tmis = tlmsp_middlebox_lookup(s, source_ID);
        if (tmis == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_M_INFO,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        tdi = &c->mInfo.delete_indicators[i];
        tdi->source_ID = source_ID;
        tdi->delete_count = delete_count;
    }

    return 1;
}

static int
tlmsp_write_m_info(SSL *s, WPACKET *pkt, const TLMSP_Container *c)
{
    const struct tlmsp_delete_indicator *tdi;
    unsigned int id;
    unsigned i;

    if (!TLMSP_CONTAINER_HAVE_M_INFO(c))
        return 1;

    id = c->mInfo.m_id;
    if (id == TLMSP_MIDDLEBOX_ID_NONE)
        id = s->tlmsp.self->state.id;

    if (!WPACKET_put_bytes_u8(pkt, id) ||
        !WPACKET_put_bytes_u8(pkt, c->mInfo.n))
        return 0;

    for (i = 0; i < c->mInfo.n; i++) {
        tdi = &c->mInfo.delete_indicators[i];
        if (!WPACKET_put_bytes_u8(pkt, tdi->source_ID) ||
            !WPACKET_put_bytes_u16(pkt, tdi->delete_count))
            return 0;
    }

    return 1;
}

static int
tlmsp_read_fragment(SSL *s, PACKET *pkt, TLMSP_Container *c)
{
    struct tlmsp_data td;
    size_t mac_size;
    PACKET fragment;

    /* Get relevant security parameters.  */
    mac_size = tlmsp_reader_mac_size(s, &c->envelope);

    if (!PACKET_get_length_prefixed_2(pkt, &fragment)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Store off a copy of the complete ciphertext.
     */
    c->ciphertextlen = PACKET_remaining(&fragment);
    if (c->ciphertextlen != 0) {
        if (c->ciphertextlen > sizeof c->ciphertext) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memcpy(c->ciphertext, PACKET_data(&fragment), c->ciphertextlen);
    }

    /*
     * Update sequence numbers.
     */
    if (!tlmsp_sequence_receive(s, tlmsp_container_origin(s, c), 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if ((c->flags & TLMSP_CONTAINER_FLAG_DELETED) != 0) {
        const struct tlmsp_delete_indicator *tdi;
        unsigned i;

        for (i = 0; i < c->mInfo.n; i++) {
            tdi = &c->mInfo.delete_indicators[i];
            if (!tlmsp_sequence_receive(s, tdi->source_ID, tdi->delete_count)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }

    /*
     * If we don't have read access, we can't decrypt or check the reader MAC.
     */
    if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_READ, s->tlmsp.self)) {
        return 1;
    }

    /*
     * Set up buffer structure.
     */
    td.data = (void *)PACKET_data(&fragment);
    td.length = PACKET_remaining(&fragment);

    /*
     * Check the reader MAC appended to the fragment.
     */
    if (SSL_WRITE_ETM(s) && mac_size != 0) {
        if (!tlmsp_verify_reader_mac(s, c, &td))
            return 0;
    }

    /*
     * Do the actual cipher operation.
     */
    if (tlmsp_container_enc(s, &td, c) < 1) {
        if (!ossl_statem_in_error(s)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
        }
        return 0;
    }

    /*
     * Check the reader MAC appended to the fragment.
     */
    if (!SSL_WRITE_ETM(s) && mac_size != 0) {
        if (!tlmsp_verify_reader_mac(s, c, &td))
            return 0;
    }

    /*
     * Set the plaintext.
     *
     * This will also error out if the size is excessive.
     */
    if (!tlmsp_container_set_plaintext(c, td.data, td.length)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_write_fragment(SSL *s, WPACKET *pkt, TLMSP_Container *c)
{
    struct tlmsp_data td;
    size_t eivlen, mac_size;
    size_t dsize;
    uint8_t *scratch, *d;
    const void *nonce;

    /* Get relevant security parameters.  */
    mac_size = tlmsp_reader_mac_size(s, &c->envelope);
    eivlen = tlmsp_eiv_size(s, &c->envelope);

    /*
     * Ensure that the container type is a valid one.
     */
    switch (c->type) {
    case SSL3_RT_APPLICATION_DATA:
    case SSL3_RT_ALERT:
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If we are just forwarding, append our copy of the ciphertext verbatim.
     */
    if (TLMSP_ENVELOPE_FORWARDING(&c->envelope)) {
        if (!WPACKET_sub_memcpy_u16(pkt, c->ciphertext, c->ciphertextlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        return 1;
    }

    /*
     * Calculate the most scratch space we might need.
     */
    dsize = TLMSP_MAX_CONTAINER_FRAGMENT_SCRATCH;
    if (!WPACKET_sub_reserve_bytes_u16(pkt, dsize, &scratch)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Set up buffers to be able to work in place.
     */
    if (c->plaintextlen != 0)
        memcpy(scratch + eivlen, c->plaintext, c->plaintextlen);
    td.data = scratch;
    td.length = eivlen + c->plaintextlen;

    /*
     * Populate the explicit IV/nonce from M_ID || random.
     *
     * XXX
     * We need better nonce management throughout, because the random approach,
     * although valid, has birthday paradox issues compared to a mix of random
     * and incrementing counter.
     */
    if (eivlen != 0 && !tlmsp_generate_nonce(s, s->tlmsp.self, scratch, eivlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    nonce = scratch;

    /*
     * Append the MAC of the fragment to the input to the cipher.
     */
    if (!SSL_WRITE_ETM(s) && mac_size != 0) {
        if (!tlmsp_container_mac(s, c, TLMSP_MAC_READER, nonce, td.data, td.length, scratch + td.length)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        td.length += mac_size;
    }

    /*
     * Do the actual cipher operation.
     */
    if (tlmsp_container_enc(s, &td, c) < 1) {
        if (!ossl_statem_in_error(s)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
        }
        return 0;
    }

    /*
     * Append the MAC of the fragment to the output of the cipher.
     */
    if (SSL_WRITE_ETM(s) && mac_size != 0) {
        if (!tlmsp_container_mac(s, c, TLMSP_MAC_READER, nonce, td.data, td.length, scratch + td.length)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        td.length += mac_size;
    }

    /*
     * If this exceeds the maximum size set out in the spec, error.
     */
    if (td.length > TLMSP_CONTAINER_MAX_SIZE) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Store off a copy of the complete ciphertext.
     */
    c->ciphertextlen = td.length;
    if (c->ciphertextlen != 0) {
        memcpy(c->ciphertext, td.data, c->ciphertextlen);
    }

    /*
     * Account for the data in our scratch buffer as part of the packet.
     */
    if (!WPACKET_sub_allocate_bytes_u16(pkt, td.length, &d) || d != scratch) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_read_writer_mac(SSL *s, PACKET *pkt, TLMSP_Container *c)
{
    TLMSP_MiddleboxInstance *tmis;
    uint8_t mac[EVP_MAX_MD_SIZE];
    tlmsp_middlebox_id_t id;
    const void *nonce;
    size_t amacsize;
    size_t eivlen;

    eivlen = tlmsp_eiv_size(s, &c->envelope);
    amacsize = tlmsp_additional_mac_size(s, &c->envelope);

    if (eivlen == 0 || amacsize == 0) {
        /*
         * We allow only alert containers to prior to the establishment of a
         * cipher.
         */
        if (c->type == SSL3_RT_ALERT)
            return 1;
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_copy_bytes(pkt, c->writer_mac, amacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_WRITE, s->tlmsp.self)) {
        return 1;
    }

    nonce = c->ciphertext;

    /*
     * Determine the generating entity from the nonce / explicit IV.
     */
    memcpy(&id, nonce, sizeof id);

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If this is an alert and the writer only had read access to the context,
     * just ignore the dummy writer MAC.
     */
    if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_WRITE, tmis)) {
        if (c->type != SSL3_RT_ALERT) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_READ, tmis)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        return 1;
    }

    /*
     * Generate the expected writer MAC and check it.
     */
    if (!tlmsp_container_mac(s, c, TLMSP_MAC_WRITER, nonce, c->ciphertext, c->ciphertextlen, mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (CRYPTO_memcmp(mac, c->writer_mac, amacsize) != 0) {
        TLMSPfatal(s, TLMSP_AD_BAD_WRITER_MAC, c->envelope.cid,
                   SSL_F_TLMSP_READ_WRITER_MAC,
                   SSL_R_TLMSP_ALERT_BAD_WRITER_MAC);
        return 0;
    }

    return 1;
}

static int
tlmsp_write_writer_mac(SSL *s, WPACKET *pkt, TLMSP_Container *c)
{
    const void *nonce;
    size_t amacsize;

    amacsize = tlmsp_additional_mac_size(s, &c->envelope);
    if (amacsize == 0) {
        /*
         * We allow only alert containers to prior to the establishment of a
         * cipher.
         */
        if (c->type == SSL3_RT_ALERT)
            return 1;
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!TLMSP_ENVELOPE_FORWARDING(&c->envelope)) {
        nonce = c->ciphertext;

        /*
         * If we are generating the writer MAC on an alert to a context we only
         * have read access to, we place a dummy writer MAC instead.
         */
        if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_WRITE, s->tlmsp.self)) {
            if (c->type != SSL3_RT_ALERT) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_WRITER_MAC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            if (!tlmsp_context_access(s, c->envelope.cid, TLMSP_CONTEXT_AUTH_READ, s->tlmsp.self)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_WRITER_MAC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            memset(c->writer_mac, 0x00, amacsize);
        } else {
            if (!tlmsp_container_mac(s, c, TLMSP_MAC_WRITER, nonce, c->ciphertext, c->ciphertextlen, c->writer_mac)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_WRITER_MAC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }

    if (!WPACKET_memcpy(pkt, c->writer_mac, amacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_read_forwarding_macs(SSL *s, PACKET *pkt, TLMSP_Container *c)
{
    const struct tlmsp_forwarding_mac *fm, *highafm;
    const TLMSP_MiddleboxInstance *tmis;
    struct tlmsp_forwarding_mac *afm;
    unsigned int nAF;
    uint8_t order;
    unsigned i;

    if (c->type == SSL3_RT_ALERT) {
        size_t fmacsize;

        fmacsize = tlmsp_additional_mac_size(s, &c->envelope);
        if (fmacsize == 0) {
            /*
             * We allow alert containers to be generated when no MACs are
             * enabled.  Simply return.
             */
            return 1;
        }
    }

    if (!tlmsp_read_forwarding_mac(s, pkt, c, &c->forwarding_mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * We must always be able to verify the first, mandatory forwarding MAC, as
     * if a modification occurs, it will be rewritten, and if no modification
     * occurs, it is left intact.
     */
    if (!tlmsp_verify_forwarding_reader_mac(s, c, &c->forwarding_mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If there are no additional forwarding MACs, we only need to concern
     * ourselves with the first one.  If we are an endpoint, we can also verify
     * the check MAC as well as the reader check MAC.
     */
    if ((c->flags & TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS) == 0) {
        if (!TLMSP_IS_MIDDLEBOX(s)) {
            if (!tlmsp_verify_forwarding_check_mac(s, c, &c->forwarding_mac)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
        return 1;
    }

    /*
     * Process any additional forwarding MACs present.
     */
    if (!PACKET_get_1(pkt, &nAF)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    c->nAF = nAF;
    for (i = 0; i < c->nAF; i++) {
        afm = &c->additional_forwarding_macs[i];
        if (!tlmsp_read_forwarding_mac(s, pkt, c, afm)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * Now we are able to also verify the MAC from the last forwarder.  If the
     * previous middlebox to us modified the container, we will find that the
     * mandatory forwarding MAC is the highest forwarding MAC.
     *
     * It is possible, further, to verify every reader check MAC back to the
     * last middlebox which modified the data.
     */
    highafm = tlmsp_container_forwarding_mac_high_order(s, c);
    if (highafm != &c->forwarding_mac) {
        /*
         * We can verify the MAC provided by a previous forwarder.
         */
        if (!tlmsp_verify_forwarding_reader_mac(s, c, highafm)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * If we are a middlebox, our work is done.
     */
    if (TLMSP_IS_MIDDLEBOX(s))
        return 1;

    /*
     * An endpoint has additional work to do to verify the contents and integrity
     * of the forwarding MAC audit log.  There may be additional checks that are
     * possible over and above what is done here.
     *
     * First, we verify the check MACs, which are used to verify the integrity
     * of a forwarding MAC's contents from the entity that generates it to the
     * endpoint that receives it.
     *
     * We start by verifying the first, mandatory forwarding MAC's check MAC.
     * This must always be verifiable.  It corresponds to the last entity to
     * modify the container
     */
    if (!tlmsp_verify_forwarding_check_mac(s, c, &c->forwarding_mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Verify the check MAC of every entry in the audit log.
     */
    for (i = 0; i < c->nAF; i++) {
        afm = &c->additional_forwarding_macs[i];
        if (!tlmsp_verify_forwarding_check_mac(s, c, afm)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * Second, we verify that the order of the audit information is acceptable,
     * specifically:
     *
     * 1. We identify the middlebox with the first audit entry (order = 0.)
     * 2. We then look up that middlebox (or endpoint.)
     * 3. We proceed to the next middlebox in network topological order, and
     *    check that it provided an audit entry with order = 1.
     * 4. We continue, incrementing the order and iterating through
     *    middleboxes.
     * 5. Finally, we check that the highest order value does equal the point
     *    at which we stopped.
     */
    order = 0;
    fm = tlmsp_container_forwarding_mac_by_order(s, c, order);
    if (fm == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    tmis = tlmsp_middlebox_lookup(s, fm->id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    while ((tmis = tlmsp_middlebox_next_direction(s, tmis, tlmsp_envelope_direction(s, &c->envelope))) != NULL) {
        order++;
        fm = tlmsp_container_forwarding_mac_by_order(s, c, order);
        if (fm == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (tmis->state.id != fm->id) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    highafm = tlmsp_container_forwarding_mac_high_order(s, c);
    if (highafm->order != order) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Third, we make sure there are no duplicate audit orders, and that each
     * order that is present appears only once.
     *
     * Since we've already ensured the proper order by order above, the easiest
     * thing to do is just check that the highest order value equals nAF, since
     * that is what a contiguous series of orders would yield.
     */
    if (c->nAF != order) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_read_forwarding_mac(SSL *s, PACKET *pkt, TLMSP_Container *c, struct tlmsp_forwarding_mac *fm)
{
    unsigned id, order, flags;
    size_t eivlen;
    size_t fmacsize;

    eivlen = tlmsp_eiv_size(s, &c->envelope);
    fmacsize = tlmsp_additional_mac_size(s, &c->envelope);

    if (fmacsize == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_1(pkt, &id) ||
        !PACKET_get_1(pkt, &order) ||
        !PACKET_get_1(pkt, &flags)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    fm->id = id;
    fm->order = order;
    fm->flags = flags;

    if (!PACKET_copy_bytes(pkt, fm->outboundReaderCheckMAC, fmacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (tlmsp_want_aad(s, &c->envelope)) {
        if (!PACKET_copy_bytes(pkt, fm->nonce, eivlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!PACKET_copy_bytes(pkt, fm->checkMAC, fmacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_write_forwarding_macs(SSL *s, WPACKET *pkt, TLMSP_Container *c)
{
    const struct tlmsp_forwarding_mac *highafm;
    struct tlmsp_forwarding_mac *afm;
    unsigned i;

    if (c->type == SSL3_RT_ALERT) {
        size_t fmacsize;

        fmacsize = tlmsp_additional_mac_size(s, &c->envelope);
        if (fmacsize == 0) {
            /*
             * We allow alert containers to be generated when no MACs are
             * enabled.  Simply return.
             */
            return 1;
        }
    }

    /*
     * Add our forwarding MAC if appropriate.
     *
     * If we are just forwarding, we add an additional forwarding MAC.
     *
     * If we modified the container, we move the existing forwarding MAC to the
     * additional forwarding MACs and replace the first forwarding MAC.
     */
    if ((c->flags & TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS) != 0) {
        if (c->envelope.status != TLMSP_CS_SENDING) {
            highafm = tlmsp_container_forwarding_mac_high_order(s, c);
        } else {
            /*
             * There should not be any forwarding MACs on things we originate.
             */
            if (c->nAF != 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            highafm = NULL;
        }

        if (TLMSP_ENVELOPE_FORWARDING(&c->envelope)) {
            if (c->nAF == TLMSP_CONTAINER_MAX_AF) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            afm = &c->additional_forwarding_macs[c->nAF++];

            if (!tlmsp_container_forwarding_mac(s, c, highafm, afm)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        } else {
            if (c->envelope.status != TLMSP_CS_SENDING) {
                /*
                 * Move the received first forwarding MAC to the additional
                 * forwarding MACs.
                 */
                if (c->nAF == TLMSP_CONTAINER_MAX_AF) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                afm = &c->additional_forwarding_macs[c->nAF++];
                *afm = c->forwarding_mac;
                if (highafm == &c->forwarding_mac)
                    highafm = afm;
            }

            if (!tlmsp_container_forwarding_mac(s, c, highafm, &c->forwarding_mac)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    } else {
        /*
         * We are not keeping additional forwarding MACs, so we leave the
         * mandatory forwarding MAC intact if we are forwarding, and otherwise
         * we recalculate it.
         */
        if (!tlmsp_container_forwarding_mac(s, c, NULL, &c->forwarding_mac)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * Now write the mandatory forwarding MAC.
     */
    if (!tlmsp_write_forwarding_mac(s, pkt, c, &c->forwarding_mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((c->flags & TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS) == 0)
        return 1;

    /*
     * Now write out all forwarding MACs.
     */
    if (!WPACKET_put_bytes_u8(pkt, c->nAF)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    for (i = 0; i < c->nAF; i++) {
        afm = &c->additional_forwarding_macs[i];
        if (!tlmsp_write_forwarding_mac(s, pkt, c, afm)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

static int
tlmsp_write_forwarding_mac(SSL *s, WPACKET *pkt, const TLMSP_Container *c, const struct tlmsp_forwarding_mac *fm)
{
    size_t eivlen;
    size_t fmacsize;
    int want_aad;

    eivlen = tlmsp_eiv_size(s, &c->envelope);
    fmacsize = tlmsp_additional_mac_size(s, &c->envelope);
    want_aad = tlmsp_want_aad(s, &c->envelope);

    if (fmacsize == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(pkt, fm->id) ||
        !WPACKET_put_bytes_u8(pkt, fm->order) ||
        !WPACKET_put_bytes_u8(pkt, fm->flags)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_memcpy(pkt, fm->outboundReaderCheckMAC, fmacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (want_aad) {
        if (!WPACKET_memcpy(pkt, fm->nonce, eivlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!WPACKET_memcpy(pkt, fm->checkMAC, fmacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_verify_forwarding_check_mac(SSL *s, const TLMSP_Container *c, const struct tlmsp_forwarding_mac *fm)
{
    const struct tlmsp_forwarding_mac *ifm;
    uint8_t mac[EVP_MAX_MD_SIZE];
    const void *inbound_reader_check_mac;
    const void *nonce;
    size_t fmacsize;

    fmacsize = tlmsp_additional_mac_size(s, &c->envelope);
    if (fmacsize == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_FORWARDING_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (tlmsp_want_aad(s, &c->envelope)) {
        nonce = fm->nonce;
    } else {
        nonce = NULL;
    }

    if (fm->order != 0) {
        ifm = tlmsp_container_forwarding_mac_by_order(s, c, fm->order - 1);
        if (ifm == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_FORWARDING_CHECK_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        inbound_reader_check_mac = ifm->outboundReaderCheckMAC;
    } else {
        inbound_reader_check_mac = NULL;
    }
    if (!tlmsp_container_check_mac(s, c, nonce, inbound_reader_check_mac, fm, mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_FORWARDING_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (CRYPTO_memcmp(mac, fm->checkMAC, fmacsize) != 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_FORWARDING_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_verify_forwarding_reader_mac(SSL *s, const TLMSP_Container *c, const struct tlmsp_forwarding_mac *fm)
{
    uint8_t mac[EVP_MAX_MD_SIZE];
    const void *nonce;
    size_t fmacsize;

    fmacsize = tlmsp_additional_mac_size(s, &c->envelope);
    if (fmacsize == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_FORWARDING_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (tlmsp_want_aad(s, &c->envelope)) {
        nonce = fm->nonce;
    } else {
        nonce = NULL;
    }

    if (!tlmsp_container_reader_check_mac(s, c, fm->id, nonce, mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_FORWARDING_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (CRYPTO_memcmp(mac, fm->outboundReaderCheckMAC, fmacsize) != 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_FORWARDING_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_verify_reader_mac(SSL *s, TLMSP_Container *c, struct tlmsp_data *td)
{
    uint8_t md[EVP_MAX_MD_SIZE];
    const uint8_t *mac;
    size_t mac_size;
    const void *nonce;

    mac_size = tlmsp_reader_mac_size(s, &c->envelope);

    if (mac_size == 0 || mac_size > sizeof md) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (td->length < mac_size) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    td->length -= mac_size;
    mac = td->data + td->length;
    nonce = td->data;

    if (!tlmsp_container_mac(s, c, TLMSP_MAC_READER, nonce, td->data, td->length, md)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_VERIFY_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (CRYPTO_memcmp(md, mac, mac_size) != 0) {
        TLMSPfatal(s, TLMSP_AD_BAD_READER_MAC, c->envelope.cid,
                   SSL_F_TLMSP_VERIFY_READER_MAC,
                   SSL_R_TLMSP_ALERT_BAD_READER_MAC);
        return 0;
    }

    return 1;
}

static int
tlmsp_container_enc(SSL *s, struct tlmsp_data *td, const TLMSP_Container *c)
{
    tlmsp_middlebox_id_t id;
    const void *aad;
    size_t aadlen;
    size_t fraglen;
    size_t eivlen;
    size_t taglen;

    if (tlmsp_want_aad(s, &c->envelope)) {
        eivlen = tlmsp_eiv_size(s, &c->envelope);
        taglen = tlmsp_tag_size(s, &c->envelope);

        /*
         * Compute the length of the plaintext.
         */
        fraglen = td->length - eivlen;
        if (!TLMSP_ENVELOPE_SENDING(&c->envelope)) {
            /*
             * In this case we are strictly receiving.  The write path has
             * already handled forwarding pristine packets, we know that if
             * we're sending, it's a total rewrite.  This check applies only on
             * the receive and verify path, as to ensure that the input isn't
             * somehow too short to include data as well as a tag.
             */
            if (fraglen < taglen) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            fraglen -= taglen;

            /*
             * Determine the sender from the nonce / explicit IV.
             */
            if (eivlen == 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            id = td->data[0];
        } else {
            id = s->tlmsp.self->state.id;
        }

        aad = tlmsp_mac_input(s, c, id, NULL, fraglen, &aadlen);
        if (aad == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        aad = NULL;
        aadlen = 0;
    }

    return tlmsp_enc(s, &c->envelope, TLMSP_ENC_CONTAINER, td, aad, aadlen);
}

/*
 * This gets called to generate either the reader MAC or any of the additional
 * MACs.  In the first case, we are called only if we are not using AEAD.  In
 * the other cases, we do GMAC if we are using AEAD.
 *
 * The output size is either the size of the tag for an additional MAC with
 * AEAD in GMAC mode, or the size of the reader MAC for all MACs in non-AEAD
 * modes.
 */
static int
tlmsp_container_mac(SSL *s, const TLMSP_Container *c, enum tlmsp_mac_kind kind, const void *nonce, const void *frag, size_t fraglen, void *macp)
{
    TLMSP_MiddleboxInstance *tmis;
    tlmsp_middlebox_id_t id;
    const void *mac_input;
    size_t mac_inputlen;
    size_t eivlen;

    eivlen = tlmsp_eiv_size(s, &c->envelope);

    /*
     * Determine the generating entity from the nonce / explicit IV.
     */
    if (eivlen == 0 || nonce == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    memcpy(&id, nonce, sizeof id);

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    mac_input = tlmsp_mac_input(s, c, tmis->state.id, frag, fraglen, &mac_inputlen);
    if (mac_input == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_mac(s, &c->envelope, kind, nonce, mac_input, mac_inputlen, macp)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_container_check_mac(SSL *s, const TLMSP_Container *c, const void *nonce, const void *inbound_reader_check_mac, const struct tlmsp_forwarding_mac *fm, void *macp)
{
    struct tlmsp_envelope cme;
    size_t check_mac_inputlen;
    size_t fmacsize;
    WPACKET pkt;

    fmacsize = tlmsp_additional_mac_size(s, &c->envelope);
    if (fmacsize == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Generate the input for checkMAC.
     */
    if (!WPACKET_init_static_len(&pkt, s->tlmsp.check_mac_input_buffer, sizeof s->tlmsp.check_mac_input_buffer, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(&pkt, c->type) ||
        !WPACKET_put_bytes_u16(&pkt, TLMSP_TLS_VERSION(s->version)) ||
        !WPACKET_put_bytes_u32(&pkt, s->tlmsp.sid)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_sequence_entity(s, fm->id, &pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u16(&pkt, c->flags) ||
        !tlmsp_write_m_info(s, &pkt, c)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * This corresponds with the "length" field of the checkMAC input, which
     * covers the final fields of the input, as below.
     */
    if (!WPACKET_start_sub_packet_u8(&pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(&pkt, fm->id) ||
        !WPACKET_put_bytes_u8(&pkt, fm->order) ||
        !WPACKET_put_bytes_u8(&pkt, fm->flags)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (inbound_reader_check_mac != NULL) {
        if (!WPACKET_memcpy(&pkt, inbound_reader_check_mac, fmacsize)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!WPACKET_memcpy(&pkt, fm->outboundReaderCheckMAC, fmacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * This is the end of the data covered by the "length" field.
     */
    if (!WPACKET_close(&pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_get_total_written(&pkt, &check_mac_inputlen) ||
        !WPACKET_finish(&pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Synthesize a checkMAC envelope based on the direction the container is
     * moving overall.  For a client-to-server container, the checkMAC is from
     * the forwarding MAC generator to the server, and from the generator to
     * the client for server-to-client containers.
     *
     * XXX
     * We also need to indicate whether we are sending or receiving, in theory.
     */
    cme = c->envelope;
    switch (tlmsp_envelope_direction(s, &cme)) {
    case TLMSP_D_CTOS:
        cme.src = fm->id;
        cme.dst = TLMSP_MIDDLEBOX_ID_SERVER;
        break;
    case TLMSP_D_STOC:
        cme.src = fm->id;
        cme.dst = TLMSP_MIDDLEBOX_ID_CLIENT;
        break;
    }

    /*
     * Generate the final checkMAC.
     */
    if (!tlmsp_mac(s, &cme, TLMSP_MAC_CHECK, nonce, s->tlmsp.check_mac_input_buffer, check_mac_inputlen, macp)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_container_forwarding_mac(SSL *s, const TLMSP_Container *c, const struct tlmsp_forwarding_mac *ifm, struct tlmsp_forwarding_mac *ofm)
{
    const void *inbound_reader_check_mac;
    const void *nonce;
    size_t eivlen;

    if (ifm == ofm) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (tlmsp_want_aad(s, &c->envelope)) {
        eivlen = tlmsp_eiv_size(s, &c->envelope);

        /*
         * Generate a nonce for AEAD modes.
         */
        if (!tlmsp_generate_nonce(s, s->tlmsp.self, ofm->nonce, eivlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        nonce = ofm->nonce;
    } else {
        nonce = NULL;
    }

    ofm->id = s->tlmsp.self->state.id;
    if (ifm != NULL) {
        if (ifm->order == TLMSP_CONTAINER_ORDER_RESERVED) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        ofm->order = ifm->order + 1;
        if (ofm->order == TLMSP_CONTAINER_ORDER_RESERVED) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        ofm->order = 0;
    }
    ofm->flags = c->audit_flags;

    if (!tlmsp_container_reader_check_mac(s, c, ofm->id, nonce, ofm->outboundReaderCheckMAC)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (ifm != NULL) {
        inbound_reader_check_mac = ifm->outboundReaderCheckMAC;
    } else {
        inbound_reader_check_mac = NULL;
    }
    if (!tlmsp_container_check_mac(s, c, nonce, inbound_reader_check_mac, ofm, ofm->checkMAC)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_container_reader_check_mac(SSL *s, const TLMSP_Container *c, tlmsp_middlebox_id_t id, const void *nonce, void *macp)
{
    uint8_t hash[EVP_MAX_MD_SIZE];
    size_t hashlen;
    const void *mac_input;
    size_t mac_inputlen;

    mac_input = tlmsp_mac_input(s, c, id, c->ciphertext, c->ciphertextlen, &mac_inputlen);
    if (mac_input == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_READER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_hash(s, mac_input, mac_inputlen, hash, &hashlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_READER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_mac(s, &c->envelope, TLMSP_MAC_READER_CHECK, nonce, hash, hashlen, macp)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_READER_CHECK_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static const void *
tlmsp_mac_input(SSL *s, const TLMSP_Container *c, tlmsp_middlebox_id_t id, const void *frag, size_t fraglen, size_t *lenp)
{
    WPACKET pkt;
    void *buf;
    size_t bufsize;
    int want_aad;
    int want_data;

    want_aad = tlmsp_want_aad(s, &c->envelope);
    want_data = frag != NULL && fraglen != 0;

    if (!want_data && !want_aad) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                 ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if (want_aad && !want_data) {
        buf = s->tlmsp.aad_buffer;
        bufsize = sizeof s->tlmsp.aad_buffer;
    } else {
        buf = s->tlmsp.mac_input_buffer;
        bufsize = sizeof s->tlmsp.mac_input_buffer;
    }

    if (!WPACKET_init_static_len(&pkt, buf, bufsize, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                 ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if (!WPACKET_put_bytes_u8(&pkt, c->type) ||
        !WPACKET_put_bytes_u16(&pkt, TLMSP_TLS_VERSION(s->version)) ||
        !WPACKET_put_bytes_u32(&pkt, s->tlmsp.sid)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                 ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if (!tlmsp_sequence_entity(s, id, &pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                 ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if (!WPACKET_put_bytes_u16(&pkt, c->flags) ||
        !tlmsp_write_m_info(s, &pkt, c) ||
        !WPACKET_put_bytes_u16(&pkt, fraglen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                 ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if (want_data) {
        if (!WPACKET_memcpy(&pkt, frag, fraglen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                     ERR_R_INTERNAL_ERROR);
            return NULL;
        }
    }

    if (!WPACKET_get_total_written(&pkt, lenp) ||
        !WPACKET_finish(&pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                 ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    return buf;
}

static int
tlmsp_container_create(SSL *s, TLMSP_Container **cp, int type, tlmsp_context_id_t cid)
{
    tlmsp_context_audit_t audit;
    TLMSP_Container *c;

    if (s == NULL || cp == NULL)
        return 0;

    if (!tlmsp_context_present(s, cid))
        return 0;

    c = OPENSSL_zalloc(sizeof *c);
    if (c == NULL)
        return 0;

    c->type = type;
    TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, cid, s);
    c->flags = TLMSP_CONTAINER_FLAGS_DEFAULT;
    c->audit_flags = 0;

    /*
     * We set up flags assuming we are creating a container to write to this
     * context.  If we are reading, the read routines will remove/replace
     * anything they need to from the wire.
     */

    /*
     * Set audit-related flags.
     */
    if (!tlmsp_context_audit(s, c->envelope.cid, &audit))
        return 0;
    switch (audit) {
    case TLMSP_CONTEXT_AUDIT_UNCONFIRMED:
        break;
    case TLMSP_CONTEXT_AUDIT_CONFIRMED:
        c->flags |= TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS;
        break;
    default:
        return 0;
    }

    /*
     * If we are a middlebox, set the inserted bit and set up M_INFO to be
     * filled out at write time.
     */
    if (TLMSP_IS_MIDDLEBOX(s)) {
        c->mInfo.m_id = TLMSP_MIDDLEBOX_ID_NONE;
        c->mInfo.n = 0;
        c->flags |= TLMSP_CONTAINER_FLAG_INSERTED;
        c->audit_flags |= TLMSP_CONTAINER_FM_FLAG_INSERTED;
    }

    *cp = c;

    return 1;
}

static int
tlmsp_container_set_plaintext(TLMSP_Container *c, const void *d, size_t dlen)
{
    if (c == NULL || dlen > sizeof c->plaintext)
        return 0;

    /*
     * Alert containers must bear 2 bytes of data.
     */
    if (c->type == SSL3_RT_ALERT && dlen != 2)
        return 0;

    if (dlen == 0) {
        c->plaintextlen = 0;
    } else {
        /*
         * We use memmove to allow for overlapping data, in case someone is
         * using set_data with get_data in combination to do something like
         * remove some bytes from the start or end.  We also don't do the
         * memmove if d is equal to c->plaintext, which would be a simple
         * truncate.
         *
         * If we move to using buffers on the heap, we must be careful not to
         * free the old one until we have done memmove.
         */
        if (c->plaintext != d)
            memmove(c->plaintext, d, dlen);
        c->plaintextlen = dlen;
    }
    return 1;

}

/*
 * Unless M_INFO is present, the origin of a container is the peer.  If there
 * is M_INFO, e.g. for an insert, then it carries information about the
 * ultimate origin of the container in the face of any modifications.
 */
static tlmsp_middlebox_id_t
tlmsp_container_origin(SSL *s, const TLMSP_Container *c)
{
    if (!TLMSP_CONTAINER_HAVE_M_INFO(c))
        return TLMSP_MIDDLEBOX_ID_PEER(s);
    if (c->mInfo.m_id != TLMSP_MIDDLEBOX_ID_NONE)
        return c->mInfo.m_id;
    return s->tlmsp.self->state.id;
}

static const struct tlmsp_forwarding_mac *
tlmsp_container_forwarding_mac_by_order(SSL *s, const TLMSP_Container *c, int match)
{
    const struct tlmsp_forwarding_mac *fm;
    unsigned i;

    if (match == TLMSP_CONTAINER_ORDER_RESERVED)
        return NULL;

    fm = &c->forwarding_mac;
    if (fm->order == match)
        return fm;

    if ((c->flags & TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS) == 0)
        return NULL;

    for (i = 0; i < c->nAF; i++) {
        fm = &c->additional_forwarding_macs[i];
        if (fm->order == match)
            return fm;
    }

    return NULL;
}

static const struct tlmsp_forwarding_mac *
tlmsp_container_forwarding_mac_high_order(SSL *s, const TLMSP_Container *c)
{
    const struct tlmsp_forwarding_mac *fm, *highfm;
    unsigned i;

    fm = &c->forwarding_mac;
    if ((c->flags & TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS) == 0)
        return fm;

    highfm = fm;
    for (i = 0; i < c->nAF; i++) {
        fm = &c->additional_forwarding_macs[i];
        if (fm->order <= highfm->order)
            continue;
        highfm = fm;
    }

    return highfm;
}

int
tlmsp_container_deliver_alert(SSL *s, TLMSP_Container *c)
{
    uint8_t alert_data[2];
    int alert;

    if (TLMSP_IS_MIDDLEBOX(s))
        return 0;
    if (c->type != SSL3_RT_ALERT)
        return 0;

    if (TLMSP_container_alert(c, &alert) != 1) {
        SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_CONTAINER_DELIVER_ALERT,
                 SSL_R_INVALID_ALERT);
        return 0;
    }

    alert_data[0] = SSL_alert_level(alert);
    alert_data[1] = SSL_alert_description(alert);

    if (!tlmsp_process_alert(s, c->envelope.cid, alert_data, sizeof alert_data)) {
        SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_CONTAINER_DELIVER_ALERT,
                 SSL_R_INVALID_ALERT);
        return 0;
    }

    return 1;
}

int
tlmsp_container_parse(SSL *s, TLMSP_Container **cp, int type, const uint8_t *d, size_t dlen)
{
    TLMSP_Container *c;
    size_t csize;
    int rv;

    rv = tlmsp_read_container(s, type, d, dlen, &c, &csize);
    if (rv != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_PARSE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (csize != dlen) {
        TLMSP_container_free(s, c);
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_CONTAINER_PARSE,
                 SSL_R_BAD_LENGTH);
        return 0;
    }

    *cp = c;

    return 1;
}

enum tlmsp_direction
tlmsp_envelope_direction(const SSL *s, const struct tlmsp_envelope *env)
{
    if (env->src == TLMSP_MIDDLEBOX_ID_CLIENT ||
        env->dst == TLMSP_MIDDLEBOX_ID_SERVER)
        return TLMSP_D_CTOS;
    if (env->src == TLMSP_MIDDLEBOX_ID_SERVER ||
        env->dst == TLMSP_MIDDLEBOX_ID_CLIENT)
        return TLMSP_D_STOC;
    /*
     * We do not at present support middlebox-to-middlebox messages.
     */
    abort();
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
