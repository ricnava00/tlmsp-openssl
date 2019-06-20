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

/*
 * XXX
 * We need to manage the sequence number increments.
 *
 * XXX
 * Put full middlebox MAC processing constuct in place.
 */

/*
 * XXX
 * Needs lots of errors added.
 */

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

static int tlmsp_check_reader_mac(SSL *, TLMSP_Container *, struct tlmsp_buffer *);

static int tlmsp_container_enc(SSL *, struct tlmsp_buffer *, const TLMSP_Container *);
static int tlmsp_container_mac(SSL *, const TLMSP_Container *, enum tlmsp_mac_kind, const void *, const void *, size_t, void *);
static int tlmsp_container_forwarding_mac(SSL *, const TLMSP_Container *, const struct tlmsp_forwarding_mac *, struct tlmsp_forwarding_mac *);

static const void *tlmsp_mac_input(SSL *, const TLMSP_Container *, const void *, size_t, size_t *);

/*
 * XXX
 * Needs alert containers support
 *
 * XXX
 * Review for handling of all possible error conditions
 */
int
TLMSP_container_read(SSL *s, TLMSP_Container **cp)
{
    size_t avail, csize;
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
        rv = ssl3_read_bytes(s, SSL3_RT_APPLICATION_DATA, NULL,
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
    }

    rv = tlmsp_read_container(s, SSL3_RT_APPLICATION_DATA, s->tlmsp.container_read_buffer + s->tlmsp.container_read_offset, avail, cp, &csize);
    if (rv != 1)
        return -1;
    s->tlmsp.container_read_offset += csize;

    /*
     * XXX
     * For non- middlebox, we do verify here.
     */

    return 1;
}

int
TLMSP_container_write(SSL *s, TLMSP_Container *c)
{
    size_t written, blen;
    WPACKET pkt;
    int rv;

    /*
     * Boilerplate checks for write path.
     */
    if (s->handshake_func == NULL) {
        SSLerr(SSL_F_TLMSP_CONTAINER_WRITE, SSL_R_UNINITIALIZED);
        return 0;
    }

    if (s->shutdown & SSL_SENT_SHUTDOWN) {
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

    if (!tlmsp_context_present(s, c->contextId) ||
        !tlmsp_context_present(s, c->envelope.cid))
        return 0;

    /* XXX temporary */
    if (c->deleted) {
	TLMSP_container_free(s, c);
        return 1;
    }
    
    if (!WPACKET_init_static_len(&pkt, s->tlmsp.write_packet_buffer, TLMSP_MAX_RECORD_PAYLOAD, 0))
        return 0;

    /*
     * XXX
     * Review whether we need additional internal API points to drive
     * establishing final container state or automatically peforming it here is
     * sufficient.
     */

    /*
     * We may send a container which was created early, before this connection
     * was established and we knew what our role was.  This is probably not
     * good practice generally, but it can happen.  In that case, we should
     * reinitialize the envelope.
     *
     * XXX
     * Should we error out in container create if we don't have our ID
     * established yet?
     */
    if (c->envelope.src == TLMSP_MIDDLEBOX_ID_NONE &&
        c->envelope.dst == TLMSP_MIDDLEBOX_ID_NONE) {
        TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, c->contextId, s);
    }

    /*
     * Having an invalid source, destination, or context identifier is an
     * error.
     */
    if (c->envelope.src == TLMSP_MIDDLEBOX_ID_NONE ||
        c->envelope.dst == TLMSP_MIDDLEBOX_ID_NONE ||
        c->envelope.cid == TLMSP_CONTEXT_CONTROL ||
        c->contextId == TLMSP_CONTEXT_CONTROL) {
        return 0;
    }

    /*
     * If this container's envelope marks it to go in the opposite direction as
     * we're sending it, it must be a container we're simply reflecting
     * backwards, rather than forwarding, so just reestablish its envelope.
     */
    switch (tlmsp_envelope_direction(s, &c->envelope)) {
    case TLMSP_D_CTOS:
        if (s->tlmsp.peer_id == TLMSP_MIDDLEBOX_ID_CLIENT) {
            TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, c->contextId, s);
            break;
        }
        break;
    case TLMSP_D_STOC:
        if (s->tlmsp.peer_id == TLMSP_MIDDLEBOX_ID_SERVER) {
            TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, c->contextId, s);
            break;
        }
        break;
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
    /* XXX Rewrite, queue.  */
    c->deleted = 1;
    return 1;
}

int
TLMSP_container_verify(SSL *s, const TLMSP_Container *c)
{
    /* XXX All the verify.  */
    /*
     * Depending on the keys we have available, and our role, verify the
     * various MACs.
     */
    return 0;
}

int
TLMSP_container_create(SSL *s, TLMSP_Container **cp, tlmsp_context_id_t cid, const void *d, size_t dlen)
{
    TLMSP_Container *c;

    if (s == NULL || cp == NULL)
        return 0;

    if (cid == TLMSP_CONTEXT_CONTROL || !tlmsp_context_present(s, cid))
        return 0;

    c = OPENSSL_zalloc(sizeof *c);
    if (c == NULL)
        return 0;

    c->type = SSL3_RT_APPLICATION_DATA;
    TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, cid, s);
    c->contextId = cid;
    c->flags = 0; /* XXX */

    if (!TLMSP_container_set_data(c, d, dlen)) {
        TLMSP_container_free(s, c);
        return 0;
    }

    *cp = c;

    return 1;
}

int
TLMSP_container_create_alert(SSL *s, TLMSP_Container **cp, tlmsp_context_id_t cid, int al, const void *d, size_t dlen)
{
    TLMSP_Container *c;

    if (s == NULL || cp == NULL)
        return 0;

    if (!tlmsp_context_present(s, cid))
        return 0;

    c = OPENSSL_zalloc(sizeof *c);

    c->type = SSL3_RT_ALERT;
    TLMSP_ENVELOPE_INIT_SSL_WRITE(&c->envelope, cid, s);
    c->contextId = cid;
    c->flags = 0; /* XXX */

    *cp = c;

    return 0;
}

void
TLMSP_container_free(SSL *s, TLMSP_Container *c)
{
    if (c == NULL)
        return;
    OPENSSL_free(c);
}

tlmsp_context_id_t
TLMSP_container_context(const TLMSP_Container *c)
{
    if (c == NULL)
        return 0;
    return c->contextId;
}

size_t
TLMSP_container_length(const TLMSP_Container *c)
{
    if (c == NULL)
        return 0;
    return c->plaintextlen;
}

const void *
TLMSP_container_get_data(const TLMSP_Container *c)
{
    if (c == NULL || c->plaintextlen == 0)
        return NULL;
    return c->plaintext;
}

int
TLMSP_container_set_data(TLMSP_Container *c, const void *d, size_t dlen)
{
    if (c == NULL || dlen > sizeof c->plaintext)
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
 * XXX
 * Use origin indication or state field in the container to determine if we
 * are originating it (and we know whether we're a middlebox) or whether
 * we're forwarding it, so that we can manage audit, etc.
 *
 * XXX
 * write_hash and FMs.
 */

static int
tlmsp_read_container(SSL *s, int type, const void *d, size_t dsize, TLMSP_Container **cp, size_t *csizep)
{
    unsigned contextId, flags;
    TLMSP_Container *c;
    PACKET pkt;

    if (!PACKET_buf_init(&pkt, d, dsize) ||
        !PACKET_get_1(&pkt, &contextId) ||
        !PACKET_get_net_2(&pkt, &flags))
        return 0;

    switch (type) {
    case SSL3_RT_APPLICATION_DATA:
        if (!TLMSP_container_create(s, &c, contextId, NULL, 0))
            return 0;
        break;
    case SSL3_RT_ALERT:
        if (!TLMSP_container_create_alert(s, &c, contextId, 128/*XXX ALERT */, NULL, 0))
            return 0;
        break;
    default:
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
        return 0;
    }

    *cp = c;
    *csizep = dsize - PACKET_remaining(&pkt);

    return 1;
}

static int
tlmsp_write_container(SSL *s, WPACKET *pkt, TLMSP_Container *c)
{
    if (!WPACKET_put_bytes_u8(pkt, c->contextId) ||
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
    return 1;
}

static int
tlmsp_write_m_info(SSL *s, WPACKET *pkt, const TLMSP_Container *c)
{
    return 1;
}

static int
tlmsp_read_fragment(SSL *s, PACKET *pkt, TLMSP_Container *c)
{
    struct tlmsp_buffer tb;
    size_t eivlen, mac_size;
    PACKET fragment;

    /* Get relevant security parameters.  */
    mac_size = tlmsp_reader_mac_size(s, &c->envelope);
    eivlen = tlmsp_eiv_size(s, &c->envelope);

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
     * Set up buffer structure.
     */
    tb.data = (void *)PACKET_data(&fragment);
    tb.length = PACKET_remaining(&fragment);

    /*
     * Check the reader MAC appended to the fragment.
     */
    if (SSL_WRITE_ETM(s) && mac_size != 0) {
        if (!tlmsp_check_reader_mac(s, c, &tb))
            return 0;
    }

    /*
     * Do the actual cipher operation.
     */
    if (tlmsp_container_enc(s, &tb, c) < 1) {
        fprintf(stderr, "%s: tlmsp_enc failed\n", __func__);
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
        if (!tlmsp_check_reader_mac(s, c, &tb))
            return 0;
    }

    /*
     * XXX
     * We need to do our own compression instead.
     */
#if 0
    if (s->compress != NULL) {
        /*
         * XXX
         * What if the data grows, does the packet reserve room for that or are
         * we meant to provide some other data pointer?  It seems like we must.
         */
        if (!ssl3_do_uncompress(s, rr)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
#endif

    /*
     * Set the plaintext.
     *
     * This will also error out if the size is excessive.
     */
    if (!TLMSP_container_set_data(c, tb.data, tb.length)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

/*
 * XXX
 * By this point an internal marker on the container will show whether we
 * are originating the container or forwarding.
 */
static int
tlmsp_write_fragment(SSL *s, WPACKET *pkt, TLMSP_Container *c)
{
    struct tlmsp_buffer tb;
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
     * Calculate the most scratch space we might need.
     */
    dsize = TLMSP_MAX_CONTAINER_FRAGMENT_SCRATCH;
    if (!WPACKET_sub_reserve_bytes_u16(pkt, dsize, &scratch)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * XXX
     * We need to do our own compression.
     */
#if 0
    if (s->compress != NULL && c->plaintextlen != 0) {
        if (!ssl3_do_compress(s, wr)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
#endif

    /*
     * Set up buffers to be able to work in place.
     */
    if (c->plaintextlen != 0)
        memcpy(scratch + eivlen, c->plaintext, c->plaintextlen);
    tb.data = scratch;
    tb.length = eivlen + c->plaintextlen;

    /*
     * Populate the explicit IV/nonce from M_ID || random.
     *
     * XXX
     * We need better nonce management throughout, because the random approach,
     * although valid, has birthday paradox issues compared to a mix of random
     * and incrementing counter.
     */
    if (!tlmsp_generate_nonce(s, s->tlmsp.self_id, scratch, eivlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    nonce = scratch;

    /*
     * Append the MAC of the fragment to the input to the cipher.
     */
    if (!SSL_WRITE_ETM(s) && mac_size != 0) {
        if (!tlmsp_container_mac(s, c, TLMSP_MAC_READER, nonce, tb.data, tb.length, scratch + tb.length)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        tb.length += mac_size;
    }

    /*
     * Do the actual cipher operation.
     */
    if (tlmsp_container_enc(s, &tb, c) < 1) {
        fprintf(stderr, "%s: tlmsp_enc failed\n", __func__);
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
        if (!tlmsp_container_mac(s, c, TLMSP_MAC_READER, nonce, tb.data, tb.length, scratch + tb.length)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        tb.length += mac_size;
    }

    /*
     * If this exceeds the maximum size set out in the spec, error.
     */
    if (tb.length > TLMSP_CONTAINER_MAX_SIZE) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Store off a copy of the complete ciphertext.
     */
    c->ciphertextlen = tb.length;
    if (c->ciphertextlen != 0) {
        memcpy(c->ciphertext, tb.data, c->ciphertextlen);
    }

    /*
     * Account for the data in our scratch buffer as part of the packet.
     */
    if (!WPACKET_sub_allocate_bytes_u16(pkt, tb.length, &d) || d != scratch) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FRAGMENT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

/*
 * XXX
 * When forwarding, we need to just populate/regurgitate the writer_mac in the
 * container.
 */
static int
tlmsp_read_writer_mac(SSL *s, PACKET *pkt, TLMSP_Container *c)
{
    uint8_t mac[EVP_MAX_MD_SIZE];
    const void *nonce;
    size_t amacsize;

    amacsize = tlmsp_additional_mac_size(s, &c->envelope);

    if (!PACKET_copy_bytes(pkt, c->writer_mac, amacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    nonce = c->ciphertext;

    if (!tlmsp_container_mac(s, c, TLMSP_MAC_WRITER, nonce, c->ciphertext, c->ciphertextlen, mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (CRYPTO_memcmp(mac, c->writer_mac, amacsize) != 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
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

    nonce = c->ciphertext;

    if (!tlmsp_container_mac(s, c, TLMSP_MAC_WRITER, nonce, c->ciphertext, c->ciphertextlen, c->writer_mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_WRITER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
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
    if (!tlmsp_read_forwarding_mac(s, pkt, c, &c->forwarding_mac)) {
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
    if (!tlmsp_container_forwarding_mac(s, c, NULL, &c->forwarding_mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_write_forwarding_mac(s, pkt, c, &c->forwarding_mac)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_WRITE_FORWARDING_MACS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
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
tlmsp_check_reader_mac(SSL *s, TLMSP_Container *c, struct tlmsp_buffer *tb)
{
    uint8_t md[EVP_MAX_MD_SIZE];
    const uint8_t *mac;
    size_t mac_size;
    const void *nonce;

    mac_size = tlmsp_reader_mac_size(s, &c->envelope);

    if (mac_size == 0 || mac_size > sizeof md) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CHECK_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (tb->length < mac_size) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CHECK_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    tb->length -= mac_size;
    mac = tb->data + tb->length;
    nonce = tb->data;

    if (!tlmsp_container_mac(s, c, TLMSP_MAC_READER, nonce, tb->data, tb->length, md)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CHECK_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (CRYPTO_memcmp(md, mac, mac_size) != 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CHECK_READER_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_container_enc(SSL *s, struct tlmsp_buffer *tb, const TLMSP_Container *c)
{
    const void *aad;
    size_t aadlen;
    size_t fraglen;
    size_t eivlen;
    size_t taglen;

    if (tlmsp_want_aad(s, &c->envelope)) {
        eivlen = tlmsp_eiv_size(s, &c->envelope);
        taglen = tlmsp_tag_size(s, &c->envelope);

        /*
         * Compute the length of the compressed plaintext.
         */
        fraglen = tb->length - eivlen;
        if (c->envelope.src != s->tlmsp.self_id) {
            /*
             * XXX TODO XXX
             * This code assumes that in this case we are receiving, and tries
             * to guess accordingly.  What if we're forwarding?
             */
            if (fraglen < taglen) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            fraglen -= taglen;
        }

        aad = tlmsp_mac_input(s, c, NULL, fraglen, &aadlen);
        if (aad == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        aad = NULL;
        aadlen = 0;
    }

    return tlmsp_enc(s, &c->envelope, TLMSP_ENC_CONTAINER, tb, aad, aadlen);
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
    const void *mac_input;
    size_t mac_inputlen;
    size_t amacsize;

    amacsize = tlmsp_additional_mac_size(s, &c->envelope);

    mac_input = tlmsp_mac_input(s, c, frag, fraglen, &mac_inputlen);
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
tlmsp_container_forwarding_mac(SSL *s, const TLMSP_Container *c, const struct tlmsp_forwarding_mac *ifm, struct tlmsp_forwarding_mac *ofm)
{
    uint8_t hash[EVP_MAX_MD_SIZE];
    const uint8_t *seq;
    WPACKET pkt;
    size_t hashlen;
    const void *mac_input;
    size_t mac_inputlen;
    const void *nonce;
    size_t check_mac_inputlen;
    size_t eivlen;
    size_t fmacsize;

    fmacsize = tlmsp_additional_mac_size(s, &c->envelope);
    if (fmacsize == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    mac_input = tlmsp_mac_input(s, c, c->ciphertext, c->ciphertextlen, &mac_inputlen);
    if (mac_input == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_hash(s, mac_input, mac_inputlen, hash, &hashlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (tlmsp_want_aad(s, &c->envelope)) {
        eivlen = tlmsp_eiv_size(s, &c->envelope);

        /*
         * Generate a nonce for AEAD modes.
         */
        if (!tlmsp_generate_nonce(s, s->tlmsp.self_id, ofm->nonce, eivlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        nonce = ofm->nonce;
    } else {
        nonce = NULL;
    }

    if (!tlmsp_mac(s, &c->envelope, TLMSP_MAC_OUTBOUND_READER_CHECK, nonce, hash, hashlen, ofm->outboundReaderCheckMAC)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ofm->id = s->tlmsp.self_id;
    ofm->order = 0;
    ofm->flags = 0;

    /*
     * Generate the input for checkMAC.
     */
    if (!WPACKET_init_static_len(&pkt, s->tlmsp.check_mac_input_buffer, sizeof s->tlmsp.check_mac_input_buffer, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(&pkt, c->type) ||
        !WPACKET_put_bytes_u16(&pkt, TLMSP_TLS_VERSION(s->version)) ||
        !WPACKET_put_bytes_u32(&pkt, s->tlmsp.sid)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    seq = RECORD_LAYER_get_write_sequence(&s->rlayer);

    if (!WPACKET_memcpy(&pkt, seq, 8)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(&pkt, c->flags) ||
        !tlmsp_write_m_info(s, &pkt, c) ||
        !WPACKET_put_bytes_u16(&pkt, c->ciphertextlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(&pkt, ofm->id) ||
        !WPACKET_put_bytes_u8(&pkt, ofm->order) ||
        !WPACKET_put_bytes_u8(&pkt, ofm->flags)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (ifm != NULL) {
        if (!WPACKET_memcpy(&pkt, ifm->outboundReaderCheckMAC, fmacsize)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!WPACKET_memcpy(&pkt, ofm->outboundReaderCheckMAC, fmacsize)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_get_total_written(&pkt, &check_mac_inputlen) ||
        !WPACKET_finish(&pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_mac(s, &c->envelope, TLMSP_MAC_CHECK, nonce, s->tlmsp.check_mac_input_buffer, check_mac_inputlen, ofm->checkMAC)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONTAINER_FORWARDING_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static const void *
tlmsp_mac_input(SSL *s, const TLMSP_Container *c, const void *frag, size_t fraglen, size_t *lenp)
{
    const uint8_t *seq;
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

    /*
     * XXX Abstract out sequence number management.
     */
    if (c->envelope.src == s->tlmsp.self_id)
        seq = RECORD_LAYER_get_write_sequence(&s->rlayer);
    else
        seq = RECORD_LAYER_get_read_sequence(&s->rlayer);

    if (!WPACKET_memcpy(&pkt, seq, 8)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC_INPUT,
                 ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    if (!WPACKET_put_bytes_u8(&pkt, c->flags) ||
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
