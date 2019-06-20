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
#include "tlmsp_msg.h"
#include <openssl/rand.h>
#include <openssl/tlmsp.h>

#pragma clang diagnostic error "-Wmissing-prototypes"

/*
 * XXX
 * Are we harmonizing things like context and middlebox state often enough and
 * completely enough?
 */

static int tlmsp_middlebox_handshake_broadcast(SSL *, int, int, const uint8_t *, size_t);
static int tlmsp_middlebox_handshake_forward(SSL *, int, int, const uint8_t *, size_t, int (*)(SSL *, int));
static int tlmsp_middlebox_process_change_cipher_spec(SSL *, PACKET *);
static int tlmsp_middlebox_post_write_change_cipher_spec(SSL *, int);
static int tlmsp_middlebox_process_client_hello(SSL *, PACKET *);
static int tlmsp_middlebox_post_write_client_hello(SSL *, int);
static int tlmsp_middlebox_process_server_hello(SSL *, PACKET *);
static int tlmsp_middlebox_post_write_server_hello(SSL *, int);
static int tlmsp_middlebox_post_write_server_done(SSL *, int);
static int tlmsp_middlebox_send_middlebox_hello(SSL *);
static int tlmsp_middlebox_send_middlebox_key_confirmation(SSL *);

static void TLMSP_MWQI_free(TLMSP_MWQI *);

/* API functions.  */

int
tlmsp_middlebox_handshake_flush(SSL *s)
{
    TLMSP_MWQIs *write_queue;
    OSSL_STATEM *st;
    SSL *write_ssl;
    size_t written;
    TLMSP_MWQI *w;
    int rv;

    st = &s->statem;

    write_queue = s->tlmsp.middlebox_write_queue;
    write_ssl = s->tlmsp.middlebox_other_ssl;

    if (write_queue == NULL ||
        sk_TLMSP_MWQI_num(write_queue) == 0) {
        /*
         * If we finished our handshake and are just waiting until we have
         * flushed our write queue to leave the init state, we're done now and
         * can finish.
         */
        if (SSL_in_init(s) && st->hand_state == TLS_ST_OK) {
            ossl_statem_set_in_init(s, 0);
        }
        return 1;
    }

    w = sk_TLMSP_MWQI_value(write_queue, 0);
    rv = ssl3_write_bytes(write_ssl, w->type,
                          (const void *)w->buffer, w->length, &written);
    if (rv != 1)
        return 0;
    if (written != w->length) {
        w->length -= written;
        memmove(w->buffer, w->buffer + written, w->length);
    } else {
        sk_TLMSP_MWQI_shift(write_queue);
        if (w->completion != NULL) {
            if (!w->completion(s, sk_TLMSP_MWQI_num(write_queue) == 0)) {
                TLMSP_MWQI_free(w);
                return 0;
            }
        }
        TLMSP_MWQI_free(w);
    }

    if (BIO_flush(write_ssl->wbio) <= 0)
        return 0;
    return tlmsp_middlebox_handshake_flush(s);
}

void
tlmsp_middlebox_handshake_free(SSL *s)
{
    if (s->tlmsp.middlebox_write_queue == NULL)
        return;
    sk_TLMSP_MWQI_pop_free(s->tlmsp.middlebox_write_queue, TLMSP_MWQI_free);
    s->tlmsp.middlebox_write_queue = NULL;
}

int
tlmsp_middlebox_handshake_process(SSL *s, int toserver)
{
    PACKET pkt;
    OSSL_STATEM *st;
    uint8_t *tail;
    size_t readbytes;
    size_t avail;
    int recvd_type;
    int rv;

    st = &s->statem;

    if (!SSL_in_init(s) || st->hand_state == TLS_ST_OK)
        return 1;

    if (SSL_in_before(s)) {
        if (SSL_IS_FIRST_HANDSHAKE(s)) {
            st->read_state_first_init = 1;
            if (s->session == NULL) {
                if (!ssl_get_new_session(s, 0)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                             ERR_R_INTERNAL_ERROR);
                    return -1;
                }
            }
        }
        st->hand_state = TLMSP_ST_MIDDLEBOX_HANDSHAKE;
    }

    if (st->read_state_first_init) {
        s->first_packet = 1;
        st->read_state_first_init = 0;
    }

    /*
     * Get the header for the next handshake message.
     */
    for (;;) {
        if (s->tlmsp.handshake_buffer_length >= SSL3_HM_HEADER_LENGTH)
            break;

        tail = &s->tlmsp.handshake_buffer[s->tlmsp.handshake_buffer_length];
        rv = ssl3_read_bytes(s, SSL3_RT_HANDSHAKE, &recvd_type, tail,
                             SSL3_HM_HEADER_LENGTH - s->tlmsp.handshake_buffer_length, 0, &readbytes);
        if (rv <= 0)
            return rv;

        switch (recvd_type) {
        case SSL3_RT_HANDSHAKE:
            break;
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            if (s->tlmsp.handshake_buffer_length != 0 || readbytes != 1) {
                SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                         SSL_R_BAD_CHANGE_CIPHER_SPEC);
                return -1;
            }
            if (!PACKET_buf_init(&pkt, s->tlmsp.handshake_buffer,
                                 s->tlmsp.handshake_buffer_length + readbytes))
                return 0;
            if (!tlmsp_middlebox_process_change_cipher_spec(s, &pkt))
                return -1;
            return 1;
        default:
            SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                     SSL_R_CCS_RECEIVED_EARLY);
            return -1;
        }

        s->tlmsp.handshake_buffer_length += readbytes;
    }

    /*
     * Now receive the entire body.
     */
    for (;;) {
        MSG_PROCESS_RETURN ret;
        size_t message_length;
        const uint8_t *msg;
        unsigned int mt;

        /* Decode header.  */
        if (!PACKET_buf_init(&pkt,
                             s->tlmsp.handshake_buffer,
                             s->tlmsp.handshake_buffer_length) ||
            !PACKET_get_1(&pkt, &mt) ||
            !PACKET_get_net_3_len(&pkt, &message_length))
            return 0;

        if (SSL3_HM_HEADER_LENGTH + message_length > sizeof s->tlmsp.handshake_buffer) {
            SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                     SSL_R_EXCESSIVE_MESSAGE_SIZE);
            return -1;
        }

        msg = PACKET_data(&pkt);
        avail = PACKET_remaining(&pkt);
        if (avail < message_length) {
            tail = &s->tlmsp.handshake_buffer[s->tlmsp.handshake_buffer_length];
            rv = ssl3_read_bytes(s, SSL3_RT_HANDSHAKE, NULL, tail,
                                 message_length - avail, 0, &readbytes);
            if (rv <= 0)
                return rv;
            s->tlmsp.handshake_buffer_length += readbytes;
            continue;
        }

        /*
         * XXX
         * Seems like at any point we reach this far, we can just as well clear
         * handshake_buffer_length, since we won't be processing the packet
         * again and have no more to read into it.
         */

        /*
         * Now we have a PACKET which has had the header decoded successfully,
         * and whose body is entirely available.
         */
        switch (mt) {
        case SSL3_MT_CLIENT_HELLO:
            if (!tlmsp_middlebox_process_client_hello(s, &pkt))
                return -1;
            break;
        case SSL3_MT_SERVER_HELLO:
            if (!tlmsp_middlebox_process_server_hello(s, &pkt))
                return -1;
            break;
        case SSL3_MT_SERVER_DONE:
            if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE, mt, msg, message_length, tlmsp_middlebox_post_write_server_done))
                return -1;
            s->tlmsp.handshake_buffer_length = 0;
            break;
        case TLMSP_MT_MIDDLEBOX_KEY_MATERIAL:
            ret = tlmsp_process_middlebox_key_material(s, &pkt);
            if (ret == MSG_PROCESS_ERROR)
                return -1;
            if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE, mt, msg, message_length, NULL))
                return -1;
            s->tlmsp.handshake_buffer_length = 0;
            if (ret == MSG_PROCESS_FINISHED_READING) {
                /*
                 * Time for us to send our MiddleboxKeyConfirmation.
                 */
                if (!tlmsp_middlebox_send_middlebox_key_confirmation(s))
                    return -1;
            }
            break;
        case TLMSP_MT_MIDDLEBOX_KEY_CONFIRMATION:
            ret = tlmsp_process_middlebox_key_confirmation(s, &pkt);
            if (ret == MSG_PROCESS_ERROR)
                return -1;
            if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE, mt, msg, message_length, NULL))
                return -1;
            s->tlmsp.handshake_buffer_length = 0;
            if (ret == MSG_PROCESS_FINISHED_READING) {
                /*
                 * Time for us to send our MiddleboxKeyConfirmation.
                 */
                if (!tlmsp_middlebox_send_middlebox_key_confirmation(s))
                    return -1;
            }
            break;
        case SSL3_MT_FINISHED:
            if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE, mt, msg, message_length, NULL))
                return -1;
            s->tlmsp.handshake_buffer_length = 0;
            st->hand_state = TLS_ST_OK;
            break;
        default:
            if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE, mt, msg, message_length, NULL))
                return -1;
            s->tlmsp.handshake_buffer_length = 0;
            break;
        }
        return 1;
    }
}

/* Local functions.  */

static int
tlmsp_middlebox_handshake_broadcast(SSL *s, int rt, int mt, const uint8_t *m, size_t len)
{
    SSL *other = s->tlmsp.middlebox_other_ssl;
    int rv[2];

    rv[0] = tlmsp_middlebox_handshake_forward(s, rt, mt, m, len, NULL);
    rv[1] = tlmsp_middlebox_handshake_forward(other, rt, mt, m, len, NULL);

    if (rv[0] != 1)
        return rv[0];
    if (rv[1] != 1)
        return rv[1];
    return 1;
}

static int
tlmsp_middlebox_handshake_forward(SSL *s, int rt, int mt, const uint8_t *m, size_t len, int (*completion)(SSL *, int))
{
    struct tlmsp_middlebox_write_queue_item *w;
    WPACKET pkt;

    if (s->tlmsp.middlebox_write_queue == NULL) {
        s->tlmsp.middlebox_write_queue = sk_TLMSP_MWQI_new_null();
        if (s->tlmsp.middlebox_write_queue == NULL)
            return 0;
    }

    w = OPENSSL_zalloc(sizeof *w);
    if (w == NULL)
        return 0;

    if (!WPACKET_init_static_len(&pkt, w->buffer, sizeof w->buffer, 0)) {
        TLMSP_MWQI_free(w);
        return 0;
    }

    w->type = rt;
    w->completion = completion;
    if (mt != SSL3_MT_DUMMY) {
        if (!WPACKET_put_bytes_u8(&pkt, mt) ||
            !WPACKET_sub_memcpy_u24(&pkt, m, len)) {
            TLMSP_MWQI_free(w);
            return 0;
        }
    } else if (len != 0) {
        if (!WPACKET_memcpy(&pkt, m, len))
            return 0;
    }

    if (!WPACKET_finish(&pkt) ||
        !WPACKET_get_total_written(&pkt, &w->length)) {
        TLMSP_MWQI_free(w);
        return 0;
    }

    if (!sk_TLMSP_MWQI_push(s->tlmsp.middlebox_write_queue, w)) {
        TLMSP_MWQI_free(w);
        return 0;
    }

    return 1;
}

static int
tlmsp_middlebox_process_change_cipher_spec(SSL *s, PACKET *pkt)
{
    unsigned int type;

    s->session->cipher = s->s3->tmp.new_cipher;
    if (!tlmsp_setup_key_block(s)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_change_cipher_state(s, SSL3_CC_READ)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (PACKET_remaining(pkt) != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_peek_1(pkt, &type)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (type != 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Queue this to be forwarded.
     */
    if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_CHANGE_CIPHER_SPEC,
                                           SSL3_MT_DUMMY, PACKET_data(pkt),
                                           PACKET_remaining(pkt),
                                           tlmsp_middlebox_post_write_change_cipher_spec)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* We are done with the input buffer.  */
    s->tlmsp.handshake_buffer_length = 0;

    return 1;
}

static int
tlmsp_middlebox_post_write_change_cipher_spec(SSL *s, int qempty)
{
    SSL *other = s->tlmsp.middlebox_other_ssl;

    other->session->cipher = other->s3->tmp.new_cipher;
    if (!tlmsp_setup_key_block(other)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_POST_WRITE_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_change_cipher_state(other, SSL3_CC_WRITE)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_POST_WRITE_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_middlebox_process_client_hello(SSL *s, PACKET *pkt)
{
    PACKET session_id, cipher_suites, compression_methods, extensions, extension;
    struct tlmsp_middlebox_instance_state *tmis;
    unsigned int client_version;
    unsigned int extension_type;
    size_t outbytes;
    WPACKET out;

    tmis = &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT];

    if (!WPACKET_init_static_len(&out, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_net_2(pkt, &client_version) ||
        !WPACKET_put_bytes_u16(&out, client_version)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_copy_bytes(pkt, tmis->to_server_random, sizeof tmis->to_server_random) ||
        !WPACKET_memcpy(&out, tmis->to_server_random, sizeof tmis->to_server_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &session_id) ||
        PACKET_remaining(&session_id) > SSL3_MAX_SSL_SESSION_ID_LENGTH ||
        !WPACKET_sub_memcpy_u8(&out, PACKET_data(&session_id), PACKET_remaining(&session_id))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_length_prefixed_2(pkt, &cipher_suites) ||
        !WPACKET_sub_memcpy_u16(&out, PACKET_data(&cipher_suites), PACKET_remaining(&cipher_suites))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &compression_methods) ||
        !WPACKET_sub_memcpy_u8(&out, PACKET_data(&compression_methods), PACKET_remaining(&compression_methods))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Now process extensions.  */
    if (PACKET_remaining(pkt)) {
        if (!PACKET_get_length_prefixed_2(pkt, &extensions) ||
            !WPACKET_start_sub_packet_u16(&out)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        while (PACKET_remaining(&extensions)) {
            if (!PACKET_get_net_2(&extensions, &extension_type) ||
                !PACKET_get_length_prefixed_2(&extensions, &extension)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }

            switch (extension_type) {
            case TLSEXT_TYPE_tlmsp:
                if (!tlmsp_parse_ctos_tlmsp(s, &extension, 0, NULL, 0)) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                if (PACKET_remaining(&extension) != 0) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                if (!tlmsp_construct_ctos_tlmsp(s, &out, 0, NULL, 0)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                break;
            case TLSEXT_TYPE_tlmsp_context_list:
                if (!tlmsp_parse_ctos_tlmsp_context_list(s, &extension, 0, NULL, 0)) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                if (PACKET_remaining(&extension) != 0) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                if (!tlmsp_construct_ctos_tlmsp_context_list(s, &out, 0, NULL, 0)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                break;
            case TLSEXT_TYPE_supported_groups:
                /*
                 * Since we are just reading supported_groups, and not
                 * reproducing it, go ahead and copy its data verbatim before
                 * processing.
                 */
                if (!WPACKET_put_bytes_u16(&out, extension_type) ||
                    !WPACKET_sub_memcpy_u16(&out, PACKET_data(&extension), PACKET_remaining(&extension))) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                if (!tls_parse_ctos_supported_groups(s, &extension, 0, NULL, 0)) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                if (PACKET_remaining(&extension) != 0) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                break;
            default:
                if (!WPACKET_put_bytes_u16(&out, extension_type) ||
                    !WPACKET_sub_memcpy_u16(&out, PACKET_data(&extension), PACKET_remaining(&extension))) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                break;
            }
        }

        if (!WPACKET_close(&out)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!WPACKET_finish(&out)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_get_total_written(&out, &outbytes))
        return 0;

    /*
     * Queue this to be forwarded.
     */
    if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE,
                                           SSL3_MT_CLIENT_HELLO,
                                           s->tlmsp.handshake_output_buffer,
                                           outbytes,
                                           tlmsp_middlebox_post_write_client_hello)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* We are done with the input buffer.  */
    s->tlmsp.handshake_buffer_length = 0;

    /*
     * Before we can actually forward the message on, we must connect to the
     * remote peer.
     *
     * Should the attempt to write the forwarding queue do this instead?
     */
    if (SSL_IS_FIRST_HANDSHAKE(s)) {
        if (s->tlmsp.middlebox_other_ssl == NULL) {
            s->tlmsp.middlebox_handshake_error = SSL_ERROR_WANT_OUTBOUND_CONN;
            return 0;
        }
    }

    return 1;
}

static int
tlmsp_middlebox_post_write_client_hello(SSL *s, int qempty)
{
    SSL *other = s->tlmsp.middlebox_other_ssl;

    /*
     * Provision the following to the other SSL:
     *
     * 1. Our middlebox ID.
     * 2. Everything we know about contexts and middleboxes.
     */
    other->tlmsp.self_id = s->tlmsp.self_id;
    other->tlmsp.peer_id = TLMSP_MIDDLEBOX_ID_SERVER;
    memcpy(other->tlmsp.context_states, s->tlmsp.context_states, sizeof s->tlmsp.context_states);
    memcpy(other->tlmsp.middlebox_states, s->tlmsp.middlebox_states, sizeof s->tlmsp.middlebox_states);

    return 1;
}

static int
tlmsp_middlebox_process_server_hello(SSL *s, PACKET *pkt)
{
    PACKET session_id, extensions, extension;
    struct tlmsp_middlebox_instance_state *tmis;
    unsigned int server_version;
    unsigned int extension_type;
    unsigned int compression_method;
    const SSL_CIPHER *c;
    size_t outbytes;
    WPACKET out;

    tmis = &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER];

    if (!WPACKET_init_static_len(&out, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_net_2(pkt, &server_version) ||
        !WPACKET_put_bytes_u16(&out, server_version)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_copy_bytes(pkt, tmis->to_client_random, sizeof tmis->to_server_random) ||
        !WPACKET_memcpy(&out, tmis->to_client_random, sizeof tmis->to_server_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &session_id) ||
        PACKET_remaining(&session_id) > SSL3_MAX_SSL_SESSION_ID_LENGTH ||
        !WPACKET_sub_memcpy_u8(&out, PACKET_data(&session_id), PACKET_remaining(&session_id))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_copy_bytes(pkt, s->tlmsp.middlebox_cipher, sizeof s->tlmsp.middlebox_cipher) ||
        !WPACKET_memcpy(&out, s->tlmsp.middlebox_cipher, sizeof s->tlmsp.middlebox_cipher)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Establish the cipher.
     *
     * As a middlebox, we have to roll with anything we possibly can support.
     * While it would be nice to have a supported ciphers list of some sort,
     * that just won't fly.
     */
    c = ssl_get_cipher_by_char(s, s->tlmsp.middlebox_cipher, 0);
    if (c == NULL) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 SSL_R_UNKNOWN_CIPHER_RETURNED);
        return 0;
    }
    fprintf(stderr, "%s: Established cipher: %s (%s)\n", __func__, SSL_CIPHER_get_name(c), SSL_CIPHER_standard_name(c));
    s->s3->tmp.new_cipher = c;

    /*
     * Now pick a certificate suitable for use with this cipher.
     *
     * XXX
     * This seems to work, but is suspect.  Don't we need to set up the sialg explicitly?
     */
    if (!tls_choose_sigalg(s, 1)) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 SSL_R_UNKNOWN_CIPHER_RETURNED);
        return 0;
    }

    if (!PACKET_get_1(pkt, &compression_method) ||
        !WPACKET_put_bytes_u8(&out, compression_method)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    s->tlmsp.middlebox_compression = compression_method;

    /* Now process extensions.  */
    if (PACKET_remaining(pkt)) {
        if (!PACKET_get_length_prefixed_2(pkt, &extensions) ||
            !WPACKET_start_sub_packet_u16(&out)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        while (PACKET_remaining(&extensions)) {
            if (!PACKET_get_net_2(&extensions, &extension_type) ||
                !PACKET_get_length_prefixed_2(&extensions, &extension)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }

            switch (extension_type) {
            case TLSEXT_TYPE_tlmsp:
                if (!tlmsp_parse_stoc_tlmsp(s, &extension, 0, NULL, 0)) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                if (!tlmsp_construct_stoc_tlmsp(s, &out, 0, NULL, 0)) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                break;
            case TLSEXT_TYPE_tlmsp_context_list:
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                         SSL_R_BAD_EXTENSION);
                return 0;
            default:
                if (!WPACKET_put_bytes_u16(&out, extension_type) ||
                    !WPACKET_sub_memcpy_u16(&out, PACKET_data(&extension), PACKET_remaining(&extension))) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                break;
            }
        }

        if (!WPACKET_close(&out)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!WPACKET_finish(&out)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_get_total_written(&out, &outbytes))
        return 0;

    /*
     * Queue this to be forwarded.
     */
    if (!tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE,
                                           SSL3_MT_SERVER_HELLO,
                                           s->tlmsp.handshake_output_buffer,
                                           outbytes,
                                           tlmsp_middlebox_post_write_server_hello)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* We are done with the input buffer.  */
    s->tlmsp.handshake_buffer_length = 0;

    /*
     * Subsequent records from the server will include the Sid.
     */
    s->tlmsp.record_sid = 1;

    return 1;
}

static int
tlmsp_middlebox_post_write_server_hello(SSL *s, int qempty)
{
    SSL *other = s->tlmsp.middlebox_other_ssl;

    /*
     * Provision the following to the other SSL:
     *
     * 1. The Sid.
     * 2. All updated information on contexts and middleboxes.
     * 3. The cipher suite and compression method. XXX Compression.
     */
    other->tlmsp.sid = s->tlmsp.sid;
    other->tlmsp.have_sid = s->tlmsp.have_sid;
    other->tlmsp.record_sid = s->tlmsp.record_sid;
    memcpy(other->tlmsp.context_states, s->tlmsp.context_states, sizeof s->tlmsp.context_states);
    memcpy(other->tlmsp.middlebox_states, s->tlmsp.middlebox_states, sizeof s->tlmsp.middlebox_states);
    other->s3->tmp.new_cipher = s->s3->tmp.new_cipher;

    return 1;
}

static int
tlmsp_middlebox_post_write_server_done(SSL *s, int qempty)
{
    /*
     * If we are the last middlebox before the server, send our MiddleboxHello
     * (and subsequent) messages.
     *
     * Otherwise, we do so after receiving a MiddleboxHelloDone from the
     * middlebox after us.
     */
    if (tlmsp_middlebox_next(s, s->tlmsp.self_id) == TLMSP_MIDDLEBOX_ID_NONE) {
        if (!tlmsp_middlebox_send_middlebox_hello(s))
            return 0;
    }
    return 1;
}


static int
tlmsp_middlebox_send_middlebox_hello(SSL *s)
{
    SSL *other = s->tlmsp.middlebox_other_ssl;
    WPACKET pkt;
    size_t pktbytes;

    if (!WPACKET_init_static_len(&pkt, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0) ||
        !tlmsp_construct_middlebox_hello(s, &pkt) ||
        !WPACKET_finish(&pkt) ||
        !WPACKET_get_total_written(&pkt, &pktbytes) ||
        !tlmsp_middlebox_handshake_broadcast(s, SSL3_RT_HANDSHAKE,
                                             TLMSP_MT_MIDDLEBOX_HELLO,
                                             s->tlmsp.handshake_output_buffer,
                                             pktbytes)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_SEND_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * At this point, we have generated our to-client and to-server random
     * values, and need to propagate them to the other SSL as well.
     */
    memcpy(other->tlmsp.middlebox_states[s->tlmsp.self_id].to_client_random, s->tlmsp.middlebox_states[s->tlmsp.self_id].to_client_random, SSL3_RANDOM_SIZE);
    memcpy(other->tlmsp.middlebox_states[s->tlmsp.self_id].to_server_random, s->tlmsp.middlebox_states[s->tlmsp.self_id].to_server_random, SSL3_RANDOM_SIZE);

    if (!WPACKET_init_static_len(&pkt, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0) ||
        !tlmsp_construct_middlebox_cert(s, &pkt) ||
        !WPACKET_finish(&pkt) ||
        !WPACKET_get_total_written(&pkt, &pktbytes) ||
        !tlmsp_middlebox_handshake_broadcast(s, SSL3_RT_HANDSHAKE,
                                             TLMSP_MT_MIDDLEBOX_CERT,
                                             s->tlmsp.handshake_output_buffer,
                                             pktbytes)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_SEND_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_init_static_len(&pkt, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0) ||
        !tlmsp_construct_middlebox_key_exchange(s, &pkt) ||
        !WPACKET_finish(&pkt) ||
        !WPACKET_get_total_written(&pkt, &pktbytes) ||
        !tlmsp_middlebox_handshake_broadcast(s, SSL3_RT_HANDSHAKE,
                                             TLMSP_MT_MIDDLEBOX_KEY_EXCHANGE,
                                             s->tlmsp.handshake_output_buffer,
                                             pktbytes)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_SEND_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_init_static_len(&pkt, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0) ||
        !tlmsp_construct_middlebox_hello_done(s, &pkt) ||
        !WPACKET_finish(&pkt) ||
        !WPACKET_get_total_written(&pkt, &pktbytes) ||
        !tlmsp_middlebox_handshake_broadcast(s, SSL3_RT_HANDSHAKE,
                                             TLMSP_MT_MIDDLEBOX_HELLO_DONE,
                                             s->tlmsp.handshake_output_buffer,
                                             pktbytes)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_SEND_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_middlebox_send_middlebox_key_confirmation(SSL *s)
{
    SSL *other = s->tlmsp.middlebox_other_ssl;
    WPACKET pkt;
    size_t pktbytes;

    /*
     * When sending a MiddleboxKeyConfirmation, also synchronize context state
     * from us to the other SSL, so that it is up to date on the latest
     * contributions.
     */
    memcpy(other->tlmsp.context_states, s->tlmsp.context_states, sizeof s->tlmsp.context_states);

    if (!WPACKET_init_static_len(&pkt, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0) ||
        !tlmsp_construct_middlebox_key_confirmation(s, &pkt) ||
        !WPACKET_finish(&pkt) ||
        !WPACKET_get_total_written(&pkt, &pktbytes) ||
        !tlmsp_middlebox_handshake_forward(s, SSL3_RT_HANDSHAKE,
                                           TLMSP_MT_MIDDLEBOX_KEY_CONFIRMATION,
                                           s->tlmsp.handshake_output_buffer,
                                           pktbytes, NULL)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_SEND_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static void
TLMSP_MWQI_free(TLMSP_MWQI *w)
{
    OPENSSL_free(w);
}
