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

/*
 * XXX
 * Are we harmonizing things like context and middlebox state often enough and
 * completely enough?
 */

/* Handshake message forwarding.  */
static int tlmsp_middlebox_handshake_broadcast(SSL *, int, int, const uint8_t *, size_t);
static int tlmsp_middlebox_handshake_forward(SSL *, int, int, int, const uint8_t *, size_t, int (*)(SSL *, int));

/* Handshake message processing.  */
/* Endpoint handshake messages. */
static int tlmsp_middlebox_process_certificate(SSL *, PACKET *);

static int tlmsp_middlebox_process_change_cipher_spec(SSL *, PACKET *);
static int tlmsp_middlebox_post_write_change_cipher_spec(SSL *, int);

static int tlmsp_middlebox_process_client_hello(SSL *, PACKET *);
static int tlmsp_middlebox_post_write_client_hello(SSL *, int);

static int tlmsp_middlebox_process_client_key_exchange(SSL *, PACKET *);

static int tlmsp_middlebox_process_server_hello(SSL *, PACKET *);
static int tlmsp_middlebox_post_write_server_hello(SSL *, int);

static int tlmsp_middlebox_post_write_server_done(SSL *, int);

static int tlmsp_middlebox_process_server_key_exchange(SSL *, PACKET *);

/* Middlebox handshake messages. */
static int tlmsp_middlebox_process_middlebox_certificate(SSL *, PACKET *);

static int tlmsp_middlebox_process_middlebox_finished(SSL *, PACKET *);

static int tlmsp_middlebox_process_middlebox_hello(SSL *, PACKET *);

static int tlmsp_middlebox_process_middlebox_hello_done(SSL *, PACKET *);

static int tlmsp_middlebox_process_middlebox_key_material(SSL *, PACKET *);

static int tlmsp_middlebox_send_middlebox_hello(SSL *);

/* Extension processing.  */
static int tlmsp_middlebox_parse_ctos_sig_algs(SSL *, PACKET *);

/* Helper functions.  */
static void TLMSP_MWQI_free(TLMSP_MWQI *);

/*
 * This structure allows us to generalize processing by middleboxes of
 * messages.
 */
enum tlmsp_middlebox_message_forward {
    TMMF_NONE,      /* Process function will handle forwarding, if any.  */
    TMMF_BEFORE,    /* Message should be forwarded before processing.  */
};

struct tlmsp_middlebox_message_handler {
    int mt;
    enum tlmsp_middlebox_message_forward forward;
    int (*process)(SSL *, PACKET *);
    int (*post_write)(SSL *, int);
};

/*
 * TODO
 * CertificateRequest
 * MboxCertificateRequest
 * CertificateMbox
 * ClientMboxKeyExchange
 */
static const struct tlmsp_middlebox_message_handler tlmsp_middlebox_message_handlers[] = {
    { SSL3_MT_CLIENT_HELLO,                 TMMF_NONE,      tlmsp_middlebox_process_client_hello,               NULL },
    { SSL3_MT_SERVER_HELLO,                 TMMF_BEFORE,    tlmsp_middlebox_process_server_hello,               tlmsp_middlebox_post_write_server_hello },
    { SSL3_MT_CERTIFICATE,                  TMMF_BEFORE,    tlmsp_middlebox_process_certificate,                NULL },
    { SSL3_MT_SERVER_KEY_EXCHANGE,          TMMF_BEFORE,    tlmsp_middlebox_process_server_key_exchange,        NULL },
    { SSL3_MT_SERVER_DONE,                  TMMF_BEFORE,    NULL,                                               tlmsp_middlebox_post_write_server_done },
    { TLMSP_MT_MIDDLEBOX_CERT,              TMMF_BEFORE,    tlmsp_middlebox_process_middlebox_certificate,      NULL },
    { TLMSP_MT_MIDDLEBOX_HELLO,             TMMF_BEFORE,    tlmsp_middlebox_process_middlebox_hello,            NULL },
    { TLMSP_MT_MIDDLEBOX_HELLO_DONE,        TMMF_NONE,      tlmsp_middlebox_process_middlebox_hello_done,       NULL },
    { SSL3_MT_CLIENT_KEY_EXCHANGE,          TMMF_BEFORE,    tlmsp_middlebox_process_client_key_exchange,        NULL },
    { TLMSP_MT_MIDDLEBOX_KEY_MATERIAL,      TMMF_NONE,      tlmsp_middlebox_process_middlebox_key_material,     NULL },
    { TLMSP_MT_MIDDLEBOX_FINISHED,          TMMF_NONE,      tlmsp_middlebox_process_middlebox_finished,         NULL },
    { -1,                                   TMMF_BEFORE,    NULL,                                               NULL },
};

struct tlmsp_middlebox_write_queue_item {
    int rt;
    int originated;
    size_t length;
    uint8_t buffer[TLMSP_MAX_HANDSHAKE_BUFFER];
    uint8_t *head;
    int (*completion)(SSL *, int);
};

/* API functions.  */

int
tlmsp_middlebox_handshake_flush(SSL *s)
{
    TLMSP_MWQIs *write_queue;
    OSSL_STATEM *st;
    SSL *write_ssl;
    size_t resid, written;
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
    resid = w->length - (w->head - w->buffer);
    rv = ssl3_write_bytes(write_ssl, w->rt, w->head, resid, &written);
    if (rv != 1)
        return 0;
    if (written != resid) {
        w->head += written;
    } else {
        sk_TLMSP_MWQI_shift(write_queue);

        /*
         * XXX
         * There may be a race in doing this here rather than in forward().
         */
        if (!tlmsp_finish_append(s, w->originated, w->rt, w->buffer, w->length)) {
            TLMSP_MWQI_free(w);
            return 0;
        }

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
    const struct tlmsp_middlebox_message_handler *tmmh;
    unsigned int mt;
    PACKET pkt, msg;
    OSSL_STATEM *st;
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
     * As we do not allow a handshake message to be split across records in
     * TLMSP, we instead read a record at a time, and process its contents.
     *
     * Only Handshake protocol messages may contain multiple messages per
     * record, so if we are processing the left-overs of our last record, we
     * know it is handshake type.
     */
    if (s->tlmsp.handshake_buffer_length == 0) {
        SSL3_RECORD *rr;

        rv = ssl3_get_record(s);
        if (rv <= 0)
            return -1;
        if (RECORD_LAYER_get_numrpipes(&s->rlayer) != 1) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }

        rr = s->rlayer.rrec;
        if (SSL3_RECORD_get_length(rr) > sizeof s->tlmsp.handshake_buffer) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }
        s->tlmsp.handshake_buffer_length = SSL3_RECORD_get_length(rr);
        memcpy(s->tlmsp.handshake_buffer, &rr->data[rr->off], s->tlmsp.handshake_buffer_length);
        SSL3_RECORD_set_read(rr);

        switch (SSL3_RECORD_get_type(rr)) {
        case SSL3_RT_HANDSHAKE:
            break;
        case SSL3_RT_CHANGE_CIPHER_SPEC:
            if (s->tlmsp.handshake_buffer_length != 1) {
                SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                         SSL_R_BAD_CHANGE_CIPHER_SPEC);
                return -1;
            }
            if (!PACKET_buf_init(&pkt, s->tlmsp.handshake_buffer,
                                 s->tlmsp.handshake_buffer_length)) {
                return -1;
            }
            s->tlmsp.handshake_buffer_length = 0;
            if (!tlmsp_middlebox_process_change_cipher_spec(s, &pkt))
                return -1;
            return 1;
        case SSL3_RT_ALERT:
            if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_ALERT, SSL3_MT_DUMMY, s->tlmsp.handshake_buffer, s->tlmsp.handshake_buffer_length, NULL))
                return -1;
            s->tlmsp.handshake_buffer_length = 0;
            return 1;
        default:
            SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                     SSL_R_CCS_RECEIVED_EARLY);
            return -1;
        }
    }

    /*
     * Now process the next Handshake message.
     */
    /* Decode header.  */
    if (!PACKET_buf_init(&pkt,
                         s->tlmsp.handshake_buffer,
                         s->tlmsp.handshake_buffer_length) ||
        !PACKET_get_1(&pkt, &mt) ||
        !PACKET_get_length_prefixed_3(&pkt, &msg)) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_MIDDLEBOX_HANDSHAKE_PROCESS,
                 SSL_R_EXCESSIVE_MESSAGE_SIZE);
        return -1;
    }
    s->tlmsp.handshake_buffer_length = PACKET_remaining(&pkt);
    if (s->tlmsp.handshake_buffer_length != 0)
        fprintf(stderr, "%s: observed multiple messages in one record.\n", __func__);

    /* Find the appropriate handler.  */
    for (tmmh = tlmsp_middlebox_message_handlers; tmmh->mt != -1; tmmh++) {
        if (tmmh->mt == (int)mt)
            break;
    }

    /* If we are handling forwarding before processing, do so.  */
    if (tmmh->forward == TMMF_BEFORE) {
        if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_HANDSHAKE, mt, PACKET_data(&msg), PACKET_remaining(&msg), tmmh->post_write))
            return -1;
    }

    if (tmmh->process != NULL) {
        /* Call the processing function.  */
        if (!tmmh->process(s, &msg))
            return -1;
    }
    return 1;
}

/* Local functions.  */

static int
tlmsp_middlebox_handshake_broadcast(SSL *s, int rt, int mt, const uint8_t *m, size_t len)
{
    SSL *other = s->tlmsp.middlebox_other_ssl;
    int rv[2];

    rv[0] = tlmsp_middlebox_handshake_forward(s, 1, rt, mt, m, len, NULL);
    rv[1] = tlmsp_middlebox_handshake_forward(other, 1, rt, mt, m, len, NULL);

    if (rv[0] != 1)
        return rv[0];
    if (rv[1] != 1)
        return rv[1];
    return 1;
}

static int
tlmsp_middlebox_handshake_forward(SSL *s, int originated, int rt, int mt, const uint8_t *m, size_t len, int (*completion)(SSL *, int))
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

    w->rt = rt;
    w->originated = originated;
    w->completion = completion;
    w->head = w->buffer;
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
tlmsp_middlebox_process_certificate(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis;

    tmis = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    if (tmis == NULL)
        return 0;

    if (!tlmsp_process_certificate(s, pkt, &tmis->cert_chain))
        return 0;

    if (!tlmsp_middlebox_verify_certificate(s, tmis))
        return 0;

    return 1;
}

static int
tlmsp_middlebox_process_change_cipher_spec(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *peer;
    unsigned int type;

    peer = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    if (peer == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

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
    if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_CHANGE_CIPHER_SPEC,
                                           SSL3_MT_DUMMY, PACKET_data(pkt),
                                           PACKET_remaining(pkt),
                                           tlmsp_middlebox_post_write_change_cipher_spec)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CHANGE_CIPHER_SPEC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

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
    TLMSP_MiddleboxInstance *tmis;
    unsigned int client_version;
    unsigned int extension_type;
    size_t outbytes;
    WPACKET out;

    tmis = &s->tlmsp.client_middlebox;

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
            case TLSEXT_TYPE_signature_algorithms:
            case TLSEXT_TYPE_supported_groups:
                /*
                 * Since we are just reading these extensions, and not
                 * reproducing them, go ahead and copy their data verbatim
                 * before processing.
                 */
                if (PACKET_remaining(&extension) == 0) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             SSL_R_BAD_EXTENSION);
                    return 0;
                }
                if (!WPACKET_put_bytes_u16(&out, extension_type) ||
                    !WPACKET_sub_memcpy_u16(&out, PACKET_data(&extension), PACKET_remaining(&extension))) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
                switch (extension_type) {
                case TLSEXT_TYPE_signature_algorithms:
                    if (!tlmsp_middlebox_parse_ctos_sig_algs(s, &extension)) {
                        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                                 SSL_R_BAD_EXTENSION);
                        return 0;
                    }
                    break;
                case TLSEXT_TYPE_supported_groups:
                    if (!tls_parse_ctos_supported_groups(s, &extension, 0, NULL, 0)) {
                        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                                 SSL_R_BAD_EXTENSION);
                        return 0;
                    }
                    break;
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
    if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_HANDSHAKE,
                                           SSL3_MT_CLIENT_HELLO,
                                           s->tlmsp.handshake_output_buffer,
                                           outbytes,
                                           tlmsp_middlebox_post_write_client_hello)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_CLIENT_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

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
     * 1. Everything we know about contexts and middleboxes, including ourself.
     */
    memcpy(other->tlmsp.context_states, s->tlmsp.context_states, sizeof s->tlmsp.context_states);
    if (!tlmsp_middlebox_synchronize(other, s, 1))
        return 0;

    /*
     * Enable alert containerization on this SSL.
     */
    s->tlmsp.alert_container = 1;

    return 1;
}

static int
tlmsp_middlebox_process_client_key_exchange(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *peer;

    peer = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    if (peer == NULL)
        return 0;

    return tlmsp_process_client_key_exchange(s, pkt, peer, &s->tlmsp.kex_from_peer);
}

static int
tlmsp_middlebox_process_server_hello(SSL *s, PACKET *pkt)
{
    PACKET session_id, extensions, extension;
    TLMSP_MiddleboxInstance *tmis;
    unsigned int server_version;
    unsigned int extension_type;
    unsigned int compression_method;
    const SSL_CIPHER *c;

    tmis = &s->tlmsp.server_middlebox;

    if (!PACKET_get_net_2(pkt, &server_version)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_copy_bytes(pkt, tmis->to_client_random, sizeof tmis->to_server_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_length_prefixed_1(pkt, &session_id) ||
        PACKET_remaining(&session_id) > SSL3_MAX_SSL_SESSION_ID_LENGTH) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_copy_bytes(pkt, s->tlmsp.middlebox_cipher, sizeof s->tlmsp.middlebox_cipher)) {
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
#if 0
    fprintf(stderr, "%s: Established cipher: %s (%s)\n", __func__, SSL_CIPHER_get_name(c), SSL_CIPHER_standard_name(c));
#endif
    s->s3->tmp.new_cipher = c;

    /*
     * Now pick a certificate suitable for use with this cipher.
     */
    if (!tlmsp_middlebox_choose_certificate(s)) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 SSL_R_UNKNOWN_CIPHER_RETURNED);
        return 0;
    }

    if (!PACKET_get_1(pkt, &compression_method)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (compression_method != 0) {
        SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                 SSL_R_UNSUPPORTED_COMPRESSION_ALGORITHM);
        return 0;
    }

    /* Now process extensions.  */
    if (PACKET_remaining(pkt)) {
        if (!PACKET_get_length_prefixed_2(pkt, &extensions)) {
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
                break;
            case TLSEXT_TYPE_tlmsp_context_list:
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_SERVER_HELLO,
                         SSL_R_BAD_EXTENSION);
                return 0;
            default:
                break;
            }
        }
    }

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
     * 3. The cipher suite.
     */
    other->tlmsp.sid = s->tlmsp.sid;
    other->tlmsp.have_sid = s->tlmsp.have_sid;
    other->tlmsp.record_sid = s->tlmsp.record_sid;
    memcpy(other->tlmsp.context_states, s->tlmsp.context_states, sizeof s->tlmsp.context_states);
    if (!tlmsp_middlebox_synchronize(other, s, 0))
        return 0;
    other->s3->tmp.new_cipher = s->s3->tmp.new_cipher;

    /*
     * Enable alert containerization on this SSL.
     */
    s->tlmsp.alert_container = 1;

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
    if (tlmsp_middlebox_next(s, s->tlmsp.self) == NULL) {
        if (!tlmsp_middlebox_send_middlebox_hello(s))
            return 0;
    }
    return 1;
}

static int
tlmsp_middlebox_process_server_key_exchange(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *peer;

    peer = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    if (peer == NULL)
        return 0;

    return tlmsp_process_server_key_exchange(s, pkt, peer, &s->tlmsp.kex_from_peer);
}

static int
tlmsp_middlebox_process_middlebox_certificate(SSL *s, PACKET *pkt)
{
    MSG_PROCESS_RETURN ret;

    ret = tlmsp_process_middlebox_cert(s, pkt);
    if (ret == MSG_PROCESS_ERROR)
        return -1;

    return 1;
}

static int
tlmsp_middlebox_process_middlebox_finished(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis, *peer, *otherpeer;
    SSL *other = s->tlmsp.middlebox_other_ssl;
    unsigned int id;
    size_t mfinbytes;
    WPACKET mfin;

    if (!PACKET_peek_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * This may be the MiddleboxFinished which ends the handshake in this
     * direction, which occurs when it is the message for the last middlebox.
     */
    if (tlmsp_middlebox_next(s, tmis) == NULL) {
        OSSL_STATEM *st;

        st = &s->statem;
        st->hand_state = TLS_ST_OK;
    }

    if (id != s->tlmsp.self->state.id) {
        if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_HANDSHAKE,
                                               TLMSP_MT_MIDDLEBOX_FINISHED,
                                               PACKET_data(pkt),
                                               PACKET_remaining(pkt), NULL)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        return 1;
    }

    peer = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    if (peer == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * This is for us, we replace the value with our MiddleboxFinished
     * continuing in the same direction, i.e. a MiddleboxFinished from the
     * client to the server we verify against the client value, and then we
     * send on with a server value.
     */
    if (!PACKET_forward(pkt, 1) ||
        !tlmsp_finish_verify(s, peer, PACKET_data(pkt), PACKET_remaining(pkt))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    otherpeer = tlmsp_middlebox_lookup(other, TLMSP_MIDDLEBOX_ID_PEER(other));
    if (otherpeer == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_init_static_len(&mfin, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0) ||
        !WPACKET_put_bytes_u8(&mfin, other->tlmsp.self->state.id) ||
        !tlmsp_finish_construct(other, otherpeer, &mfin) ||
        !WPACKET_finish(&mfin) ||
        !WPACKET_get_total_written(&mfin, &mfinbytes)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_HANDSHAKE,
                                           TLMSP_MT_MIDDLEBOX_FINISHED,
                                           s->tlmsp.handshake_output_buffer,
                                           mfinbytes, NULL)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_middlebox_process_middlebox_hello(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis, *othertmis;
    SSL *other = s->tlmsp.middlebox_other_ssl;
    unsigned int id;
    MSG_PROCESS_RETURN ret;

    if (!PACKET_peek_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    othertmis = tlmsp_middlebox_lookup(other, id);
    if (tmis == NULL || othertmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    ret = tlmsp_process_middlebox_hello(s, pkt);
    if (ret == MSG_PROCESS_ERROR)
        return -1;

    /* Sync client_random and server_random values.  */
    memcpy(othertmis->to_client_random, tmis->to_client_random, sizeof tmis->to_client_random);
    memcpy(othertmis->to_server_random, tmis->to_server_random, sizeof tmis->to_server_random);

    return 1;
}

static int
tlmsp_middlebox_process_middlebox_hello_done(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis;
    unsigned int id;

    if (!PACKET_peek_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_HELLO_DONE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_HELLO_DONE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_HANDSHAKE,
                                           TLMSP_MT_MIDDLEBOX_HELLO_DONE,
                                           PACKET_data(pkt),
                                           PACKET_remaining(pkt), NULL)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_HELLO_DONE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If this is the middlebox which follows us in network topological order,
     * it is our turn to send out our MiddleboxHello.
     */
    if (tlmsp_middlebox_next(s, s->tlmsp.self) == tmis) {
        if (!tlmsp_middlebox_send_middlebox_hello(s)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_HELLO_DONE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

static int
tlmsp_middlebox_process_middlebox_key_material(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *peer;
    MSG_PROCESS_RETURN ret;
    unsigned int id;
    size_t mkcbytes;
    WPACKET mkc;
    unsigned j;

    if (!PACKET_peek_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (id != s->tlmsp.self->state.id) {
        peer = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
        if (peer == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (!tlmsp_middlebox_handshake_forward(s, 0, SSL3_RT_HANDSHAKE,
                                               TLMSP_MT_MIDDLEBOX_KEY_MATERIAL,
                                               PACKET_data(pkt),
                                               PACKET_remaining(pkt), NULL)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        return 1;
    }

    ret = tlmsp_process_middlebox_key_material(s, pkt);
    if (ret == MSG_PROCESS_ERROR) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Copy all context contributions to the other middlebox.
     *
     * We could just copy the parts contributed by this peer, but copying the
     * whole thing is easy and converges on the correct result (a shared
     * understanding.)
     */
    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        const struct tlmsp_context_instance_state *tcis;
        const struct tlmsp_context_key_block *tckb;
        struct tlmsp_context_key_block *othertckb;
        SSL *other = s->tlmsp.middlebox_other_ssl;

        tcis = &s->tlmsp.context_states[j];
        if (!tcis->state.present)
            continue;
        tckb = &tcis->key_block;
        othertckb = &other->tlmsp.context_states[j].key_block;

        memcpy(othertckb->contributions, tckb->contributions, sizeof tckb->contributions);
    }

    if (!WPACKET_init_static_len(&mkc, s->tlmsp.handshake_output_buffer, sizeof s->tlmsp.handshake_output_buffer, 0) ||
        !tlmsp_construct_middlebox_key_confirmation(s, &mkc) ||
        !WPACKET_finish(&mkc) ||
        !WPACKET_get_total_written(&mkc, &mkcbytes)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_middlebox_handshake_forward(s, 1, SSL3_RT_HANDSHAKE,
                                           TLMSP_MT_MIDDLEBOX_KEY_CONFIRMATION,
                                           s->tlmsp.handshake_output_buffer,
                                           mkcbytes, NULL)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MIDDLEBOX_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_middlebox_send_middlebox_hello(SSL *s)
{
    TLMSP_MiddleboxInstance *otherself;
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
    otherself = tlmsp_middlebox_lookup(other, s->tlmsp.self->state.id);
    memcpy(otherself->to_client_random, s->tlmsp.self->to_client_random, SSL3_RANDOM_SIZE);
    memcpy(otherself->to_server_random, s->tlmsp.self->to_server_random, SSL3_RANDOM_SIZE);

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
tlmsp_middlebox_parse_ctos_sig_algs(SSL *s, PACKET *pkt)
{
    PACKET sig_algs;

    if (!PACKET_get_length_prefixed_2(pkt, &sig_algs)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PARSE_CTOS_SIG_ALGS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PARSE_CTOS_SIG_ALGS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (PACKET_remaining(&sig_algs) == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PARSE_CTOS_SIG_ALGS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tls1_save_u16(&sig_algs, &s->s3->tmp.peer_sigalgs,
                       &s->s3->tmp.peer_sigalgslen)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_MIDDLEBOX_PARSE_CTOS_SIG_ALGS,
                 SSL_R_BAD_EXTENSION);
        return 0;
    }

    return 1;
}

static void
TLMSP_MWQI_free(TLMSP_MWQI *w)
{
    OPENSSL_free(w);
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
