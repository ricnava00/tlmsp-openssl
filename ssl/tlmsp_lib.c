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
    ctx->tlmsp.discovery_cb = cb;
    ctx->tlmsp.discovery_cb_arg = arg;
}

void TLMSP_set_discovery_cb_instance(SSL *s, TLMSP_discovery_cb_fn cb, void *arg)
{
    s->tlmsp.discovery_cb = cb;
    s->tlmsp.discovery_cb_arg = arg;
}

int
TLMSP_discovery_get_hash(SSL *s, unsigned char *buf, size_t buflen)
{
    /* XXX we are relying on caller to be separately aware of which hash is in use in order to size buffer / result */
    return 0;
}

const TLMSP_ReconnectState *
TLMSP_get_reconnect_state(SSL *s)
{
    TLMSP_ReconnectState *reconnect;
    struct tlmsp_context_state *tcs;
    char *purpose_str;
    unsigned int i;

    if (!s->tlmsp.need_reconnect)
        return NULL;

    reconnect = OPENSSL_zalloc(sizeof *reconnect);
    if (reconnect == NULL) {
        SSLerr(SSL_F_TLMSP_GET_RECONNECT_STATE, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    reconnect->sid = s->tlmsp.sid;

    memcpy(&reconnect->client_address, &s->tlmsp.client_middlebox.state.address, sizeof(reconnect->client_address));
    memcpy(&reconnect->server_address, &s->tlmsp.server_middlebox.state.address, sizeof(reconnect->server_address));

    if (!tlmsp_get_middleboxes_list(&reconnect->initial_middleboxes, s->tlmsp.initial_middlebox_list)) {
        SSLerr(SSL_F_TLMSP_GET_RECONNECT_STATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!tlmsp_get_middleboxes_list(&reconnect->final_middleboxes, s->tlmsp.current_middlebox_list)) {
        SSLerr(SSL_F_TLMSP_GET_RECONNECT_STATE, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    for (i = 0; i < TLMSP_CONTEXT_COUNT; i++) {
        if (i == TLMSP_CONTEXT_CONTROL)
            continue;
        tcs = &s->tlmsp.context_states[i].state;
        purpose_str = strndup((char *)tcs->purpose, tcs->purposelen);
        if (purpose_str == NULL)
            goto err;
        if (!TLMSP_context_add(&reconnect->contexts, i, purpose_str, tcs->audit)) {
            free(purpose_str);
            goto err;
        }
        free(purpose_str);
    }

    if (!ssl3_digest_cached_records(s, 0))
        goto err;

    if (!ssl_handshake_hash(s, reconnect->hash, sizeof(reconnect->hash), &reconnect->hashlen))
        goto err;

    return reconnect;

err:
    TLMSP_reconnect_state_free(reconnect);

    return NULL;
}

int
TLMSP_set_reconnect_state(SSL *s, const TLMSP_ReconnectState *reconnect)
{
    if (reconnect == NULL)
        return 0;

    s->tlmsp.have_sid = 1;
    s->tlmsp.sid = reconnect->sid;

    if (!tlmsp_address_set(&s->tlmsp.client_middlebox.state.address,
            reconnect->client_address.address_type, reconnect->client_address.address, reconnect->client_address.address_len))
        return 0;
    if (!tlmsp_address_set(&s->tlmsp.server_middlebox.state.address,
            reconnect->server_address.address_type, reconnect->server_address.address, reconnect->server_address.address_len))
        return 0;

    tlmsp_middleboxes_clear_initial(s);
    tlmsp_middleboxes_clear_current(s);

    if (!tlmsp_set_middlebox_list(&s->tlmsp.initial_middlebox_list, reconnect->initial_middleboxes))
        return 0;
    if (!tlmsp_middlebox_table_compile_initial(s))
        return 0;

    if (!tlmsp_set_middlebox_list(&s->tlmsp.current_middlebox_list, reconnect->final_middleboxes))
        return 0;
    if (!tlmsp_middlebox_table_compile_current(s))
        return 0;

    if (!TLMSP_set_contexts_instance(s, reconnect->contexts))
        return 0;

    memcpy(s->tlmsp.post_discovery_hash, reconnect->hash, reconnect->hashlen);
    s->tlmsp.post_discovery_hashlen = reconnect->hashlen;

    s->tlmsp.is_post_discovery = 1;

    return 1;
}

void
TLMSP_reconnect_state_free(const TLMSP_ReconnectState *reconnect)
{
    if (reconnect == NULL)
        return;

    TLMSP_middleboxes_free(reconnect->initial_middleboxes);
    TLMSP_middleboxes_free(reconnect->final_middleboxes);
    TLMSP_contexts_free(reconnect->contexts);
    OPENSSL_free((void *)reconnect);
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
    memset(&ctx->tlmsp.client_middlebox_state, 0, sizeof ctx->tlmsp.client_middlebox_state);
    memset(&ctx->tlmsp.server_middlebox_state, 0, sizeof ctx->tlmsp.server_middlebox_state);

    ctx->tlmsp.discovery_cb = NULL;
    ctx->tlmsp.discovery_cb_arg = NULL;

    ctx->tlmsp.always_reconnect = 1;

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
        s->tlmsp.client_middlebox.state = ctx->tlmsp.client_middlebox_state;
        s->tlmsp.client_middlebox.state.id = TLMSP_MIDDLEBOX_ID_CLIENT;
        s->tlmsp.server_middlebox.state = ctx->tlmsp.server_middlebox_state;
        s->tlmsp.server_middlebox.state.id = TLMSP_MIDDLEBOX_ID_SERVER;
        if (!TLMSP_set_initial_middleboxes_instance(s, ctx->tlmsp.middlebox_states))
            return 0;
    } else {
        s->tlmsp.always_reconnect = 1;
    }

    /*
     * Copy middlebox configuration parameters.
     */
    s->tlmsp.middlebox_config = ctx->tlmsp.middlebox_config;

    tlmsp_buffer_init(&s->tlmsp.client_hello_buffer);
    tlmsp_buffer_init(&s->tlmsp.server_hello_buffer);

    tlmsp_finish_init(&s->tlmsp.middlebox_finish_state);

    /*
     * Copy discovery callback configuration
     */
    s->tlmsp.discovery_cb = ctx->tlmsp.discovery_cb;
    s->tlmsp.discovery_cb_arg = ctx->tlmsp.discovery_cb_arg;

    if (!tlmsp_instance_state_reset(s))
        return 0;

    return 1;
}

int
tlmsp_instance_state_reset(SSL *s)
{
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

    s->tlmsp.self = NULL;

    s->tlmsp.have_sid = 0;
    s->tlmsp.record_sid = 0;

    s->tlmsp.alert_container = 0;
    s->tlmsp.alert_context = TLMSP_CONTEXT_CONTROL;

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

    s->tlmsp.send_middlebox_key_material = 1;
    s->tlmsp.next_middlebox_key_material_middlebox = NULL;
    s->tlmsp.send_middlebox_finished = 1;
    s->tlmsp.next_middlebox_finished_middlebox = NULL;

    tlmsp_buffer_clear(&s->tlmsp.client_hello_buffer);
    tlmsp_buffer_clear(&s->tlmsp.server_hello_buffer);

    tlmsp_finish_clear(&s->tlmsp.middlebox_finish_state);

    tlmsp_sequence_init(&s->tlmsp.client_middlebox);
    tlmsp_sequence_init(&s->tlmsp.server_middlebox);

    /*
     * XXX
     * In some circumstances, we could reset all middlebox state; which cases
     * should those be?
     */

    tlmsp_middlebox_handshake_free(s);

    return 1;
}

void
tlmsp_instance_state_free(SSL *s)
{
    /* Use the reset function to get rid of anything temporary.  */
    (void)tlmsp_instance_state_reset(s);

    /*
     * Clean up all middlebox state.
     */
    tlmsp_middlebox_instance_cleanup(&s->tlmsp.client_middlebox);
    tlmsp_middlebox_instance_cleanup(&s->tlmsp.server_middlebox);

    tlmsp_middleboxes_clear_initial(s);
    tlmsp_middleboxes_clear_current(s);

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

    while (s->tlmsp.stream_read_container == NULL) {
        rv = TLMSP_container_read(s, &s->tlmsp.stream_read_container);
        if (rv <= 0)
            return rv;
        if (s->tlmsp.stream_read_container == NULL) {
            *readp = 0;
            return 1;
        }
        if (TLMSP_container_alert(s->tlmsp.stream_read_container, NULL) != 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_READ_BYTES,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }
        /*
         * Discard all delete containers.
         *
         * They may bear data, but we deem this to be out-of-band metadata, and
         * not relevant to the data stream as seen through the stream-oriented
         * API.
         */
        if (TLMSP_container_deleted(s->tlmsp.stream_read_container)) {
            TLMSP_container_free(s, s->tlmsp.stream_read_container);
            s->tlmsp.stream_read_container = NULL;
            continue;
        }
        /*
         * XXX
         * We should probably do likewise for empty containers.  We'll support
         * forwarding alert containers including close_notify, so we shouldn't
         * do this, but instead return a 0-length read for a close_notify alert.
         */
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

    s->tlmsp.read_last_context = s->tlmsp.stream_read_container->envelope.cid;
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

void
tlmsp_fatal(SSL *s, int al, tlmsp_context_id_t cid, int func, int reason, const char *file, int line)
{
    /*
     * If we already have an error, don't override the context, as we will only
     * send the first alert.  Otherwise, set the context that will be used for
     * sending the alert.
     */
    if (!s->statem.in_init || s->statem.state != MSG_FLOW_ERROR)
        s->tlmsp.alert_context = cid;
    ossl_statem_fatal(s, al, func, reason, file, line);
}

int
tlmsp_process_alert(SSL *s, tlmsp_context_id_t cid, const uint8_t *alert_data, size_t alert_datalen)
{
    char context_number[sizeof "255"];
    char alert_number[sizeof "255"];
    int alert;

    /*
     * In this case, we have a TLMSPAlert, which cannot occur within a
     * container, but which indicates the origin endpoint/middlebox with the
     * initial byte of data.  We ignore the first byte for now, as we lack
     * anything to do with it.
     */
    if (alert_datalen == 3) {
        alert_data++;
        alert_datalen--;
    }

    /*
     * We can reach this point where there is a record containing a
     * containerized alert early in the handshake.  If we can't parse it into a
     * container and deliver it as an alert, there's nothing more we can do.
     */
    if (alert_datalen != 2) {
        TLMSP_Container *c;

        if (!tlmsp_container_parse(s, &c, SSL3_RT_ALERT, alert_data, alert_datalen)) {
            SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_PROCESS_ALERT,
                     SSL_R_INVALID_ALERT);
            return 0;
        }
        if (TLMSP_container_alert(c, NULL) != 1) {
            TLMSP_container_free(s, c);
            SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_PROCESS_ALERT,
                     SSL_R_INVALID_ALERT);
            return 0;
        }
        if (!tlmsp_container_deliver_alert(s, c)) {
            TLMSP_container_free(s, c);
            SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_PROCESS_ALERT,
                     SSL_R_INVALID_ALERT);
            return 0;
        }
        return 1;
    }

    alert = SSL_alert_value(alert_data[0], alert_data[1]);

    if (s->msg_callback != NULL)
        s->msg_callback(0, s->version, SSL3_RT_ALERT, alert_data, 2, s, s->msg_callback_arg);

    if (s->info_callback != NULL)
        s->info_callback(s, SSL_CB_READ_ALERT, alert);

    if (s->ctx->info_callback != NULL)
        s->ctx->info_callback(s, SSL_CB_READ_ALERT, alert);

    switch (alert_data[0]) {
    case SSL3_AL_WARNING:
        s->s3->warn_alert = alert_data[1];
        if (++s->rlayer.alert_count == MAX_WARN_ALERT_COUNT) {
            SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_PROCESS_ALERT,
                     SSL_R_TOO_MANY_WARN_ALERTS);
            return 0;
        }
        switch (alert_data[1]) {
        case SSL_AD_CLOSE_NOTIFY:
            if (cid != TLMSP_CONTEXT_CONTROL) {
                SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_PROCESS_ALERT,
                         SSL_R_INVALID_ALERT);
                return 0;
            }
            s->shutdown |= SSL_RECEIVED_SHUTDOWN;
            break;
        default:
            break;
        }
        break;
    case SSL3_AL_FATAL:
        s->rwstate = SSL_NOTHING;
        s->s3->fatal_alert = alert_data[1];
        SSLfatal(s, SSL_AD_NO_ALERT, SSL_F_TLMSP_PROCESS_ALERT,
                 SSL_AD_REASON_OFFSET + alert_data[1]);
        BIO_snprintf(alert_number, sizeof alert_number, "%u", alert_data[1]);
        BIO_snprintf(context_number, sizeof context_number, "%u", cid);
        ERR_add_error_data(4, "TLMSP context ", context_number, " alert number ", alert_number);
        s->shutdown |= SSL_RECEIVED_SHUTDOWN;
        SSL_CTX_remove_session(s->session_ctx, s->session);
        break;
    default:
        SSLfatal(s, SSL_AD_UNEXPECTED_MESSAGE, SSL_F_TLMSP_PROCESS_ALERT,
                 SSL_R_INVALID_ALERT);
        return 0;
    }

    return 1;
}

int
tlmsp_alert_code(int code)
{
    switch (code) {
    case TLMSP_AD_MIDDLEBOX_ROUTE_FAILURE:
        return TLMSP_AD_MIDDLEBOX_ROUTE_FAILURE;
    case TLMSP_AD_MIDDLEBOX_AUTHORIZATION_FAILURE:
        return TLMSP_AD_MIDDLEBOX_AUTHORIZATION_FAILURE;
    case TLMSP_AD_MIDDLEBOX_REQUIRED:
        return TLMSP_AD_MIDDLEBOX_REQUIRED;
    case TLMSP_AD_DISCOVERY_ACK:
        return TLMSP_AD_DISCOVERY_ACK;
    case TLMSP_AD_UNKNOWN_CONTEXT:
        return TLMSP_AD_UNKNOWN_CONTEXT;
    case TLMSP_AD_UNSUPPORTED_CONTEXT:
        return TLMSP_AD_UNSUPPORTED_CONTEXT;
    case TLMSP_AD_MIDDLEBOX_KEY_VERIFY_FAILURE:
        return TLMSP_AD_MIDDLEBOX_KEY_VERIFY_FAILURE;
    case TLMSP_AD_BAD_READER_MAC:
        return TLMSP_AD_BAD_READER_MAC;
    case TLMSP_AD_BAD_WRITER_MAC:
        return TLMSP_AD_BAD_WRITER_MAC;
    case TLMSP_AD_MIDDLEBOX_KEYCONFIRMATION_FAULT:
        return TLMSP_AD_MIDDLEBOX_KEYCONFIRMATION_FAULT;
    case TLMSP_AD_AUTHENTICATION_REQUIRED:
        return TLMSP_AD_AUTHENTICATION_REQUIRED;
    default:
        return tls1_alert_code(code);
    }
}

/* Local functions.  */

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
