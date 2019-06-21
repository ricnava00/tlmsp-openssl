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
 * XXX TODO XXX
 *
 * For the Hackathon, we are restricted in the following ways:
 *
 * We will only generate a key exchange using ephemeral Diffie-Hellman signed
 * with an RSA key.
 *
 * We are not verifying certificates or signatures.
 *
 * MiddleboxKeyConfirmation is empty and ignored.
 *
 * MiddleboxFin is left completely absent.
 */

static int tlmsp_construct_bignum(SSL *, WPACKET *, const BIGNUM *);
static int tlmsp_process_bignum(SSL *, PACKET *, BIGNUM **);
static int tlmsp_construct_server_key_exchange(SSL *, WPACKET *, EVP_PKEY **);
static int tlmsp_process_server_key_exchange(SSL *, PACKET *, EVP_PKEY **);

int
tlmsp_construct_middlebox_hello(SSL *s, WPACKET *pkt)
{
    struct tlmsp_middlebox_instance_state *tmis;

    tmis = &s->tlmsp.middlebox_states[s->tlmsp.self_id];

    if (RAND_priv_bytes(tmis->to_client_random, sizeof tmis->to_client_random) <= 0 ||
        RAND_priv_bytes(tmis->to_server_random, sizeof tmis->to_server_random) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self_id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLMSP_TLS_VERSION(s->version))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_memcpy(pkt, tmis->to_client_random, sizeof tmis->to_client_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_memcpy(pkt, tmis->to_server_random, sizeof tmis->to_server_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* session_id */
    if (!WPACKET_sub_memcpy_u8(pkt, NULL, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* cipher_suites */
    if (!WPACKET_sub_memcpy_u16(pkt, NULL, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* compression_methods */
    if (!WPACKET_sub_memcpy_u8(pkt, NULL, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* No extensions presently.  */

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_hello(SSL *s, PACKET *pkt)
{
    PACKET session_id, cipher_suites, compression_methods;
    struct tlmsp_middlebox_instance_state *tmis;
    unsigned int client_version;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = &s->tlmsp.middlebox_states[id];
    if (!tmis->state.present || id == s->tlmsp.self_id) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    if (!PACKET_get_net_2(pkt, &client_version) ||
        !PACKET_copy_bytes(pkt, tmis->to_client_random, sizeof tmis->to_client_random) ||
        !PACKET_copy_bytes(pkt, tmis->to_server_random, sizeof tmis->to_server_random) ||
        !PACKET_get_length_prefixed_1(pkt, &session_id) ||
        !PACKET_get_length_prefixed_2(pkt, &cipher_suites) ||
        !PACKET_get_length_prefixed_1(pkt, &compression_methods)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * XXX
     * What meaning these fields would have for a TLMSP middlebox has not yet
     * been defined.
     */
    if (PACKET_remaining(&session_id) != 0 ||
        PACKET_remaining(&cipher_suites) != 0 ||
        PACKET_remaining(&compression_methods) != 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * XXX
     * No extensions support as yet.
     */
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_cert(SSL *s, WPACKET *pkt)
{
    CERT_PKEY *cpk;

    cpk = s->s3->tmp.cert;
    if (cpk == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_CERT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self_id) ||
        !ssl3_output_cert_chain(s, pkt, cpk)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_CERT,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_cert(SSL *s, PACKET *pkt)
{
    fprintf(stderr, "%s: Hackathon: discarding middlebox certificate.\n", __func__);
    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_key_exchange(SSL *s, WPACKET *pkt)
{
    struct tlmsp_middlebox_instance_state *tmis;

    tmis = &s->tlmsp.middlebox_states[s->tlmsp.self_id];

    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self_id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* XXX Renegotiate.  */
    if (tmis->to_client_pkey != NULL || tmis->to_server_pkey != NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_construct_server_key_exchange(s, pkt, &tmis->to_client_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!tlmsp_construct_server_key_exchange(s, pkt, &tmis->to_server_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_key_exchange(SSL *s, PACKET *pkt)
{
    struct tlmsp_middlebox_instance_state *tmis;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = &s->tlmsp.middlebox_states[id];
    if (!tmis->state.present || id == s->tlmsp.self_id) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /* XXX Renegotiate.  */
    if (tmis->to_client_pkey != NULL || tmis->to_server_pkey != NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_process_server_key_exchange(s, pkt, &tmis->to_client_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!tlmsp_process_server_key_exchange(s, pkt, &tmis->to_server_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_hello_done(SSL *s, WPACKET *pkt)
{
    struct tlmsp_middlebox_instance_state *tmis;

    tmis = &s->tlmsp.middlebox_states[s->tlmsp.self_id];
    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self_id))
        return 0;
    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_hello_done(SSL *s, PACKET *pkt)
{
    struct tlmsp_middlebox_instance_state *tmis;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO_DONE,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = &s->tlmsp.middlebox_states[id];
    if (!tmis->state.present || id == s->tlmsp.self_id) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO_DONE,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * The server will keep reading after a MiddleboxHelloDone, to receive
     * either the next MiddleboxHello, or the ClientKeyExchange.
     *
     * In the client case, we read until we receive the final
     * MiddleboxHelloDone, which is from the middlebox closest to us (i.e. the
     * first middlebox.)  After that, we send CertificateMbox, or Certificate,
     * or ClientKeyExchange, depending on configuration.
     */
    if (s->server || id != tlmsp_middlebox_first(s))
        return MSG_PROCESS_CONTINUE_READING;

    return MSG_PROCESS_FINISHED_READING;
}

int
tlmsp_construct_middlebox_key_material(SSL *s, WPACKET *pkt)
{
    uint8_t nonce[EVP_MAX_IV_LENGTH];
    uint8_t mac[EVP_MAX_MD_SIZE];
    struct tlmsp_envelope env;
    struct tlmsp_buffer tb;
    unsigned contrib;
    const void *aad;
    size_t mac_size;
    size_t aadlen;
    size_t eivlen;
    size_t keylen;
    WPACKET cpkt;
    size_t clen;
    unsigned j;

    /*
     * Set up the envelope for our eventual encryption.
     */
    TLMSP_ENVELOPE_INIT_SSL_WRITE(&env, TLMSP_CONTEXT_CONTROL, s);
    env.keys = TLMSP_KEY_SET_ADVANCE;

    eivlen = tlmsp_eiv_size(s, &env);
    keylen = tlmsp_key_size(s);
    mac_size = tlmsp_reader_mac_size(s, &env);

    switch (s->tlmsp.self_id) {
    case TLMSP_MIDDLEBOX_ID_SERVER:
        contrib = TLMSP_CONTRIBUTION_SERVER;
        break;
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        contrib = TLMSP_CONTRIBUTION_CLIENT;
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * This is the first MiddleboxKeyMaterial we've produced, and as we are an
     * endpoint go through and generate our share of the key contributions
     * (which are per-context and the same for every middlebox.)  We then
     * select the real next middlebox and continue.
     *
     * The code goes through and sends the MiddleboxKeyMaterial to the next
     * middlebox, and sees if there are any more middleboxes to send to.  If
     * there are, we set next_middlebox_key_material to the next one.  If there
     * are not, we set next_middlebox_key_material back to
     * TLMSP_MIDDLEBOX_ID_NONE, and clear send_middlebox_key_material, which
     * tells the state machine to transition to the next state.
     *
     * XXX
     * Do this here if we are the client, and on last receive from the server,
     * so that client and server can, on last receive, derive keys.
     */
    if (s->tlmsp.next_middlebox_key_material_middlebox == TLMSP_MIDDLEBOX_ID_NONE) {
        for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
            struct tlmsp_context_instance_state *tcis;
            struct tlmsp_context_contributions *tcc;

            tcis = &s->tlmsp.context_states[j];
            if (!tcis->state.present)
                continue;
            tcc = &tcis->key_block.contributions[contrib];

            if (j == TLMSP_CONTEXT_CONTROL) {
                if (RAND_priv_bytes(tcc->synch, keylen) <= 0) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            }
            if (RAND_priv_bytes(tcc->reader, keylen) <= 0 ||
                RAND_priv_bytes(tcc->writer, keylen) <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        if (TLMSP_HAVE_MIDDLEBOXES(s))
            s->tlmsp.next_middlebox_key_material_middlebox = tlmsp_middlebox_first(s);
        else
            s->tlmsp.next_middlebox_key_material_middlebox = s->tlmsp.peer_id;
    }
    env.dst = s->tlmsp.next_middlebox_key_material_middlebox;

    /*
     * Setup advance keys for talking to this middlebox.
     */
    if (!tlmsp_setup_advance_keys(s, env.dst)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_init_static_len(&cpkt, s->tlmsp.key_material_contribution_buffer, sizeof s->tlmsp.key_material_contribution_buffer, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Place the middlebox ID at the start of the packet.
     */
    if (!WPACKET_put_bytes_u8(&cpkt, env.dst)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Set the explicit IV.
     */
    if (eivlen != 0) {
        if (!tlmsp_generate_nonce(s, s->tlmsp.self_id, nonce, eivlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!WPACKET_memcpy(&cpkt, nonce, eivlen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * Write each Contribution.
     */
    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        struct tlmsp_context_instance_state *tcis;
        struct tlmsp_context_contributions *tcc;
        const uint8_t *kcdata;
        size_t kclen;

        tcis = &s->tlmsp.context_states[j];
        if (!tcis->state.present)
            continue;
        tcc = &tcis->key_block.contributions[contrib];

        if (!WPACKET_put_bytes_u8(&cpkt, j)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (j == TLMSP_CONTEXT_CONTROL) {
            kcdata = NULL;
            kclen = 0;
            if (tlmsp_context_access(s, j, TLMSP_CONTEXT_AUTH_WRITE, env.dst)) {
                kcdata = tcc->synch;
                kclen = keylen;
            }
            if (!WPACKET_memcpy(&cpkt, kcdata, kclen)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        kcdata = NULL;
        kclen = 0;
        if (tlmsp_context_access(s, j, TLMSP_CONTEXT_AUTH_READ, env.dst)) {
            kcdata = tcc->reader;
            kclen = keylen;
        }
        if (!WPACKET_sub_memcpy_u8(&cpkt, kcdata, kclen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        kcdata = NULL;
        kclen = 0;
        if (tlmsp_context_access(s, j, TLMSP_CONTEXT_AUTH_WRITE, env.dst)) {
            kcdata = tcc->writer;
            kclen = keylen;
        }
        if (!WPACKET_sub_memcpy_u8(&cpkt, kcdata, kclen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!WPACKET_finish(&cpkt) ||
        !WPACKET_get_total_written(&cpkt, &clen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Now encrypt (and authenticate, if not using AEAD) the contributions.
     */
    if (tlmsp_want_aad(s, &env)) {
        /*
         * In AAD mode, we are additionally authenticating the middlebox ID and
         * the explicit IV (nonce.)
         */
        aad = s->tlmsp.key_material_contribution_buffer;
        aadlen = 1 + eivlen;
    } else {
        /*
         * Generate an explicit MAC.  We do MAC-then-Encrypt only.
         */
        if (!tlmsp_mac(s, &env, TLMSP_MAC_KEY_MATERIAL_CONTRIBUTION, NULL, s->tlmsp.key_material_contribution_buffer, clen, mac)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (clen + mac_size > sizeof s->tlmsp.key_material_contribution_buffer) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memcpy(s->tlmsp.key_material_contribution_buffer + clen, mac, mac_size);
        clen += mac_size;

        aad = NULL;
        aadlen = 0;
    }

    /*
     * Finally, do the encryption operation, covering everything except the middlebox ID.
     *
     * XXX
     * We need to check that clen + (tag or padding) can not exceed the size of our buffer.
     */
    tb.data = s->tlmsp.key_material_contribution_buffer + 1;
    tb.length = clen - 1;

    if (!tlmsp_enc(s, &env, TLMSP_ENC_KEY_MATERIAL, &tb, aad, aadlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (tb.data != s->tlmsp.key_material_contribution_buffer + 1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    tb.data--;
    tb.length++;

    /*
     * Now output our encrypted and authenticated message.
     */
    if (!WPACKET_memcpy(pkt, tb.data, tb.length)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (s->tlmsp.next_middlebox_key_material_middlebox != s->tlmsp.peer_id) {
        /*
         * We were not sending the final MiddleboxKeyMaterial, which is the one
         * which is sent to our peer.  Send to the next middlebox, and if there
         * is not one, to our peer.
         */
        s->tlmsp.next_middlebox_key_material_middlebox = tlmsp_middlebox_next(s, env.dst);
        if (s->tlmsp.next_middlebox_key_material_middlebox == TLMSP_MIDDLEBOX_ID_NONE) {
            s->tlmsp.next_middlebox_key_material_middlebox = s->tlmsp.peer_id;
        }
    } else {
        /*
         * When we have sent all of the KeyMaterialContributions we need to send,
         * this becomes 0.
         */
        s->tlmsp.send_middlebox_key_material = 0;
        s->tlmsp.next_middlebox_key_material_middlebox = TLMSP_MIDDLEBOX_ID_NONE;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_key_material(SSL *s, PACKET *pkt)
{
    uint8_t mac[EVP_MAX_MD_SIZE];
    struct tlmsp_envelope env;
    struct tlmsp_buffer tb;
    unsigned contrib;
    unsigned int id;
    const void *aad;
    size_t mac_size;
    size_t aadlen;
    size_t eivlen;
    size_t keylen;
    PACKET cpkt;
    size_t clen;

    TLMSP_ENVELOPE_INIT_SSL_READ(&env, TLMSP_CONTEXT_CONTROL, s);
    env.keys = TLMSP_KEY_SET_ADVANCE;

    eivlen = tlmsp_eiv_size(s, &env);
    keylen = tlmsp_key_size(s);
    mac_size = tlmsp_reader_mac_size(s, &env);

    switch (s->tlmsp.peer_id) {
    case TLMSP_MIDDLEBOX_ID_SERVER:
        contrib = TLMSP_CONTRIBUTION_SERVER;
        break;
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        contrib = TLMSP_CONTRIBUTION_CLIENT;
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * First, check if this message is meant for us.
     */
    if (!PACKET_peek_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }
    if (id != s->tlmsp.self_id) {
        /*
         * Not for us, move on.
         *
         * We always have more to read at this point, because the last
         * MiddleboxKeyMaterial we receive will be our own.  When we receive
         * our own, if there are no middleboxes, we switch to writing; if there
         * are middleboxes, we expect to start receiving
         * MiddleboxKeyConfirmation messages instead.
         *
         * Now, if we are a middlebox, we handle things a little differently.
         * If this is destined for an endpoint, it is the last MiddleboxKeyMaterial
         * message which is coming.
         *
         * If it is destined for the server, that means it has come from the
         * client.  If we are the first middlebox, tell the caller that we
         * should write, i.e. that we should start sending
         * MiddleboxKeyConfirmation messages.
         *
         * If it is destined for the client, and we are the last middlebox,
         * then we would do likewise.
         */
        if ((id == TLMSP_MIDDLEBOX_ID_SERVER &&
             s->tlmsp.self_id == tlmsp_middlebox_first(s)) ||
            (id == TLMSP_MIDDLEBOX_ID_CLIENT &&
             tlmsp_middlebox_next(s, s->tlmsp.self_id) == TLMSP_MIDDLEBOX_ID_NONE)) {
            return MSG_PROCESS_FINISHED_READING;
        }
        return MSG_PROCESS_CONTINUE_READING;
    }
    env.dst = id;

    /*
     * Provision advance keys for talking to this endpoint.
     */
    if (!tlmsp_setup_advance_keys(s, s->tlmsp.peer_id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * Second, verify that this is big enough, but not bigger than the maximum.
     */
    clen = PACKET_remaining(pkt);
    if (clen <= 1 + eivlen + mac_size) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }
    if (clen >= sizeof s->tlmsp.key_material_contribution_buffer) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }
    if (!PACKET_copy_bytes(pkt, s->tlmsp.key_material_contribution_buffer, clen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * Fourth, decrypt all of the contributions.
     */
    if (tlmsp_want_aad(s, &env)) {
        /*
         * In AAD mode, we are additionally authenticating the middlebox ID and
         * the explicit IV (nonce.)
         */
        aad = s->tlmsp.key_material_contribution_buffer;
        aadlen = 1 + eivlen;
    } else {
        aad = NULL;
        aadlen = 0;
    }

    /* We do not encrypt/decrypt the middlebox ID.  */
    tb.data = s->tlmsp.key_material_contribution_buffer + 1;
    tb.length = clen - 1;

    if (!tlmsp_enc(s, &env, TLMSP_ENC_KEY_MATERIAL, &tb, aad, aadlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * If we are not using AEAD, we must back up and compute a MAC which covers
     * the entire buffer, including middlebox ID and explicit IV, but not
     * including the MAC.
     *
     * We verify the MAC and remove it, the middlebox ID, and the explicit IV
     */
    if (!tlmsp_want_aad(s, &env)) {
        if (tb.data != s->tlmsp.key_material_contribution_buffer + 1 + eivlen) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }
        tb.data = s->tlmsp.key_material_contribution_buffer;
        tb.length += 1 + eivlen;

        if (!tlmsp_mac(s, &env, TLMSP_MAC_KEY_MATERIAL_CONTRIBUTION, NULL, tb.data, tb.length - mac_size, mac)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }

        if (memcmp(tb.data + tb.length - mac_size, mac, mac_size) != 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }
        tb.data += 1 + eivlen;
        tb.length -= 1 + eivlen + mac_size;
    }

    /*
     * Now set up a packet structure to use for decoding.
     */
    if (!PACKET_buf_init(&cpkt, tb.data, tb.length)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * Now decode the packet and handle its contributions if they're meant for
     * us.
     */
    while (PACKET_remaining(&cpkt) != 0) {
        struct tlmsp_context_instance_state *tcis;
        struct tlmsp_context_key_block *tckb;
        PACKET contribution;
        unsigned int cid;

        if (!PACKET_get_1(&cpkt, &cid)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }

        tcis = &s->tlmsp.context_states[cid];
        if (!tcis->state.present) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }
        tckb = &tcis->key_block;

        if (cid == 0) {
            if (!PACKET_copy_bytes(&cpkt, tckb->contributions[contrib].synch, keylen)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                         ERR_R_INTERNAL_ERROR);
                return MSG_PROCESS_ERROR;
            }
        }

        if (!PACKET_get_length_prefixed_1(&cpkt, &contribution)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }

        if (PACKET_remaining(&contribution) == 0) {
            /* We have not been granted reader access to this context.  */
            /* XXX TODO XXX */
        } else {
            /* We have been granted reader access to this context.  */
            /* XXX TODO XXX */
            if (!PACKET_copy_bytes(&contribution, tckb->contributions[contrib].reader, keylen) ||
                PACKET_remaining(&contribution) != 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                         ERR_R_INTERNAL_ERROR);
                return MSG_PROCESS_ERROR;
            }
        }

        if (!PACKET_get_length_prefixed_1(&cpkt, &contribution)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }

        if (PACKET_remaining(&contribution) == 0) {
            /* We have not been granted writer access to this context.  */
            /* XXX TODO XXX */
        } else {
            /* We have been granted writer access to this context.  */
            /* XXX TODO XXX */
            if (!PACKET_copy_bytes(&contribution, tckb->contributions[contrib].writer, keylen) ||
                PACKET_remaining(&contribution) != 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                         ERR_R_INTERNAL_ERROR);
                return MSG_PROCESS_ERROR;
            }
        }
    }

    /*
     * What we do after receiving a MiddleboxKeyMaterial message depends on
     * whether there are any middleboxes.
     *
     * If there are no middleboxes, then both the client and the server are
     * finished reading and move on to writing after receiving a
     * MiddleboxKeyMaterial message.
     *
     * In the case of the client, after the MiddleboxKeyMaterial message, we
     * send ChangeCipherSpec and move into the completion of this round of the
     * Handshake protocol.
     *
     * If we are the server, we send our own MiddleboxKeyMaterial to the client
     * instead.
     *
     * If there are middleboxes, however, each of those are delayed, and we
     * remain in the write state until the state machine pushes us to shift to
     * the next state due to receipt of a certain message.
     *
     * If we are the client, then we will receive KeyMaterialConfirmation
     * messages from the middleboxes; once we have received one from each
     * middlebox, we will again move from reading to writing, and continue with
     * ChangeCipherSpec as above.
     *
     * If we are the server, likewise we expect to receive
     * KeyMaterialConfirmation messages from the middleboxes between the client
     * and us, but unlike the client we remain in the read state, to await the
     * client's ChangeCipherSpec.
     *
     * Middleboxes?         Client          Server
     * No                   Write           Write
     * Yes                  Read            Read
     */

    /*
     * If there are no middleboxes, we are done reading.
     */
    if (!TLMSP_HAVE_MIDDLEBOXES(s))
        return MSG_PROCESS_FINISHED_READING;

    /*
     * There are middleboxes.  We continue to read MiddleboxKeyMaterial, or the
     * state machine will transition us to reading MiddleboxKeyConfirmation
     * when appropriate.
     */
    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_key_confirmation(SSL *s, WPACKET *pkt)
{
    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self_id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_key_confirmation(SSL *s, PACKET *pkt)
{
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * If we are the client or the server, we switch to writing if this message
     * is from the middlebox nearest us, i.e. the first middlebox if we are the
     * client, and the last middlebox if we are the server.
     *
     * If we are, however, a middlebox, we instead go by the direction the
     * message is travelling.  If our peer (i.e. the direction we are reading
     * from) is the client, then we write if we are the next middlebox after
     * this id.  If our peer is the server, we write if this id is the next
     * middlebox after us.
     */
    switch (s->tlmsp.self_id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        if (id == tlmsp_middlebox_first(s))
            return MSG_PROCESS_FINISHED_READING;
        break;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        if (tlmsp_middlebox_next(s, id) == TLMSP_MIDDLEBOX_ID_NONE)
            return MSG_PROCESS_FINISHED_READING;
        break;
    default:
        switch (s->tlmsp.peer_id) {
        case TLMSP_MIDDLEBOX_ID_CLIENT:
            if (tlmsp_middlebox_next(s, id) == s->tlmsp.self_id)
                return MSG_PROCESS_FINISHED_READING;
            break;
        case TLMSP_MIDDLEBOX_ID_SERVER:
            if (tlmsp_middlebox_next(s, s->tlmsp.self_id) == id)
                return MSG_PROCESS_FINISHED_READING;
            break;
        default:
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_CONFIRMATION,
                     ERR_R_INTERNAL_ERROR);
            return MSG_PROCESS_ERROR;
        }
        break;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

/* Local functions.  */

static int
tlmsp_construct_bignum(SSL *s, WPACKET *pkt, const BIGNUM *bn)
{
    uint8_t *binval;
    size_t bytes;

    bytes = BN_num_bytes(bn);
    if (!WPACKET_sub_allocate_bytes_u16(pkt, bytes, &binval))
        return 0;
    BN_bn2bin(bn, binval);
    return 1;
}

static int
tlmsp_process_bignum(SSL *s, PACKET *pkt, BIGNUM **bnp)
{
    PACKET bin;
    BIGNUM *bn;

    if (!PACKET_get_length_prefixed_2(pkt, &bin))
        return 0;
    bn = BN_bin2bn(PACKET_data(&bin), PACKET_remaining(&bin), NULL);
    if (bn == NULL)
        return 0;
    *bnp = bn;
    return 1;
}

static int
tlmsp_construct_server_key_exchange(SSL *s, WPACKET *pkt, EVP_PKEY **privkeyp)
{
    const struct tlmsp_middlebox_instance_state *tmis;
    const BIGNUM *p, *g, *Ys;
    const SIGALG_LOOKUP *lu;
    const EVP_MD *md;
    WPACKET params;
    EVP_MD_CTX *md_ctx;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkdh;
    EVP_PKEY *pkey;
    EVP_PKEY *signkey;
    size_t paramslen;
    int type;
    DH *dhp;
    size_t siglen;
    const DH *dh;
    uint8_t *sigbytes1, *sigbytes2;

    tmis = &s->tlmsp.middlebox_states[s->tlmsp.self_id];
    type = s->s3->tmp.new_cipher->algorithm_mkey;
    signkey = s->s3->tmp.cert->privatekey;

    /*
     * XXX
     * For now we are only using this scheme.
     *
     * We need to parse the ClientHello's extensions and pick a suitable sigalg
     * as a result.
     */
    lu = tls1_lookup_sigalg(TLSEXT_SIGALG_rsa_pss_rsae_sha256);
    if (lu == NULL || !tls1_lookup_md(lu, &md)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * XXX
     * For now we are only supporting DHE.
     */
    if ((type & SSL_kDHE) == 0) {
        fprintf(stderr, "%s: middleboxes currently require DHE key exchange.\n", __func__);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * XXX
     * For now we are only supporting RSA keys for signing.
     */
    if (EVP_PKEY_base_id(signkey) != EVP_PKEY_RSA) {
        fprintf(stderr, "%s: middleboxes currently require RSA keys for signing.\n", __func__);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    dhp = ssl_get_auto_dh(s);
    if (dhp == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pkdh = EVP_PKEY_new();
    if (pkdh == NULL) {
        DH_free(dhp);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_PKEY_assign_DH(pkdh, dhp);

    pkey = ssl_generate_pkey(pkdh);
    if (pkey == NULL) {
        EVP_PKEY_free(pkdh);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_PKEY_free(pkdh);

    dh = EVP_PKEY_get0_DH(pkey);
    if (dh == NULL) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    DH_get0_pqg(dh, &p, NULL, &g);
    DH_get0_key(dh, &Ys, NULL);

    if (!WPACKET_init_static_len(&params, s->tlmsp.middlebox_signed_params_buffer, sizeof s->tlmsp.middlebox_signed_params_buffer, 0)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_construct_bignum(s, &params, p) ||
        !tlmsp_construct_bignum(s, &params, g) ||
        !tlmsp_construct_bignum(s, &params, Ys)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_finish(&params) ||
        !WPACKET_get_total_written(&params, &paramslen)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Place the parameters into the message.
     */
    if (!WPACKET_memcpy(pkt, s->tlmsp.middlebox_signed_params_buffer, paramslen)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Place the signature algorithm.
     */
    if (!WPACKET_put_bytes_u16(pkt, lu->sigalg)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Set up our digest and sign operation.
     */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_DigestSignInit(md_ctx, &pctx, md, NULL, signkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (lu->sig == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (EVP_DigestSignUpdate(md_ctx, tmis->to_client_random, sizeof tmis->to_client_random) <= 0 ||
        EVP_DigestSignUpdate(md_ctx, tmis->to_server_random, sizeof tmis->to_server_random) <= 0 ||
        EVP_DigestSignUpdate(md_ctx, s->tlmsp.middlebox_signed_params_buffer, paramslen) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_DigestSignFinal(md_ctx, NULL, &siglen) <= 0 ||
        !WPACKET_sub_reserve_bytes_u16(pkt, siglen, &sigbytes1) ||
        EVP_DigestSignFinal(md_ctx, sigbytes1, &siglen) <= 0 ||
        !WPACKET_sub_allocate_bytes_u16(pkt, siglen, &sigbytes2) ||
        sigbytes1 != sigbytes2) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_MD_CTX_free(md_ctx);

    *privkeyp = pkey;

    return 1;
}

/*
 * XXX
 * Will need to take the middlebox certificate as a parameter.
 */
static int
tlmsp_process_server_key_exchange(SSL *s, PACKET *pkt, EVP_PKEY **pubkeyp)
{
    BIGNUM *p, *g, *Ys;
    PACKET signature;
    unsigned int sigalg;
    EVP_PKEY *pkey;
    DH *dh;
    int type;

    type = s->s3->tmp.new_cipher->algorithm_mkey;

    /*
     * XXX
     * For now we are only supporting DHE.
     */
    if ((type & SSL_kDHE) == 0) {
        fprintf(stderr, "%s: middleboxes currently require DHE key exchange.\n", __func__);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    p = NULL;
    g = NULL;
    Ys = NULL;
    if (!tlmsp_process_bignum(s, pkt, &p) ||
        !tlmsp_process_bignum(s, pkt, &g) ||
        !tlmsp_process_bignum(s, pkt, &Ys)) {
        BN_free(Ys);
        BN_free(g);
        BN_free(p);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_net_2(pkt, &sigalg) ||
        sigalg != TLSEXT_SIGALG_rsa_pss_rsae_sha256 ||
        !PACKET_get_length_prefixed_2(pkt, &signature)) {
        BN_free(Ys);
        BN_free(g);
        BN_free(p);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    dh = DH_new();
    if (dh == NULL) {
        BN_free(Ys);
        BN_free(g);
        BN_free(p);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(Ys);
        BN_free(g);
        BN_free(p);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!DH_set0_key(dh, Ys, NULL)) {
        DH_free(dh);
        BN_free(Ys);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        DH_free(dh);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!EVP_PKEY_assign_DH(pkey, dh)) {
        EVP_PKEY_free(pkey);
        DH_free(dh);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    *pubkeyp = pkey;

    return 1;
}
