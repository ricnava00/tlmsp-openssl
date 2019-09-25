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

static int tlmsp_construct_bignum(SSL *, WPACKET *, const BIGNUM *);
static int tlmsp_process_bignum(SSL *, PACKET *, BIGNUM **);

static int tlmsp_construct_curve_point(SSL *, WPACKET *, int, EVP_PKEY *);
static int tlmsp_process_curve_point(SSL *, PACKET *, int *, EVP_PKEY *);

static int tlmsp_construct_key_material_contribution(SSL *, WPACKET *, int, unsigned, TLMSP_MiddleboxInstance *);
static int tlmsp_process_key_material_contribution(SSL *, PACKET *, int, unsigned, TLMSP_MiddleboxInstance *);

static int tlmsp_construct_server_key_exchange(SSL *, WPACKET *, EVP_PKEY **);

int
tlmsp_process_certificate(SSL *s, PACKET *pkt, STACK_OF(X509) **cert_chainp)
{
    const unsigned char *certbytes;
    PACKET chain, certdata;
    X509 *cert;

    if (!PACKET_get_length_prefixed_3(pkt, &chain)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (PACKET_remaining(&chain) == 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                 SSL_R_LENGTH_MISMATCH);
        return 0;
    }

    if (*cert_chainp != NULL) {
        sk_X509_pop_free(*cert_chainp, X509_free);
        *cert_chainp = NULL;
    }
    *cert_chainp = sk_X509_new_null();
    if (*cert_chainp == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    while (PACKET_remaining(&chain) != 0) {
        if (!PACKET_get_length_prefixed_3(&chain, &certdata)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                     SSL_R_LENGTH_MISMATCH);
            return 0;
        }

        certbytes = PACKET_data(&certdata);
        cert = d2i_X509(NULL, &certbytes, PACKET_remaining(&certdata));
        if (cert == NULL) {
            SSLfatal(s, SSL_AD_BAD_CERTIFICATE, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                     ERR_R_ASN1_LIB);
            return 0;
        }
        if (!PACKET_forward(&certdata, certbytes - PACKET_data(&certdata)) ||
            PACKET_remaining(&certdata) != 0) {
            X509_free(cert);
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                     SSL_R_CERT_LENGTH_MISMATCH);
            return 0;
        }

        if (!sk_X509_push(*cert_chainp, cert)) {
            X509_free(cert);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CERTIFICATE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

int
tlmsp_process_client_key_exchange(SSL *s, PACKET *pkt, TLMSP_MiddleboxInstance *tmis, EVP_PKEY **pubkeyp)
{
    EVP_PKEY *pkey;
    int type;

    type = s->s3->tmp.new_cipher->algorithm_mkey;

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CLIENT_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (s->tlmsp.middlebox_other_ssl == NULL ||
        s->tlmsp.middlebox_other_ssl->tlmsp.kex_from_peer == NULL ||
        !EVP_PKEY_copy_parameters(pkey, s->tlmsp.middlebox_other_ssl->tlmsp.kex_from_peer)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CLIENT_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((type & SSL_kDHE) != 0) {
        BIGNUM *Yc;
        DH *dh;

        if (!tlmsp_process_bignum(s, pkt, &Yc)) {
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CLIENT_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        dh = EVP_PKEY_get0_DH(pkey);
        if (dh == NULL) {
            BN_free(Yc);
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CLIENT_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (!DH_set0_key(dh, NULL, Yc)) {
            BN_free(Yc);
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CLIENT_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else if ((type & SSL_kECDHE) != 0) {
        if (!tlmsp_process_curve_point(s, pkt, NULL, pkey)) {
            SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_PROCESS_CLIENT_KEY_EXCHANGE,
                     SSL_R_BAD_ECPOINT);
            return 0;
        }
    } else {
        fprintf(stderr, "%s: unsupported key exchange method: %x.\n", __func__, type);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_CLIENT_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    *pubkeyp = pkey;

    return 1;
}

int
tlmsp_process_server_key_exchange(SSL *s, PACKET *pkt, TLMSP_MiddleboxInstance *tmis, EVP_PKEY **pubkeyp)
{
    const uint8_t *a_random, *b_random;
    const SIGALG_LOOKUP *lu;
    PACKET signature;
    unsigned int sigalg;
    const uint8_t *params;
    size_t paramslen;
    EVP_PKEY *pkey;
    EVP_PKEY *signkey;
    EVP_MD_CTX *md_ctx;
    EVP_PKEY_CTX *pctx;
    const EVP_MD *md;
    X509 *cert;
    int type;

    type = s->s3->tmp.new_cipher->algorithm_mkey;

    /*
     * TLMSP key exchanges are always signed, and therefore always require a
     * certificate.
     */
    if (!tlmsp_middlebox_certificate(s, tmis, &cert)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (cert == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Keep a pointer to the start of the parameters for later extraction.  */
    params = PACKET_data(pkt);

    if ((type & SSL_kDHE) != 0) {
        BIGNUM *p, *g, *Ys;
        DH *dh;

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
    } else if ((type & SSL_kECDHE) != 0) {
        int curvenid;

        if (!tlmsp_process_curve_point(s, pkt, &curvenid, NULL)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        pkey = ssl_generate_param_group(curvenid);
        if (pkey == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                     SSL_R_UNABLE_TO_FIND_ECDH_PARAMETERS);
            return 0;
        }

        if (!tlmsp_process_curve_point(s, pkt, NULL, pkey)) {
            SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                     SSL_R_BAD_ECPOINT);
            return 0;
        }
    } else {
        fprintf(stderr, "%s: unsupported key exchange method: %x.\n", __func__, type);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Now that we have processed the parameters which will be included in the signed
     * data, we can mark their end for later verification.
     */
    paramslen = PACKET_data(pkt) - params;

    /*
     * Now decode the signature for verification.
     */
    if (!PACKET_get_net_2(pkt, &sigalg) ||
        !PACKET_get_length_prefixed_2(pkt, &signature)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Check that this sigalg is appropriate for our peer's certificate key.
     */
    signkey = X509_get0_pubkey(cert);
    if (tls12_check_peer_sigalg(s, sigalg, signkey) <= 0) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    lu = s->s3->tmp.peer_sigalg;
    if (lu == NULL || !tls1_lookup_md(lu, &md)) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Endpoints only send a Random in one direction, so we use the other
     * endpoint's Random for the corresponding value.  So if this is a
     * middlebox, we use the to-client and to-server randoms, and otherwise we
     * use the actual ClientRandom and ServerRandom.
     */
    if (!TLMSP_MIDDLEBOX_ID_ENDPOINT(tmis->state.id)) {
        a_random = tmis->to_client_random;
        b_random = tmis->to_server_random;
    } else {
        const TLMSP_MiddleboxInstance *other;

        switch (tmis->state.id) {
        case TLMSP_MIDDLEBOX_ID_CLIENT:
            a_random = tmis->to_server_random;
            b_random = NULL;
            other = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_SERVER);
            break;
        case TLMSP_MIDDLEBOX_ID_SERVER:
            a_random = NULL;
            b_random = tmis->to_client_random;
            other = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_CLIENT);
            break;
        default:
            abort();
        }
        if (other == NULL) {
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (a_random == NULL)
            a_random = other->to_server_random;
        if (b_random == NULL)
            b_random = other->to_client_random;
    }

    /*
     * Set up our digest and verify operation.
     */
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_DigestVerifyInit(md_ctx, &pctx, md, NULL, signkey) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (lu->sig == EVP_PKEY_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * XXX
     * Needs 'hash' parameter for TLMSPServerKeyExchange.
     *
     * XXX
     * The construction of the to-be-signed data here should be shared with the
     * construct case.
     */
    if (EVP_DigestVerifyUpdate(md_ctx, a_random, SSL3_RANDOM_SIZE) <= 0 ||
        EVP_DigestVerifyUpdate(md_ctx, b_random, SSL3_RANDOM_SIZE) <= 0 ||
        EVP_DigestVerifyUpdate(md_ctx, params, paramslen) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_DigestVerifyFinal(md_ctx, PACKET_data(&signature), PACKET_remaining(&signature)) <= 0) {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    EVP_MD_CTX_free(md_ctx);

    /* The signature has been verified, proceed.  */

    *pubkeyp = pkey;

    return 1;
}

int
tlmsp_construct_middlebox_hello(SSL *s, WPACKET *pkt)
{
    if (RAND_priv_bytes(s->tlmsp.self->to_client_random, sizeof s->tlmsp.self->to_client_random) <= 0 ||
        RAND_priv_bytes(s->tlmsp.self->to_server_random, sizeof s->tlmsp.self->to_server_random) <= 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self->state.id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u16(pkt, TLMSP_TLS_VERSION(s->version))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_memcpy(pkt, s->tlmsp.self->to_client_random, sizeof s->tlmsp.self->to_client_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_memcpy(pkt, s->tlmsp.self->to_server_random, sizeof s->tlmsp.self->to_server_random)) {
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
    TLMSP_MiddleboxInstance *tmis;
    unsigned int client_version;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL || tmis == s->tlmsp.self) {
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

    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self->state.id) ||
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
    TLMSP_MiddleboxInstance *tmis;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_CERT,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL || tmis == s->tlmsp.self) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_CERT,
                 SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if (!tlmsp_process_certificate(s, pkt, &tmis->cert_chain)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_CERT,
                 SSL_R_LENGTH_MISMATCH);
        return MSG_PROCESS_ERROR;
    }

    if (!tlmsp_middlebox_verify_certificate(s, tmis)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_CERT,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_key_exchange(SSL *s, WPACKET *pkt)
{
    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self->state.id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* XXX Renegotiate.  */
    if (s->tlmsp.self->to_client_pkey != NULL || s->tlmsp.self->to_server_pkey != NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_construct_server_key_exchange(s, pkt, &s->tlmsp.self->to_client_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!tlmsp_construct_server_key_exchange(s, pkt, &s->tlmsp.self->to_server_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_key_exchange(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL || tmis == s->tlmsp.self) {
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

    if (!tlmsp_process_server_key_exchange(s, pkt, tmis, &tmis->to_client_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!tlmsp_process_server_key_exchange(s, pkt, tmis, &tmis->to_server_pkey)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_hello_done(SSL *s, WPACKET *pkt)
{
    if (!WPACKET_put_bytes_u8(pkt, s->tlmsp.self->state.id))
        return 0;
    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_hello_done(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_HELLO_DONE,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL || tmis == s->tlmsp.self) {
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
    if (s->server || tmis != tlmsp_middlebox_first(s))
        return MSG_PROCESS_CONTINUE_READING;

    return MSG_PROCESS_FINISHED_READING;
}

int
tlmsp_construct_middlebox_key_material(SSL *s, WPACKET *pkt)
{
    TLMSP_MiddleboxInstance *dst;
    unsigned contrib;

    switch (s->tlmsp.self->state.id) {
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
    if (s->tlmsp.next_middlebox_key_material_middlebox == NULL) {
        if (!tlmsp_context_generate_contributions(s, contrib)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (TLMSP_HAVE_MIDDLEBOXES(s))
            s->tlmsp.next_middlebox_key_material_middlebox = tlmsp_middlebox_first(s);
        else
            s->tlmsp.next_middlebox_key_material_middlebox = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    }
    dst = s->tlmsp.next_middlebox_key_material_middlebox;

    if (dst == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_construct_key_material_contribution(s, pkt, 0, contrib, dst)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (s->tlmsp.next_middlebox_key_material_middlebox != tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s))) {
        /*
         * We were not sending the final MiddleboxKeyMaterial, which is the one
         * which is sent to our peer.  Send to the next middlebox, and if there
         * is not one, to our peer.
         */
        s->tlmsp.next_middlebox_key_material_middlebox = tlmsp_middlebox_next(s, dst);
        if (s->tlmsp.next_middlebox_key_material_middlebox == NULL) {
            s->tlmsp.next_middlebox_key_material_middlebox = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
        }
    } else {
        /*
         * When we have sent all of the KeyMaterialContributions we need to send,
         * this becomes 0.
         */
        s->tlmsp.send_middlebox_key_material = 0;
        s->tlmsp.next_middlebox_key_material_middlebox = NULL;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_key_material(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *src;
    unsigned contrib;
    unsigned int id;

    switch (TLMSP_MIDDLEBOX_ID_PEER(s)) {
    case TLMSP_MIDDLEBOX_ID_SERVER:
        contrib = TLMSP_CONTRIBUTION_SERVER;
        src = &s->tlmsp.server_middlebox;
        break;
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        contrib = TLMSP_CONTRIBUTION_CLIENT;
        src = &s->tlmsp.client_middlebox;
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * The message should be meant for us.  If it is not, there is only one
     * possibility, which is that we are an endpoint and have received a
     * MiddleboxKeyMaterial which was not properly transformed by a middlebox
     * into a MiddleboxKeyConfirmation message.  This is a fatal error.
     *
     * XXX
     * We need to use the alert specified by the spec.
     */
    if (!PACKET_peek_1(pkt, &id) || id != s->tlmsp.self->state.id) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    if (!tlmsp_process_key_material_contribution(s, pkt, 0, contrib, src)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * If we are an endpoint, the MiddleboxKeyMaterial destined for us comes at
     * the end of the volley of MiddleboxKeyConfirmation messages.  We can now
     * verify each middlebox's MiddleboxKeyConfirmation messages against this
     * MiddleboxKeyMaterial.
     */
    if (!TLMSP_IS_MIDDLEBOX(s)) {
        unsigned int j;
        size_t keylen;

        keylen = tlmsp_key_size(s);

        for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
            const struct tlmsp_context_contributions *mkc, *mkm;
            const struct tlmsp_context_confirmation *confirm;
            const struct tlmsp_context_instance_state *tcis;
            const TLMSP_MiddleboxInstance *tmis;
            tlmsp_context_id_t cid;

            cid = j;

            tcis = &s->tlmsp.context_states[cid];
            if (!tcis->state.present)
                continue;
            mkm = &tcis->key_block.contributions[contrib];

            for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
                 tmis = tlmsp_middlebox_next(s, tmis)) {
                confirm = TLMSP_ContextConfirmationTable_lookup(&tmis->confirmations, cid);
                if (confirm == NULL) {
                    TLMSPfatal(s, TLMSP_AD_MIDDLEBOX_KEYCONFIRMATION_FAULT, TLMSP_CONTEXT_CONTROL,
                               SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                               SSL_R_TLMSP_ALERT_MIDDLEBOX_KEY_VERIFY_FAILURE);
                    return MSG_PROCESS_ERROR;
                }
                mkc = &confirm->contributions[contrib];

                if (cid == TLMSP_CONTEXT_CONTROL) {
                    if (CRYPTO_memcmp(mkm->synch, mkc->synch, keylen) != 0) {
                        TLMSPfatal(s, TLMSP_AD_MIDDLEBOX_KEYCONFIRMATION_FAULT, TLMSP_CONTEXT_CONTROL,
                                   SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                                   SSL_R_TLMSP_ALERT_MIDDLEBOX_KEY_VERIFY_FAILURE);
                        return MSG_PROCESS_ERROR;
                    }
                }

                if (tlmsp_context_access(s, cid, TLMSP_CONTEXT_AUTH_READ, tmis)) {
                    if (CRYPTO_memcmp(mkm->reader, mkc->reader, keylen) != 0) {
                        TLMSPfatal(s, TLMSP_AD_MIDDLEBOX_KEYCONFIRMATION_FAULT, TLMSP_CONTEXT_CONTROL,
                                   SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                                   SSL_R_TLMSP_ALERT_MIDDLEBOX_KEY_VERIFY_FAILURE);
                        return MSG_PROCESS_ERROR;
                    }
                }

                if (tlmsp_context_access(s, cid, TLMSP_CONTEXT_AUTH_WRITE, tmis)) {
                    if (CRYPTO_memcmp(mkm->writer, mkc->writer, keylen) != 0) {
                        TLMSPfatal(s, TLMSP_AD_MIDDLEBOX_KEYCONFIRMATION_FAULT, TLMSP_CONTEXT_CONTROL,
                                   SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_MATERIAL,
                                   SSL_R_TLMSP_ALERT_MIDDLEBOX_KEY_VERIFY_FAILURE);
                        return MSG_PROCESS_ERROR;
                    }
                }
            }
        }

        /*
         * If we are the client, this is the last round of
         * MiddleboxKeyConfirmation and MiddleboxKeyMaterial messages we will
         * see for this handshake.
         *
         * We can go ahead and clear out the confirmation tables, which are
         * quite large.
         */
        if (s->tlmsp.self->state.id == TLMSP_MIDDLEBOX_ID_CLIENT) {
            TLMSP_MiddleboxInstance *tmis;

            for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
                 tmis = tlmsp_middlebox_next(s, tmis)) {
                TLMSP_ContextConfirmationTable_free(&tmis->confirmations);
            }
        }
    }

    /*
     * Now we are either a middlebox which has received a MiddleboxKeyMaterial
     * meant for us and turned it into a MiddleboxKeyConfirmation, or we are
     * an endpoint which has received a MiddleboxKeyMaterial and is finished
     * processing it.
     *
     * If we are an endpoint, we now move on to writing; in the server case
     * this will be a series of MiddleboxKeyMaterial messages of our own, and
     * in the client case this will be ChangeCipherSpec.
     */
    if (!TLMSP_IS_MIDDLEBOX(s))
        return MSG_PROCESS_FINISHED_READING;

    /*
     * We continue reading if we are a middlebox.
     */
    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_key_confirmation(SSL *s, WPACKET *pkt)
{
    TLMSP_MiddleboxInstance *dst;
    unsigned contrib;

    /*
     * The MiddleboxKeyConfirmation continues on to its ultimate
     * destination, away from the peer of this half of the middlebox.
     */
    switch (TLMSP_MIDDLEBOX_ID_PEER(s)) {
    case TLMSP_MIDDLEBOX_ID_SERVER:
        contrib = TLMSP_CONTRIBUTION_SERVER;
        dst = &s->tlmsp.client_middlebox;
        break;
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        contrib = TLMSP_CONTRIBUTION_CLIENT;
        dst = &s->tlmsp.server_middlebox;
        break;
    default:
        abort();
    }

    if (!tlmsp_construct_key_material_contribution(s, pkt, 1, contrib, dst)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_key_confirmation(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis;
    unsigned contrib;
    unsigned int id;

    switch (TLMSP_MIDDLEBOX_ID_PEER(s)) {
    case TLMSP_MIDDLEBOX_ID_SERVER:
        contrib = TLMSP_CONTRIBUTION_SERVER;
        break;
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        contrib = TLMSP_CONTRIBUTION_CLIENT;
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    /*
     * Get the id of the middlebox confirming its keys.  It must not be an
     * endpoint.
     */
    if (!PACKET_peek_1(pkt, &id) || TLMSP_MIDDLEBOX_ID_ENDPOINT(id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    if (!tlmsp_process_key_material_contribution(s, pkt, 1, contrib, tmis)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_KEY_CONFIRMATION,
                 ERR_R_INTERNAL_ERROR);
        return MSG_PROCESS_ERROR;
    }

    return MSG_PROCESS_CONTINUE_READING;
}

int
tlmsp_construct_middlebox_finished(SSL *s, WPACKET *pkt)
{
    TLMSP_MiddleboxInstance *dst, *next;

    if (s->tlmsp.next_middlebox_finished_middlebox == NULL) {
        if (!TLMSP_HAVE_MIDDLEBOXES(s)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_FINISHED,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->tlmsp.next_middlebox_finished_middlebox = tlmsp_middlebox_first(s);
    }
    dst = s->tlmsp.next_middlebox_finished_middlebox;

    if (dst == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(pkt, dst->state.id) ||
        !tlmsp_finish_construct(s, dst, pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    next = tlmsp_middlebox_next(s, dst);
    if (next != NULL) {
        /*
         * We were not sending the final MiddleboxFinished, which is the one
         * which is sent to the last middlebox.
         */
        s->tlmsp.next_middlebox_finished_middlebox = next;
    } else {
        /*
         * When we have sent all of the MiddleboxFinisheds we need to send,
         * this becomes 0.
         */
        s->tlmsp.send_middlebox_finished = 0;
        s->tlmsp.next_middlebox_finished_middlebox = NULL;
    }

    return 1;
}

MSG_PROCESS_RETURN
tlmsp_process_middlebox_finished(SSL *s, PACKET *pkt)
{
    TLMSP_MiddleboxInstance *tmis;
    unsigned int id;

    if (!PACKET_get_1(pkt, &id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_finish_verify(s, tmis, PACKET_data(pkt), PACKET_remaining(pkt))) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_MIDDLEBOX_FINISHED,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If this is the last middlebox, we are finished reading, and are done
     * with the handshake, in fact.
     */
    if (tlmsp_middlebox_next(s, tmis) == NULL) {
        /* XXX TLS_ST_OK?  */
        return MSG_PROCESS_FINISHED_READING;
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
tlmsp_construct_curve_point(SSL *s, WPACKET *pkt, int curve, EVP_PKEY *pkey)
{
    /*
     * Construct ECParameters if we are sending a curve.
     */
    if (curve != 0) {
        if (!WPACKET_put_bytes_u8(pkt, NAMED_CURVE_TYPE) ||
            !WPACKET_put_bytes_u16(pkt, curve))
            return 0;
    }

    /*
     * Construct ECPoint if we are sending a point.
     */
    if (pkey != NULL) {
        unsigned char *point;
        size_t pointlen;

        /*
         * Get encoded point.
         */
        pointlen = EVP_PKEY_get1_tls_encodedpoint(pkey, &point);
        if (pointlen == 0)
            return 0;

        if (!WPACKET_sub_memcpy_u8(pkt, point, pointlen)) {
            OPENSSL_free(point);
            return 0;
        }

        OPENSSL_free(point);
    }

    return 1;
}

static int
tlmsp_process_curve_point(SSL *s, PACKET *pkt, int *curvep, EVP_PKEY *pkey)
{
    /*
     * Process ECParameters if we are receiving a curve.
     */
    if (curvep != NULL) {
        unsigned int curve_type, named_curve;

        if (!PACKET_get_1(pkt, &curve_type))
            return 0;

        switch (curve_type) {
        case NAMED_CURVE_TYPE:
            if (!PACKET_get_net_2(pkt, &named_curve))
                return 0;
            /* XXX SSL_R_WRONG_CURVE */
            if (!tls1_check_group_id(s, named_curve, 1))
                return 0;
            *curvep = named_curve;
            break;
        default:
            return 0;
        }
    }

    /*
     * Process ECPoint if we are receiving a point.
     */
    if (pkey != NULL) {
        PACKET point;

        if (!PACKET_get_length_prefixed_1(pkt, &point))
            return 0;

        if (!EVP_PKEY_set1_tls_encodedpoint(pkey, PACKET_data(&point), PACKET_remaining(&point)))
            return 0;
    }

    return 1;
}

static int
tlmsp_construct_key_material_contribution(SSL *src_ssl, WPACKET *pkt, int confirmation, unsigned contrib, TLMSP_MiddleboxInstance *dst)
{
    TLMSP_MiddleboxInstance *authmbox;
    uint8_t nonce[EVP_MAX_IV_LENGTH];
    uint8_t mac[EVP_MAX_MD_SIZE];
    struct tlmsp_envelope env;
    struct tlmsp_data td;
    SSL *authssl, *dst_ssl;
    const void *aad;
    size_t mac_size;
    size_t aadlen;
    size_t eivlen;
    size_t keylen;
    WPACKET cpkt;
    size_t clen;
    unsigned j;

    /*
     * If this is a MiddleboxKeyConfirmation, we are actually encrypting it to
     * target the other SSL.
     *
     * Likewise, if we are sending a confirmation, we are reporting on our own
     * authorization, not on the dst endpoint's, while when sending key
     * material we are authorizing the destination.
     */
    if (confirmation) {
        authssl = src_ssl;
        dst_ssl = src_ssl->tlmsp.middlebox_other_ssl;
        authmbox = src_ssl->tlmsp.self;

        /*
         * We want to find the instance associated with the destination
         * middlebox on the destination SSL, which is where the encryption keys
         * will be located.
         */
        dst = tlmsp_middlebox_lookup(dst_ssl, dst->state.id);
        if (dst == NULL) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        authssl = src_ssl;
        dst_ssl = src_ssl;
        authmbox = dst;
    }

    /*
     * Set up the envelope for our eventual encryption.
     */
    TLMSP_ENVELOPE_INIT_SSL_WRITE(&env, TLMSP_CONTEXT_CONTROL, dst_ssl);
    env.keys = TLMSP_KEY_SET_ADVANCE;
    env.dst = dst->state.id;

    eivlen = tlmsp_eiv_size(dst_ssl, &env);
    keylen = tlmsp_key_size(dst_ssl);
    mac_size = tlmsp_reader_mac_size(dst_ssl, &env);

    /*
     * Setup advance keys for sending to the destination.
     */
    if (!tlmsp_setup_advance_keys(dst_ssl, dst)) {
        SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_init_static_len(&cpkt, dst_ssl->tlmsp.key_material_contribution_buffer, sizeof dst_ssl->tlmsp.key_material_contribution_buffer, 0)) {
        SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * For a MiddleboxKeyMaterial, place the destination ID.  For
     * MiddleboxKeyContribution, the source.
     */
    if (!WPACKET_put_bytes_u8(&cpkt, confirmation ? env.src : env.dst)) {
        SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Set the explicit IV.
     */
    if (eivlen != 0) {
        if (!tlmsp_generate_nonce(dst_ssl, dst_ssl->tlmsp.self, nonce, eivlen)) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (!WPACKET_memcpy(&cpkt, nonce, eivlen)) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
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

        tcis = &src_ssl->tlmsp.context_states[j];
        if (!tcis->state.present)
            continue;
        tcc = &tcis->key_block.contributions[contrib];

        if (!WPACKET_put_bytes_u8(&cpkt, j)) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (j == TLMSP_CONTEXT_CONTROL) {
            kcdata = tcc->synch;
            kclen = keylen;
            if (!WPACKET_memcpy(&cpkt, kcdata, kclen)) {
                SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        kcdata = NULL;
        kclen = 0;
        if (tlmsp_context_access(authssl, j, TLMSP_CONTEXT_AUTH_READ, authmbox)) {
            kcdata = tcc->reader;
            kclen = keylen;
        }
        if (!WPACKET_sub_memcpy_u8(&cpkt, kcdata, kclen)) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        kcdata = NULL;
        kclen = 0;
        if (tlmsp_context_access(authssl, j, TLMSP_CONTEXT_AUTH_WRITE, authmbox)) {
            kcdata = tcc->writer;
            kclen = keylen;
        }
        if (!WPACKET_sub_memcpy_u8(&cpkt, kcdata, kclen)) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!WPACKET_finish(&cpkt) ||
        !WPACKET_get_total_written(&cpkt, &clen)) {
        SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Now encrypt (and authenticate, if not using AEAD) the contributions.
     */
    if (tlmsp_want_aad(dst_ssl, &env)) {
        /*
         * In AAD mode, we are additionally authenticating the middlebox ID and
         * the explicit IV (nonce.)
         */
        aad = dst_ssl->tlmsp.key_material_contribution_buffer;
        aadlen = 1 + eivlen;
    } else {
        /*
         * Generate an explicit MAC.  We do MAC-then-Encrypt only.
         */
        if (!tlmsp_mac(dst_ssl, &env, TLMSP_MAC_KEY_MATERIAL_CONTRIBUTION, NULL, dst_ssl->tlmsp.key_material_contribution_buffer, clen, mac)) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (clen + mac_size > sizeof dst_ssl->tlmsp.key_material_contribution_buffer) {
            SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        memcpy(dst_ssl->tlmsp.key_material_contribution_buffer + clen, mac, mac_size);
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
    td.data = dst_ssl->tlmsp.key_material_contribution_buffer + 1;
    td.length = clen - 1;

    if (!tlmsp_enc(dst_ssl, &env, TLMSP_ENC_KEY_MATERIAL, &td, aad, aadlen)) {
        SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (td.data != dst_ssl->tlmsp.key_material_contribution_buffer + 1) {
        SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    td.data--;
    td.length++;

    /*
     * Now output our encrypted and authenticated message.
     */
    if (!WPACKET_memcpy(pkt, td.data, td.length)) {
        SSLfatal(src_ssl, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_process_key_material_contribution(SSL *s, PACKET *pkt, int confirmation, unsigned contrib, TLMSP_MiddleboxInstance *src)
{
    uint8_t mac[EVP_MAX_MD_SIZE];
    struct tlmsp_envelope env;
    struct tlmsp_data td;
    const void *aad;
    size_t mac_size;
    size_t aadlen;
    size_t eivlen;
    size_t keylen;
    PACKET cpkt;
    size_t clen;

    TLMSP_ENVELOPE_INIT_SSL_READ(&env, TLMSP_CONTEXT_CONTROL, s);
    env.keys = TLMSP_KEY_SET_ADVANCE;
    env.src = src->state.id;

    eivlen = tlmsp_eiv_size(s, &env);
    keylen = tlmsp_key_size(s);
    mac_size = tlmsp_reader_mac_size(s, &env);

    /*
     * Provision advance keys for talking to the source.
     */
    if (!tlmsp_setup_advance_keys(s, src)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * First, the id will have been checked by the caller.  It may be
     * authenticated but not encrypted, and the authentication would be
     * verified here.
     *
     * Second, verify that this is big enough, but not bigger than the maximum.
     */
    clen = PACKET_remaining(pkt);
    if (clen <= 1 + eivlen + mac_size) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (clen >= sizeof s->tlmsp.key_material_contribution_buffer) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (!PACKET_copy_bytes(pkt, s->tlmsp.key_material_contribution_buffer, clen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
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
    td.data = s->tlmsp.key_material_contribution_buffer + 1;
    td.length = clen - 1;

    if (!tlmsp_enc(s, &env, TLMSP_ENC_KEY_MATERIAL, &td, aad, aadlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If we are not using AEAD, we must back up and compute a MAC which covers
     * the entire buffer, including middlebox ID and explicit IV, but not
     * including the MAC.
     *
     * We verify the MAC and remove it, the middlebox ID, and the explicit IV
     */
    if (!tlmsp_want_aad(s, &env)) {
        if (td.data != s->tlmsp.key_material_contribution_buffer + 1 + eivlen) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        td.data = s->tlmsp.key_material_contribution_buffer;
        td.length += 1 + eivlen;

        if (!tlmsp_mac(s, &env, TLMSP_MAC_KEY_MATERIAL_CONTRIBUTION, NULL, td.data, td.length - mac_size, mac)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (CRYPTO_memcmp(td.data + td.length - mac_size, mac, mac_size) != 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        td.data += 1 + eivlen;
        td.length -= 1 + eivlen + mac_size;
    }

    /*
     * Now set up a packet structure to use for decoding.
     */
    if (!PACKET_buf_init(&cpkt, td.data, td.length)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Now decode the packet and handle its contributions if they're meant for
     * us.
     */
    while (PACKET_remaining(&cpkt) != 0) {
        struct tlmsp_context_instance_state *tcis;
        struct tlmsp_context_contributions *tcc;
        PACKET contribution;
        unsigned int cid;

        if (!PACKET_get_1(&cpkt, &cid)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        tcis = &s->tlmsp.context_states[cid];
        if (!tcis->state.present) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (confirmation) {
            struct tlmsp_context_confirmation *confirm;

            confirm = TLMSP_ContextConfirmationTable_lookup(&src->confirmations, cid);
            if (confirm == NULL) {
                confirm = TLMSP_ContextConfirmationTable_insert(&src->confirmations, cid);
                if (confirm == NULL) {
                    SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                             ERR_R_INTERNAL_ERROR);
                    return 0;
                }
            }
            tcc = &confirm->contributions[contrib];
        } else {
            tcc = &tcis->key_block.contributions[contrib];
        }

        if (cid == TLMSP_CONTEXT_CONTROL) {
            if (!PACKET_copy_bytes(&cpkt, tcc->synch, keylen)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        if (!PACKET_get_length_prefixed_1(&cpkt, &contribution)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * XXX
         * What we should do for all of these contributions is check that what
         * is granted (or confirmed) matches our expectations via
         * context_access().
         */
        if (PACKET_remaining(&contribution) == 0) {
            /* We have not been granted reader access to this context.  */
        } else {
            /* We have been granted reader access to this context.  */
            if (!PACKET_copy_bytes(&contribution, tcc->reader, keylen) ||
                PACKET_remaining(&contribution) != 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        if (!PACKET_get_length_prefixed_1(&cpkt, &contribution)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (PACKET_remaining(&contribution) == 0) {
            /* We have not been granted writer access to this context.  */
        } else {
            /* We have been granted writer access to this context.  */
            if (!PACKET_copy_bytes(&contribution, tcc->writer, keylen) ||
                PACKET_remaining(&contribution) != 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PROCESS_KEY_MATERIAL_CONTRIBUTION,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }

    return 1;
}

static int
tlmsp_construct_server_key_exchange(SSL *s, WPACKET *pkt, EVP_PKEY **privkeyp)
{
    const SIGALG_LOOKUP *lu;
    const EVP_MD *md;
    WPACKET params;
    EVP_MD_CTX *md_ctx;
    EVP_PKEY_CTX *pctx;
    EVP_PKEY *pkey;
    EVP_PKEY *signkey;
    size_t paramslen;
    int type;
    size_t siglen;
    uint8_t *sigbytes1, *sigbytes2;

    type = s->s3->tmp.new_cipher->algorithm_mkey;
    signkey = s->s3->tmp.cert->privatekey;

    lu = s->s3->tmp.sigalg;
    if (lu == NULL || !tls1_lookup_md(lu, &md)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Set up a WPACKET to hold our parameters.
     */
    if (!WPACKET_init_static_len(&params, s->tlmsp.middlebox_signed_params_buffer, sizeof s->tlmsp.middlebox_signed_params_buffer, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Establish our ephemeral key for the key exchange.
     */
    if ((type & SSL_kDHE) != 0) {
        const BIGNUM *p, *g, *Ys;
        EVP_PKEY *pkdh;
        const DH *dh;
        DH *dhp;

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

        if (!tlmsp_construct_bignum(s, &params, p) ||
            !tlmsp_construct_bignum(s, &params, g) ||
            !tlmsp_construct_bignum(s, &params, Ys)) {
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else if ((type & SSL_kECDHE) != 0) {
        int curvenid;

        curvenid = tls1_shared_group(s->tlmsp.middlebox_other_ssl, -2);
        if (curvenid == 0) {
            SSLfatal(s, SSL_AD_HANDSHAKE_FAILURE, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                     SSL_R_UNSUPPORTED_ELLIPTIC_CURVE);
            return 0;
        }

        pkey = ssl_generate_pkey_group(s, curvenid);
        if (pkey == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (!tlmsp_construct_curve_point(s, &params, curvenid, pkey)) {
            EVP_PKEY_free(pkey);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        fprintf(stderr, "%s: unsupported key exchange method: %x.\n", __func__, type);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Now that we have the key parameters to be signed, move towards signing.
     */
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

    /*
     * XXX
     * Needs 'hash' parameter for TLMSPServerKeyExchange.
     *
     * XXX
     * The construction of the to-be-signed data here should be shared with the
     * process case.
     *
     * We also need to make good use of middlebox_signed_params_buffer there.
     */
    if (EVP_DigestSignUpdate(md_ctx, s->tlmsp.self->to_client_random, sizeof s->tlmsp.self->to_client_random) <= 0 ||
        EVP_DigestSignUpdate(md_ctx, s->tlmsp.self->to_server_random, sizeof s->tlmsp.self->to_server_random) <= 0 ||
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

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
