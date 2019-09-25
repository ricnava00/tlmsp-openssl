/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#include "internal/constant_time_locl.h"
#include "internal/cryptlib.h"
#include "ssl_locl.h"
#include "record/record_locl.h"
#include "statem/statem_locl.h"
#include <openssl/rand.h>
#include <openssl/tlmsp.h>

#define MAX_PADDING 256

/*
 * Values from Annex A.
 */
#define TLMSP_GCM_EXPLICIT_IV_LENGTH            (12)

#define TLMSP_CBC_EXPLICIT_IV_LENGTH            (16)

#if 0
#define TLMSP_CTR_EXPLICIT_IV_LENGTH            (12)
#endif

/*
 * Encryption and MAC local functions.
 */
static int tlmsp_record_enc(SSL *, SSL3_RECORD *, size_t, int);
static int tlmsp_record_mac(SSL *, SSL3_RECORD *, unsigned char *, int);
static size_t tlmsp_pad(void *, size_t, size_t);
static int tlmsp_prf_hash(EVP_MD_CTX *, const EVP_MD *, EVP_PKEY *, const uint8_t *, const struct tlmsp_input_data *, size_t, uint8_t *, size_t);

static SSL3_ENC_METHOD const TLMSPv1_0_enc_data = {
    tlmsp_record_enc,
    tlmsp_record_mac,
    tlmsp_setup_key_block,
    tlmsp_generate_master_secret,
    tlmsp_change_cipher_state,
    tls1_final_finish_mac,
    TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE,
    TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
    tlmsp_alert_code,
    tls1_export_keying_material,
    SSL_ENC_FLAG_EXPLICIT_IV | SSL_ENC_FLAG_SIGALGS | SSL_ENC_FLAG_SHA256_PRF
        | SSL_ENC_FLAG_TLS1_2_CIPHERS | SSL_ENC_FLAG_TLMSP,
    ssl3_set_handshake_header,
    tls_close_construct_packet,
    ssl3_handshake_write
};

/*
 * Version-generic methods.
 */
IMPLEMENT_tlmsp_meth_func(TLMSP_ANY_VERSION, 0, 0,
                          TLMSP_method,
                          ossl_statem_accept,
                          ossl_statem_connect, TLMSPv1_0_enc_data)
IMPLEMENT_tlmsp_meth_func(TLMSP_ANY_VERSION, 0, 0,
                          TLMSP_server_method,
                          ossl_statem_accept,
                          ssl_undefined_function, TLMSPv1_0_enc_data)
IMPLEMENT_tlmsp_meth_func(TLMSP_ANY_VERSION, 0, 0,
                          TLMSP_client_method,
                          ssl_undefined_function,
                          ossl_statem_connect, TLMSPv1_0_enc_data)
IMPLEMENT_tlmsp_meth_func(TLMSP_ANY_VERSION, SSL_METHOD_MIDDLEBOX, 0,
                          TLMSP_middlebox_method,
                          tlmsp_middlebox_accept,
                          tlmsp_middlebox_connect, TLMSPv1_0_enc_data)

/*
 * Version-specific methods.
 */
IMPLEMENT_tlmsp_meth_func(TLMSP1_0_VERSION, 0, 0,
                          tlmspv1_0_method,
                          ossl_statem_accept,
                          ossl_statem_connect, TLMSPv1_0_enc_data)
IMPLEMENT_tlmsp_meth_func(TLMSP1_0_VERSION, 0, 0,
                          tlmspv1_0_server_method,
                          ossl_statem_accept,
                          ssl_undefined_function, TLMSPv1_0_enc_data)
IMPLEMENT_tlmsp_meth_func(TLMSP1_0_VERSION, 0, 0,
                          tlmspv1_0_client_method,
                          ssl_undefined_function,
                          ossl_statem_connect, TLMSPv1_0_enc_data)
#if 0
IMPLEMENT_tlmsp_meth_func(TLMSP1_0_VERSION, SSL_METHOD_MIDDLEBOX, 0,
                          tlmspv1_0_middlebox_method,
                          ossl_statem_accept,
                          ossl_statem_connect, TLMSPv1_0_enc_data)
#endif

/* API functions.  */

/* Internal functions.  */

int
tlmsp_enc(SSL *s, const struct tlmsp_envelope *env, enum tlmsp_enc_kind kind, struct tlmsp_data *td, const void *aad, size_t aadlen)
{
    const EVP_CIPHER *enc;
    EVP_CIPHER_CTX *ds;
    const uint8_t *key;
    int cbc_mode;
    size_t eivlen;
    size_t mac_size;
    size_t bs;
    size_t taglen;
    int clen, fclen;
    int rv;

    ds = tlmsp_cipher_context(s, env, &enc);
    if (ds == NULL || enc == NULL)
        return 1;

    /*
     * For most things we use the same context reader keys; we use A-to-B keys
     * for KeyContributionMessage.
     */
    switch (kind) {
    case TLMSP_ENC_CONTAINER:
    case TLMSP_ENC_RECORD:
        key = tlmsp_key(s, env, TLMSP_KEY_C_READER_ENC);
        break;
    case TLMSP_ENC_KEY_MATERIAL:
        key = tlmsp_key(s, env, TLMSP_KEY_A_B_ENC);
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
            ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (key == NULL) {
        /*
         * If we have an active cipher, we must have a key.
         */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    cbc_mode = EVP_CIPHER_mode(enc) == EVP_CIPH_CBC_MODE;
    /* XXX - does CBC-mode specific work remain that will use this or is this unneeded going forward? */
    (void)cbc_mode;

    bs = tlmsp_block_size(s, env);
    eivlen = tlmsp_eiv_size(s, env);
    mac_size = tlmsp_reader_mac_size(s, env);
    taglen = tlmsp_tag_size(s, env);

    if (eivlen == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * We require the caller to have already placed the explicit IV.
     */

    /*
     * If we are using AAD with AEAD, we must follow this path.
     */
    if (tlmsp_want_aad(s, env)) {
        if (aad == NULL || aadlen == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * Set up the cipher.
         */
        rv = EVP_CipherInit_ex(ds, enc, NULL, key, NULL, TLMSP_ENVELOPE_SENDING(env));
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        rv = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_USE_IV_VERBATIM, eivlen, td->data);
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * If we are not the source, do receive processing.
         */
        if (!TLMSP_ENVELOPE_SENDING(env)) {
            /*
             * Extract tag from end of data.
             */
            td->length -= taglen;
            rv = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_SET_TAG, taglen, td->data + td->length);
            if (rv <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        /*
         * Process AAD.
         */
        rv = EVP_CipherUpdate(ds, NULL, &clen, aad, aadlen);
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return rv;
        }

        /*
         * Cipher data.
         */
        rv = EVP_CipherUpdate(ds, td->data + eivlen, &clen, td->data + eivlen, td->length - eivlen);
        if (rv <= 0)
            return -1;

        /*
         * Finish the cipher operation.
         */
        rv = EVP_CipherFinal_ex(ds, td->data + eivlen + clen, &fclen);
        if (rv <= 0)
            return -1;

        if ((size_t)(eivlen + clen + fclen) != td->length) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }

        /*
         * If we are sending this packet, we need to append the tag also.
         */
        if (TLMSP_ENVELOPE_SENDING(env)) {
            /*
             * Append tag to data.
             */
            rv = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_GET_TAG, taglen, td->data + td->length);
            if (rv <= 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            td->length += taglen;
        }
    } else {
        /* Using a simple block cipher.  */

        if (aad != NULL && aadlen != 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * Pad out the input when sending.
         */
        if (bs != 1 && TLMSP_ENVELOPE_SENDING(env)) {
            td->length = eivlen + tlmsp_pad(td->data + eivlen, td->length - eivlen, bs);
            if (td->length == 0) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        if (td->length <= eivlen || (td->length - eivlen) % bs != 0)
            return 0;

        /*
         * Set up the cipher, IV is in td->data.
         */
        rv = EVP_CipherInit_ex(ds, enc, NULL, key, td->data, TLMSP_ENVELOPE_SENDING(env));
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * We handle padding ourselves.
         */
        rv = EVP_CIPHER_CTX_set_padding(ds, 0);
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * Cipher data.
         */
        rv = EVP_CipherUpdate(ds, td->data + eivlen, &clen, td->data + eivlen, td->length - eivlen);
        if (rv <= 0)
            return -1;

        if ((size_t)(eivlen + clen) != td->length) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_ENC,
                     ERR_R_INTERNAL_ERROR);
            return -1;
        }
    }

    /*
     * If we are not the sender, do receive processing.
     */
    if (!TLMSP_ENVELOPE_SENDING(env)) {
        /*
         * Strip off explicit IV.
         */
        td->data += eivlen;
        td->length -= eivlen;

        if (bs != 1) {
            SSL3_RECORD rr;

            if (SSL_READ_ETM(s))
                mac_size = 0;

            /*
             * We only use this for tls1_cbc_remove_padding, so only initialize
             * these fields.
             */
            rr.data = rr.input = td->data;
            rr.length = td->length;

            /*
             * Remove CBC-style padding.
             */
            rv = tls1_cbc_remove_padding(s, &rr, bs, mac_size);
            /*
             * If rv == 0 then this means publicly invalid so we can short
             * circuit things here. Otherwise we must respect constant time
             * behaviour.
             */
            if (rv == 0)
                return 0;
            if (constant_time_select_int(constant_time_eq_int(rv, 1), 1, -1) == -1)
                return -1;

            td->length = rr.length;
        }
    }

    return 1;
}

int
tlmsp_mac(SSL *s, const struct tlmsp_envelope *env, enum tlmsp_mac_kind kind, const void *nonce, const void *mac_input, size_t mac_inputlen, void *macp)
{
    enum tlmsp_key_kind kk;
    const uint8_t *key;

    switch (kind) {
    case TLMSP_MAC_CHECK:
        kk = TLMSP_KEY_A_B_MAC;
        break;
    case TLMSP_MAC_READER_CHECK:
        kk = TLMSP_KEY_SYNCH_MAC;
        break;
    case TLMSP_MAC_KEY_MATERIAL_CONTRIBUTION:
        kk = TLMSP_KEY_A_B_MAC;
        break;
    case TLMSP_MAC_READER:
        kk = TLMSP_KEY_C_READER_MAC;
        break;
    case TLMSP_MAC_WRITER:
        kk = TLMSP_KEY_C_WRITER_MAC;
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    key = tlmsp_key(s, env, kk);
    if (key == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (tlmsp_want_aad(s, env)) {
        const EVP_CIPHER *enc;
        EVP_CIPHER_CTX *ds;
        size_t eivlen;
        size_t taglen;
        int clen;
        int rv;

        eivlen = tlmsp_eiv_size(s, env);
        taglen = tlmsp_tag_size(s, env);

        ds = tlmsp_cipher_context(s, env, &enc);

        if (ds == NULL || enc == NULL || key == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        rv = EVP_CipherInit_ex(ds, enc, NULL, key, NULL, TLMSP_ENVELOPE_SENDING(env));
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        rv = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_USE_IV_VERBATIM, eivlen, (void *)(uintptr_t)nonce);
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * Process MAC_INPUT as AAD.
         */
        rv = EVP_CipherUpdate(ds, NULL, &clen, mac_input, mac_inputlen);
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return rv;
        }

        /* NB: No CipherFinal_ex when doing GMAC, we just generate the tag from the AAD.  */

        /*
         * Generate the tag.
         */
        rv = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TAG_GEN, taglen, macp);
        if (rv <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        return 1;
    } else {
        const EVP_MD_CTX *hash;
        const EVP_MD *md;
        EVP_MD_CTX *ctx;
        EVP_PKEY *pkey;
        size_t maclen;
        size_t keylen;

        keylen = tlmsp_key_size(s);

        hash = tlmsp_hash_context(s, env, &md);
        if (hash == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, keylen);
        if (pkey == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        ctx = EVP_MD_CTX_new();
        if (ctx == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(pkey);
            return 0;
        }

        EVP_PKEY_free(pkey);

        /*
         * XXX
         * Should we follow tls1_mac's lead and use ssl3_cbc_digest_record in
         * the CBC and MAC-then-Encrypt case so we don't leak timing details?
         */

        if (EVP_DigestSign(ctx, macp, &maclen, mac_input, mac_inputlen) <= 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_MAC,
                     ERR_R_INTERNAL_ERROR);
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        EVP_MD_CTX_free(ctx);

        return 1;
    }
}

int
tlmsp_hash(SSL *s, const void *d, size_t dlen, void *hash, size_t *hashlenp)
{
    const EVP_MD *hashmd;
    unsigned hashlen;

    hashmd = ssl_prf_md(s);
    if (hashmd == NULL)
        return 0;

    if (EVP_Digest(d, dlen, hash, &hashlen, hashmd, NULL) <= 0)
        return 0;

    *hashlenp = hashlen;

    return 1;
}

/*
 * We cannot use the tls1_PRF function or the underlying TLS PRF implementation
 * in libcrypto because that caps seed data at 1KB, which we can very easily
 * exceed for some of the PRF parameters used in TLMSP.  As such, we just
 * implement the PRF algorithm here, and use an input vector to capture the
 * parameters we care about.
 */
int
tlmsp_prf(SSL *s, const struct tlmsp_input_data *secret, const struct tlmsp_input_data *bufs, size_t bufcnt, unsigned char *out, size_t outsize)
{
    uint8_t lastai[EVP_MAX_MD_SIZE];
    const EVP_MD *hashmd;
    EVP_MD_CTX *ctx;
    size_t hashlen;
    EVP_PKEY *pkey;

    hashmd = ssl_prf_md(s);
    if (hashmd == NULL)
        return 0;

    hashlen = EVP_MD_size(hashmd);
    if (hashlen == 0)
        return 0;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return 0;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, secret->data, secret->length);
    if (pkey == NULL) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    /*
     * Compute A(1).
     */
    if (!tlmsp_prf_hash(ctx, hashmd, pkey, NULL, bufs, bufcnt, lastai, hashlen)) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    for (;;) {
        /*
         * Generate output.
         */
        if (!tlmsp_prf_hash(ctx, hashmd, pkey, lastai, bufs, bufcnt, out, outsize)) {
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(ctx);
            return 0;
        }

        if (hashlen >= outsize)
            break;
        out += hashlen;
        outsize -= hashlen;

        /*
         * Compute A(n).
         */
        if (!tlmsp_prf_hash(ctx, hashmd, pkey, lastai, bufs, bufcnt, lastai, hashlen)) {
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(ctx);
            return 0;
        }
    }

    /* XXX Should we cleanse lastai?  */

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);

    return 1;
}

int
tlmsp_prf_init(SSL *s, const char *label)
{
    if (s->tlmsp.prf_input_count != 0)
        return 0;
    if (label == NULL) {
        struct tlmsp_input_data *tid;

        /*
         * This is a special case for creating a template input to the PRF
         * which will be used with multiple labels for multiple expansions via
         * tlmsp_prf_save and tlmsp_prf_reinit.
         *
         * tlmsp_prf_save must be called and then tlmsp_prf_reinit must be
         * called to set a label.
         */
        tid = &s->tlmsp.prf_input[0];
        tid->data = NULL;
        tid->length = 0;
        s->tlmsp.prf_input_count = 1;
        return 1;
    }
    return tlmsp_prf_update(s, label, strlen(label));
}

int
tlmsp_prf_update(SSL *s, const void *seed, size_t seedlen)
{
    struct tlmsp_input_data *tid;

    if (seed == NULL || seedlen == 0)
        return 0;
    if (s->tlmsp.prf_input_count == TLMSP_MAX_PRF_INPUTS)
        return 0;
    tid = &s->tlmsp.prf_input[s->tlmsp.prf_input_count++];
    tid->data = seed;
    tid->length = seedlen;
    return 1;
}

int
tlmsp_prf_finish(SSL *s, const void *secret, size_t secretlen, unsigned char *out, size_t outsize)
{
    struct tlmsp_input_data sec;

    if (s->tlmsp.prf_input_count == 0)
        return 0;

    sec.data = secret;
    sec.length = secretlen;

    if (!tlmsp_prf(s, &sec, s->tlmsp.prf_input, s->tlmsp.prf_input_count, out, outsize))
        return 0;

    s->tlmsp.prf_input_count = 0;

    return 1;
}

int
tlmsp_prf_save(SSL *s, size_t *countp)
{
    const struct tlmsp_input_data *label;

    if (s->tlmsp.prf_input_count == 0)
        return 0;
    label = &s->tlmsp.prf_input[0];
    if (label->data != NULL || label->length != 0)
        return 0;
    *countp = s->tlmsp.prf_input_count;
    s->tlmsp.prf_input_count = 0;
    return 1;
}

int
tlmsp_prf_reinit(SSL *s, const char *label, size_t count)
{
    if (label == NULL || strlen(label) == 0)
        return 0;
    if (count == 0 || count > TLMSP_MAX_PRF_INPUTS)
        return 0;
    if (s->tlmsp.prf_input_count != 0)
        return 0;
    if (!tlmsp_prf_init(s, label))
        return 0;
    /*
     * Expand to include previously-established seed template.
     */
    if (count != 1)
        s->tlmsp.prf_input_count = count;
    return 1;
}

/*
 * For now we do not have a mechanism for forwarding context 0 records without
 * totally rewriting them, so we do not have to look into the IV to figure out
 * the author -- we simply assume that all context 0 records originate with
 * our peer.
 */
tlmsp_middlebox_id_t
tlmsp_record_author(SSL *s, const void *r, size_t dlen)
{
    return TLMSP_MIDDLEBOX_ID_PEER(s);
}

/*
 * Returns 1 if this is a message which is treated as implicitly belonging to
 * context 0, which is handled using TLS 1.2-style cryptography.
 */
int
tlmsp_record_context0(const SSL *s, int rt)
{
    if (!SSL_IS_TLMSP(s))
        return -1;

    switch (rt) {
    case SSL3_RT_ALERT:
        if (s->tlmsp.alert_container) {
            /*
             * Once we know (or have informed the client) that the server
             * supports TLMSP, we containerize alerts.
             *
             * Prior to that, alerts go through normal TLS 1.2 formatting.
             */
            return 0;
        }
        return 1;
    case SSL3_RT_APPLICATION_DATA:
        /* Application data is always containerized.  */
        return 0;
    case SSL3_RT_CHANGE_CIPHER_SPEC:
    case SSL3_RT_HANDSHAKE:
        /* Handshake and ChangeCipherSpec are always TLS 1.2 style.  */
        return 1;
    default:
        /*
         * This message type is not part of TLMSP.
         */
        return -1;
    }
}

EVP_CIPHER_CTX *
tlmsp_cipher_context(const SSL *s, const struct tlmsp_envelope *env, const EVP_CIPHER **cipherp)
{
    if (!tlmsp_cipher_suite(s, env, cipherp, NULL))
        return NULL;

    if (TLMSP_ENVELOPE_SENDING(env)) {
        return s->enc_write_ctx;
    } else {
        return s->enc_read_ctx;
    }
}

int
tlmsp_cipher_suite(const SSL *s, const struct tlmsp_envelope *env, const EVP_CIPHER **cipherp, const EVP_MD **mdp)
{
    const EVP_CIPHER *cipher;
    const EVP_MD *md;

    if (cipherp == NULL && mdp == NULL)
        return 0;

    if (cipherp == NULL)
        cipherp = &cipher;
    if (mdp == NULL)
        mdp = &md;

    if (env->keys == TLMSP_KEY_SET_NORMAL) {
        if (TLMSP_ENVELOPE_SENDING(env)) {
            *cipherp = s->tlmsp.write_cipher;
            *mdp = s->tlmsp.write_md;
        } else {
            *cipherp = s->tlmsp.read_cipher;
            *mdp = s->tlmsp.read_md;
        }
        return 1;
    }

    return ssl_cipher_to_evp(TLMSP_TLS_VERSION(s->version), s->s3->tmp.new_cipher, 0, cipherp, mdp, NULL, NULL, NULL, s->ext.use_etm);
}

const EVP_MD_CTX *
tlmsp_hash_context(const SSL *s, const struct tlmsp_envelope *env, const EVP_MD **mdp)
{
    if (!tlmsp_cipher_suite(s, env, NULL, mdp))
        return NULL;

    if (TLMSP_ENVELOPE_SENDING(env)) {
        return s->write_hash;
    } else {
        return s->read_hash;
    }
}

size_t
tlmsp_block_size(const SSL *s, const struct tlmsp_envelope *env)
{
    const EVP_CIPHER_CTX *ds;
    const EVP_CIPHER *enc;
    int bs;

    ds = tlmsp_cipher_context(s, env, &enc);
    if (ds == NULL || enc == NULL)
        return 0;

    bs = EVP_CIPHER_block_size(enc);
    if (bs <= 0)
        return 0;

    return (size_t)bs;
}

size_t
tlmsp_reader_mac_size(const SSL *s, const struct tlmsp_envelope *env)
{
    const EVP_CIPHER_CTX *ds;
    const EVP_CIPHER *enc;
    const EVP_MD_CTX *hash;
    const EVP_MD *md;
    int mac_size;

    ds = tlmsp_cipher_context(s, env, &enc);
    hash = tlmsp_hash_context(s, env, &md);

    /*
     * Get MAC size parameters.
     */
    if (ds == NULL || enc == NULL || hash == NULL || md == NULL) {
        return 0;
    }

    mac_size = EVP_MD_size(md);
    if (mac_size < 0)
        return 0;
    return (size_t)mac_size;
}

size_t
tlmsp_eiv_size(const SSL *s, const struct tlmsp_envelope *env)
{
    const EVP_CIPHER_CTX *ds;
    const EVP_CIPHER *enc;

    ds = tlmsp_cipher_context(s, env, &enc);

    /*
     * Calculate size of explicit IV.
     */
    if (ds == NULL || enc == NULL)
        return 0;

    switch (EVP_CIPHER_mode(enc)) {
    case EVP_CIPH_CBC_MODE:
        return TLMSP_CBC_EXPLICIT_IV_LENGTH;
    case EVP_CIPH_GCM_MODE:
        return TLMSP_GCM_EXPLICIT_IV_LENGTH;
    default:
        return 0;
    }
}

size_t
tlmsp_key_size(const SSL *s)
{
    return 16; /* XXX */
}

size_t
tlmsp_tag_size(const SSL *s, const struct tlmsp_envelope *env)
{
    const EVP_CIPHER_CTX *ds;
    const EVP_CIPHER *enc;

    ds = tlmsp_cipher_context(s, env, &enc);
    if (ds == NULL || enc == NULL)
        return 0;

    switch (EVP_CIPHER_mode(enc)) {
    case EVP_CIPH_GCM_MODE:
        return EVP_GCM_TLS_TAG_LEN;
    default:
        return 0;
    }
}

size_t
tlmsp_additional_mac_size(const SSL *s, const struct tlmsp_envelope *env)
{
    if (tlmsp_want_aad(s, env))
        return tlmsp_tag_size(s, env);
    return tlmsp_reader_mac_size(s, env);
}

int
tlmsp_want_aad(const SSL *s, const struct tlmsp_envelope *env)
{
    const EVP_CIPHER_CTX *ds;
    const EVP_CIPHER *enc;

    ds = tlmsp_cipher_context(s, env, &enc);
    if (ds == NULL || enc == NULL)
        return 0;

    switch (EVP_CIPHER_mode(enc)) {
    case EVP_CIPH_GCM_MODE:
        return 1;
    default:
        return 0;
    }
}

int
tlmsp_generate_nonce(SSL *s, TLMSP_MiddleboxInstance *src, void *eiv, size_t eivlen)
{
    uint8_t *eivbytes;

    if (eivlen <= 1)
        return 0;

    eivbytes = eiv;

    eivbytes[0] = src->state.id;
    if (RAND_bytes(eivbytes + 1, eivlen - 1) <= 0)
        return 0;

    return 1;
}

static int
tlmsp_record_enc(SSL *s, SSL3_RECORD *recs, size_t nrecs, int sending)
{
    struct tlmsp_envelope env;
    tlmsp_middlebox_id_t id;
    struct tlmsp_data td;
    SSL3_RECORD *rr;
    WPACKET hpkt;
    uint8_t header[17];
    size_t headerlen;
    size_t wirelen;
    size_t eivlen;
    size_t taglen;
#if 0
    unsigned i;
#endif
    int rv;

    if (nrecs == 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (nrecs > 1) {
        for (rr = recs; rr < &recs[nrecs]; rr++) {
            rv = tlmsp_record_enc(s, rr, 1, sending);
            if (rv != 1)
                return rv;
        }
        return 1;
    }

    rr = recs;

    if (s->session == NULL)
        return 1;

    /*
     * When handling records for context 0, do not apply encryption to records
     * which do not use the context 0 cipher suite.
     */
    rv = tlmsp_record_context0(s, rr->type);
    if (rv == -1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (rv == 0)
        return 1;

    if (sending) {
        TLMSP_ENVELOPE_INIT_SSL_WRITE(&env, TLMSP_CONTEXT_CONTROL, s);

        eivlen = tlmsp_eiv_size(s, &env);

        /*
         * Establish an IV for this record.
         */
        if (eivlen != 0) {
            if (!tlmsp_generate_nonce(s, s->tlmsp.self, rr->data, eivlen)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    } else {
        TLMSP_ENVELOPE_INIT_SSL_READ(&env, TLMSP_CONTEXT_CONTROL, s);
    }

    if (tlmsp_want_aad(s, &env)) {
        eivlen = tlmsp_eiv_size(s, &env);
        taglen = tlmsp_tag_size(s, &env);

        if (rr->length < eivlen) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        wirelen = rr->length - eivlen;
        if (!sending)
            wirelen -= taglen;

        if (!WPACKET_init_static_len(&hpkt, header, sizeof header, 0)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        /*
         * Determine the sender from the nonce / explicit IV.
         */
        if (eivlen == 0) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
        id = rr->data[0];

        if (!tlmsp_sequence_entity(s, id, &hpkt)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (!WPACKET_put_bytes_u8(&hpkt, rr->type) ||
            !WPACKET_put_bytes_u16(&hpkt, TLMSP_TLS_VERSION(s->version)) ||
            !WPACKET_put_bytes_u16(&hpkt, wirelen)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        if (SSL_IS_TLMSP(s) && s->tlmsp.record_sid) {
            if (!WPACKET_put_bytes_u32(&hpkt, s->tlmsp.sid)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        if (!WPACKET_get_total_written(&hpkt, &headerlen) ||
            !WPACKET_finish(&hpkt)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        headerlen = 0;
    }

    td.data = rr->data;
    td.length = rr->length;

    if (!tlmsp_enc(s, &env, TLMSP_ENC_RECORD, &td, header, headerlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_ENC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    rr->data = rr->input = td.data;
    rr->length = td.length;

    return 1;
}

/*
 * The record layer calls this function to check or generate a MAC when not
 * using AEAD for context 0 records.
 */
static int
tlmsp_record_mac(SSL *s, SSL3_RECORD *rec, unsigned char *md, int sending)
{
    struct tlmsp_envelope env;
    WPACKET pkt;
    size_t recordlen;

    switch (tlmsp_record_context0(s, rec->type)) {
    case 1:
        break;
    default:
        /*
         * This is either not a TLMSP-allowed record type, or is not an
         * implicit context 0 record and should never have reached this point.
         *
         * TODO
         * Assert that this is not 0, since we should never get called if it
         * is.  We do get called in the -1 case so that we can generate this
         * fatal error.
         */
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (sending) {
        TLMSP_ENVELOPE_INIT_SSL_WRITE(&env, TLMSP_CONTEXT_CONTROL, s);
    } else {
        TLMSP_ENVELOPE_INIT_SSL_READ(&env, TLMSP_CONTEXT_CONTROL, s);
    }

    if (!WPACKET_init_static_len(&pkt, s->tlmsp.record_buffer, sizeof s->tlmsp.record_buffer, 0)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_sequence_record(s, sending, &pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_put_bytes_u8(&pkt, rec->type) ||
        !WPACKET_put_bytes_u16(&pkt, TLMSP_TLS_VERSION(s->version)) ||
        !WPACKET_put_bytes_u16(&pkt, rec->length)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (SSL_IS_TLMSP(s) && s->tlmsp.record_sid) {
        if (!WPACKET_put_bytes_u32(&pkt, s->tlmsp.sid)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_MAC,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /*
     * Now we have written the sequence number and synthetic header, copy in
     * the record payload itself.
     */
    if (!WPACKET_memcpy(&pkt, rec->input, rec->length)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!WPACKET_get_total_written(&pkt, &recordlen) ||
        !WPACKET_finish(&pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RECORD_MAC,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* TODO Clear out the record buffer.  */
    return tlmsp_mac(s, &env, TLMSP_MAC_READER, NULL, s->tlmsp.record_buffer, recordlen, md);
}

static size_t
tlmsp_pad(void *p, size_t len, size_t bs)
{
    size_t i, padnum;
    unsigned char padval, *buf;

    /* Add weird padding of upto 256 bytes */
    padnum = bs - (len % bs);
    if (padnum > MAX_PADDING)
        return 0;

    /* we need to add 'padnum' padding bytes of value padval */
    padval = (unsigned char)(padnum - 1);
    buf = p;
    for (i = 0; i < padnum; i++)
        buf[len + i] = padval;

    return len + padnum;
}

static int
tlmsp_prf_hash(EVP_MD_CTX *ctx, const EVP_MD *md, EVP_PKEY *pkey, const uint8_t *fb, const struct tlmsp_input_data *bufs, size_t bufcnt, uint8_t *out, size_t outsize)
{
    const struct tlmsp_input_data *tid;
    uint8_t tmp[EVP_MAX_MD_SIZE];
    size_t hashlen, siglen;

    if (outsize == 0)
        return 0;

    hashlen = EVP_MD_size(md);
    if (hashlen == 0)
        return 0;

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) <= 0)
        return 0;

    /*
     * If there is any feedback, process it.
     */
    if (fb != NULL) {
        if (EVP_DigestSignUpdate(ctx, fb, hashlen) <= 0)
            return 0;
    }

    /*
     * Now process all of the seed data.
     */
    for (tid = bufs; tid < &bufs[bufcnt]; tid++) {
        if (tid->data == NULL || tid->length == 0)
            return 0;
        if (EVP_DigestSignUpdate(ctx, tid->data, tid->length) <= 0)
            return 0;
    }

    /*
     * Now generate the output.
     */
    siglen = hashlen;
    if (outsize >= hashlen) {
        if (EVP_DigestSignFinal(ctx, out, &siglen) <= 0)
            return 0;
    } else {
        /*
         * Unlike suggested by documentation, if siglen < hashlen (i.e. outsize
         * < hashlen), EVP_DigestSignFinal is doing one of two things, either:
         * (1) writing hashlen bytes to the output pointer despite the input
         * specifying a smaller size; or (2) setting siglen to more than the
         * bytes output.  We observe that if siglen is < hashlen on call,
         * siglen will be exactly hashlen on return, and have not characterized
         * whether EVP_DigestSignFinal is writing beyond bounds, or simply
         * reporting the number of bytes it would have written, rather than
         * actually the number of bytes written.
         *
         * We use a temporary buffer of full size to avoid all doubt and just
         * copy out what we need to satisfy our caller.
         */
        if (EVP_DigestSignFinal(ctx, tmp, &siglen) <= 0)
            return 0;
        memcpy(out, tmp, outsize);
    }
    if (siglen != hashlen)
        return 0;

    return 1;
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
