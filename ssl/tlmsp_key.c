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

#define TLMSP_CONTEXT_SYNCH_KEYS_CONST          "synch keys"
#define TLMSP_CONTEXT_SYNCH_KEYS_CONST_SIZE     ((sizeof TLMSP_CONTEXT_SYNCH_KEYS_CONST) - 1)
#define TLMSP_CONTEXT_READER_KEYS_CONST         "reader keys"
#define TLMSP_CONTEXT_READER_KEYS_CONST_SIZE    ((sizeof TLMSP_CONTEXT_READER_KEYS_CONST) - 1)
#define TLMSP_CONTEXT_WRITER_KEYS_CONST         "writer keys"
#define TLMSP_CONTEXT_WRITER_KEYS_CONST_SIZE    ((sizeof TLMSP_CONTEXT_WRITER_KEYS_CONST) - 1)

/*
 * Data structures to ease key derivation.
 */
enum tlmsp_key_block_kind {
    TLMSP_KB_CONTEXT_READER,
    TLMSP_KB_CONTEXT_WRITER,
    TLMSP_KB_MIDDLEBOX,
    TLMSP_KB_SYNCH,
};

enum tlmsp_key_type {
    TLMSP_KT_MAC,
    TLMSP_KT_CIPHER,
};

struct tlmsp_key_derivation_layout {
    enum tlmsp_key_block_kind key_block;
    enum tlmsp_key_type key_type;
    enum tlmsp_direction direction;
    size_t offset_mac_keys;
    size_t offset_cipher_keys;
    size_t output_offset;
    const char *name;
};

/*
 * This handles slicing up the output of our key derivation functions to
 * provision individual keys as they are activated in each direction by
 * ChangeCipherSpec.  See tlmsp_activate_key.
 */
static const struct tlmsp_key_derivation_layout tlmsp_key_derivation_layouts[] = {
    { TLMSP_KB_MIDDLEBOX,       TLMSP_KT_MAC,       TLMSP_D_STOC,   0, 0, offsetof(struct tlmsp_middlebox_key_block, btoa_mac_key),         "B_to_A_MAC_key" },
    { TLMSP_KB_MIDDLEBOX,       TLMSP_KT_MAC,       TLMSP_D_CTOS,   1, 0, offsetof(struct tlmsp_middlebox_key_block, atob_mac_key),         "A_to_B_MAC_key" },
    { TLMSP_KB_MIDDLEBOX,       TLMSP_KT_CIPHER,    TLMSP_D_STOC,   2, 0, offsetof(struct tlmsp_middlebox_key_block, btoa_enc_key),         "B_to_A_Encryption_key" },
    { TLMSP_KB_MIDDLEBOX,       TLMSP_KT_CIPHER,    TLMSP_D_CTOS,   2, 1, offsetof(struct tlmsp_middlebox_key_block, atob_enc_key),         "A_to_B_Encryption_key" },

    { TLMSP_KB_CONTEXT_READER,  TLMSP_KT_MAC,       TLMSP_D_CTOS,   0, 0, offsetof(struct tlmsp_context_key_block, client_reader_mac_key),  "client_reader_MAC_key_i" },
    { TLMSP_KB_CONTEXT_READER,  TLMSP_KT_CIPHER,    TLMSP_D_CTOS,   1, 0, offsetof(struct tlmsp_context_key_block, client_reader_enc_key),  "client_reader_enc_key_i" },
    { TLMSP_KB_CONTEXT_READER,  TLMSP_KT_MAC,       TLMSP_D_STOC,   1, 1, offsetof(struct tlmsp_context_key_block, server_reader_mac_key),  "server_reader_MAC_key_i" },
    { TLMSP_KB_CONTEXT_READER,  TLMSP_KT_CIPHER,    TLMSP_D_STOC,   2, 1, offsetof(struct tlmsp_context_key_block, server_reader_enc_key),  "server_reader_enc_key_i" },

    { TLMSP_KB_CONTEXT_WRITER,  TLMSP_KT_MAC,       TLMSP_D_CTOS,   0, 0, offsetof(struct tlmsp_context_key_block, client_writer_mac_key),  "client_writer_MAC_key_i" },
    { TLMSP_KB_CONTEXT_WRITER,  TLMSP_KT_MAC,       TLMSP_D_STOC,   1, 0, offsetof(struct tlmsp_context_key_block, server_writer_mac_key),  "server_writer_MAC_key_i" },

    { TLMSP_KB_SYNCH,           TLMSP_KT_MAC,       TLMSP_D_CTOS,   0, 0, offsetof(struct tlmsp_synch_key_block, client_mac_key),           "client_synch_mac_key" },
    { TLMSP_KB_SYNCH,           TLMSP_KT_MAC,       TLMSP_D_STOC,   1, 0, offsetof(struct tlmsp_synch_key_block, server_mac_key),           "server_synch_mac_key" }
};

/*
 * Encryption/digest utility functions.
 */
static int tlmsp_digest_certificate(SSL *, EVP_MD_CTX *, X509 *);
static int tlmsp_digest_middlebox_certificate(SSL *, EVP_MD_CTX *, TLMSP_MiddleboxInstance *);

/*
 * Key derivation local functions.
 */
static int tlmsp_derive_keys(SSL *, enum tlmsp_key_set, TLMSP_MiddleboxInstance *);
static int tlmsp_get_client_server_random(SSL *, const uint8_t **, const uint8_t **);
static int tlmsp_get_random_pair(SSL *, const TLMSP_MiddleboxInstance *, const uint8_t **, const uint8_t **);
static int tlmsp_hash_idlist(SSL *, unsigned char *, size_t *);
static int tlmsp_reset_cipher(SSL *, int);

static int tlmsp_key_activate(const SSL *, const struct tlmsp_key_derivation_layout *, const uint8_t *, void *);
static int tlmsp_key_activate_all(SSL *, enum tlmsp_key_set, enum tlmsp_direction, TLMSP_MiddleboxInstance *);
static const struct tlmsp_middlebox_key_block *tlmsp_middlebox_key_block_get(const SSL *, const struct tlmsp_envelope *);

/* Internal functions.  */

const uint8_t *
tlmsp_key(const SSL *s, const struct tlmsp_envelope *env, enum tlmsp_key_kind kind)
{
    const struct tlmsp_context_instance_state *tcis;
    const struct tlmsp_middlebox_key_block *tmkb;
    const struct tlmsp_context_key_block *tckb;
    enum tlmsp_direction d;

    /*
     * If we are using the advance key set, only the A-to-B keys are available.
     */
    switch (env->keys) {
    case TLMSP_KEY_SET_ADVANCE:
        switch (kind) {
        case TLMSP_KEY_A_B_ENC:
        case TLMSP_KEY_A_B_MAC:
            break;
        default:
            return NULL;
        }
        break;
    case TLMSP_KEY_SET_NORMAL:
        switch (kind) {
        case TLMSP_KEY_A_B_ENC:
            /*
             * A-to-B encryption keys should only be used for
             * KeyMaterialConfirmation messages, which use advance keys.
             */
            return NULL;
        default:
            break;
        }
        break;
    }

    /*
     * If using AEAD, always map MAC keys to corresponding encryption keys
     * where they exist.
     */
    if (tlmsp_want_aad(s, env)) {
        switch (kind) {
        case TLMSP_KEY_A_B_MAC:
            kind = TLMSP_KEY_A_B_ENC;
            break;
        case TLMSP_KEY_C_READER_MAC:
            kind = TLMSP_KEY_C_READER_ENC;
            break;
        default:
            break;
        }
    }

    /*
     * XXX
     * We could do general envelope verification here, e.g., if the src, dst, or
     * cid are unknown, return NULL.
     */
    d = tlmsp_envelope_direction(s, env);

    switch (kind) {
    case TLMSP_KEY_SYNCH_MAC:
        switch (d) {
        case TLMSP_D_CTOS:
            return s->tlmsp.synch_keys.client_mac_key;
        case TLMSP_D_STOC:
            return s->tlmsp.synch_keys.server_mac_key;
        }
        break;
        /*
         * XXX
         * Run through an example matrix and ensure this is selecting the
         * correct key.
         */
    case TLMSP_KEY_A_B_MAC:
        tmkb = tlmsp_middlebox_key_block_get(s, env);
        if (tmkb == NULL)
            return NULL;
        if (env->src == TLMSP_MIDDLEBOX_ID_CLIENT)
            return tmkb->atob_mac_key;
        if (env->dst == TLMSP_MIDDLEBOX_ID_CLIENT)
            return tmkb->btoa_mac_key;
        if (env->src == TLMSP_MIDDLEBOX_ID_SERVER)
            return tmkb->atob_mac_key;
        if (env->dst == TLMSP_MIDDLEBOX_ID_SERVER)
            return tmkb->btoa_mac_key;
        return NULL;
    case TLMSP_KEY_A_B_ENC:
        tmkb = tlmsp_middlebox_key_block_get(s, env);
        if (tmkb == NULL)
            return NULL;
        if (env->src == TLMSP_MIDDLEBOX_ID_CLIENT)
            return tmkb->atob_enc_key;
        if (env->dst == TLMSP_MIDDLEBOX_ID_CLIENT)
            return tmkb->btoa_enc_key;
        if (env->src == TLMSP_MIDDLEBOX_ID_SERVER)
            return tmkb->atob_enc_key;
        if (env->dst == TLMSP_MIDDLEBOX_ID_SERVER)
            return tmkb->btoa_enc_key;
        return NULL;
    case TLMSP_KEY_C_READER_MAC:
        tcis = &s->tlmsp.context_states[env->cid];
        if (!tcis->state.present)
            return NULL;
        tckb = &tcis->key_block;
        switch (d) {
        case TLMSP_D_CTOS:
            return tckb->client_reader_mac_key;
        case TLMSP_D_STOC:
            return tckb->server_reader_mac_key;
        }
        break;
    case TLMSP_KEY_C_READER_ENC:
        tcis = &s->tlmsp.context_states[env->cid];
        if (!tcis->state.present)
            return NULL;
        tckb = &tcis->key_block;
        switch (d) {
        case TLMSP_D_CTOS:
            return tckb->client_reader_enc_key;
        case TLMSP_D_STOC:
            return tckb->server_reader_enc_key;
        }
        break;
    case TLMSP_KEY_C_WRITER_MAC:
        tcis = &s->tlmsp.context_states[env->cid];
        if (!tcis->state.present)
            return NULL;
        tckb = &tcis->key_block;
        switch (d) {
        case TLMSP_D_CTOS:
            return tckb->client_writer_mac_key;
        case TLMSP_D_STOC:
            return tckb->server_writer_mac_key;
        }
        break;
    }

    return NULL;
}

/*
 * Differences to standard TLS:
 * 1. No streaming MAC support.
 * 2. We just change the keys in use, we don't configure them to the cipher or
 *    MAC context.  Those are configured as needed.  We keep the cipher and MAC
 *    contexts around because various OpenSSL code has layering violations that
 *    use the presence of those contexts to infer protocol state.
 * 3. Never reset sequence numbers.
 */
int
tlmsp_change_cipher_state(SSL *s, int which)
{
    /*
     * We are changing the read (i.e. decrypt) states.  Otherwise, we are
     * changing write.  The code is almost identical for each.
     *
     * Comments in the first generally are implicitly applicable to the second.
     */
    if ((which & SSL3_CC_READ) != 0) {
        if (s->ext.use_etm)
            s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;
        else
            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC_READ;

        if (!tlmsp_reset_cipher(s, 0)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CHANGE_CIPHER_STATE,
                         ERR_R_INTERNAL_ERROR);
                return 0;
        }
    } else {
        /*
         * This is a safeguard so that if something fails here but the
         * application were to cause new data to be emitted, it would not do so
         * with an incomplete or corrupt encryption state, which could have
         * worse effects than simply failing or crashing.
         *
         * Note that changing the read cipher state in the TLS code path also
         * resets the write state to valid, which is probably not exploitable
         * but is probably wrong.
         *
         * We do not repeat that mistake.
         */
        s->statem.enc_write_state = ENC_WRITE_STATE_INVALID;

        if (s->ext.use_etm)
            s->s3->flags |= TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE;
        else
            s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC_WRITE;

        if (!tlmsp_reset_cipher(s, 1)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CHANGE_CIPHER_STATE,
                         ERR_R_INTERNAL_ERROR);
                return 0;
        }
    }

    if ((which & SSL3_CC_WRITE) != 0) {
        /*
         * All state changing successful, mark write state as valid.
         */
        s->statem.enc_write_state = ENC_WRITE_STATE_VALID;
    }

    return 1;
}

/*
 * Set up our advance key block, which is used to encrypt key material with the
 * next round of keys before a ChangeCipherSpec (if there are active keys, it
 * will be doubly protected.)
 *
 * We have the premaster secrets for all of our peers available to us by this
 * point, and are able to first set up the advance key blocks themselves, and
 * then to do the key derivation.
 */
int
tlmsp_setup_advance_keys(SSL *s, TLMSP_MiddleboxInstance *tmis)
{
    if (!tlmsp_derive_keys(s, TLMSP_KEY_SET_ADVANCE, tmis)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_ADVANCE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_key_activate_all(s, TLMSP_KEY_SET_ADVANCE, TLMSP_D_CTOS, tmis) ||
        !tlmsp_key_activate_all(s, TLMSP_KEY_SET_ADVANCE, TLMSP_D_STOC, tmis)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_ADVANCE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int
tlmsp_generate_master_secret(SSL *s, unsigned char *out, unsigned char *p, size_t len, size_t *secret_size)
{
    TLMSP_MiddleboxInstance *tmis;
    uint8_t idlist_hash[EVP_MAX_MD_SIZE];
    size_t hashlen;

    /*
     * In clients, this happens as part of ClientKeyExchange post-work
     * processing.  In servers, in processing ClientKeyExchange.
     *
     * We will need to do likewise, probably with this abstracted slightly, for
     * generating the master secrets for middleboxes.
     */

    switch (TLMSP_MIDDLEBOX_ID_PEER(s)) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        tmis = &s->tlmsp.client_middlebox;
        break;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        tmis = &s->tlmsp.server_middlebox;
        break;
    default:
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_hash_idlist(s, idlist_hash, &hashlen)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_prf_init(s, TLS_MD_MASTER_SECRET_CONST) ||
        !tlmsp_prf_update(s, idlist_hash, hashlen) ||
        !tlmsp_prf_update(s, s->s3->client_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_update(s, s->s3->server_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_finish(s, p, len, tmis->master_secret, sizeof tmis->master_secret)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(out, tmis->master_secret, sizeof tmis->master_secret);
    *secret_size = sizeof tmis->master_secret;
    return 1;
}

int
tlmsp_generate_middlebox_master_secret(SSL *s, TLMSP_MiddleboxInstance *tmis)
{
    uint8_t idlist_hash[EVP_MAX_MD_SIZE];
    const uint8_t *a_random, *b_random;
    uint8_t *premaster_secret;
    size_t premaster_secretlen;
    EVP_PKEY *pubkey, *privkey;
    EVP_PKEY_CTX *dctx;
    size_t hashlen;

    /*
     * Select the EVP_PKEY corresponding to the MiddleboxKeyExchange.
     */
    if (TLMSP_MIDDLEBOX_ID_ENDPOINT(s->tlmsp.self->state.id)) {
        privkey = s->tlmsp.kex_sent;
        if (s->tlmsp.self->state.id == TLMSP_MIDDLEBOX_ID_CLIENT) {
            pubkey = tmis->to_client_pkey;
        } else {
            pubkey = tmis->to_server_pkey;
        }
    } else {
        TLMSP_MiddleboxInstance *keyins;

        pubkey = s->tlmsp.kex_from_peer;
        if (tmis->state.id == TLMSP_MIDDLEBOX_ID_CLIENT) {
            /*
             * NB: Because of where the MiddleboxKeyExchange occurs, the key
             * material is always located in the server-facing SSL.
             */
            keyins = s->tlmsp.middlebox_other_ssl->tlmsp.self;
            if (keyins == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            privkey = keyins->to_client_pkey;
        } else {
            keyins = s->tlmsp.self;
            if (keyins == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
            privkey = keyins->to_server_pkey;
        }
    }

    if (privkey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (pubkey == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Now derive the premaster secret.
     */
    dctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (dctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, pubkey) <= 0 ||
        EVP_PKEY_derive(dctx, NULL, &premaster_secretlen) <= 0) {
        EVP_PKEY_CTX_free(dctx);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    premaster_secret = OPENSSL_malloc(premaster_secretlen);
    if (premaster_secret == NULL) {
        EVP_PKEY_CTX_free(dctx);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_PKEY_derive(dctx, premaster_secret, &premaster_secretlen) <= 0) {
        OPENSSL_clear_free(premaster_secret, premaster_secretlen);
        EVP_PKEY_CTX_free(dctx);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    EVP_PKEY_CTX_free(dctx);

    if (!tlmsp_hash_idlist(s, idlist_hash, &hashlen)) {
        OPENSSL_clear_free(premaster_secret, premaster_secretlen);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_get_random_pair(s, tmis, &a_random, &b_random)) {
        OPENSSL_clear_free(premaster_secret, premaster_secretlen);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_prf_init(s, TLS_MD_MASTER_SECRET_CONST) ||
        !tlmsp_prf_update(s, idlist_hash, hashlen) ||
        !tlmsp_prf_update(s, a_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_update(s, b_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_finish(s, premaster_secret, premaster_secretlen, tmis->master_secret, sizeof tmis->master_secret)) {
        OPENSSL_clear_free(premaster_secret, premaster_secretlen);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    OPENSSL_clear_free(premaster_secret, premaster_secretlen);

    return 1;
}

int
tlmsp_setup_key_block(SSL *s)
{
    TLMSP_MiddleboxInstance *peer, *tmis;
    SSL_COMP *comp;

    peer = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    if (peer == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_KEY_BLOCK,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!ssl_cipher_get_evp(s->session,
                            &s->s3->tmp.new_sym_enc,
                            &s->s3->tmp.new_hash,
                            &s->s3->tmp.new_mac_pkey_type,
                            &s->s3->tmp.new_mac_secret_size,
                            &comp,
                            s->ext.use_etm)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_KEY_BLOCK,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    (void)comp; /* Required for various checks, but not used.  */

    if (!tlmsp_derive_keys(s, TLMSP_KEY_SET_NORMAL, peer)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_KEY_BLOCK,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * If we are an endpoint, derive keys for all middleboxes we might talk to.
     */
    if (!TLMSP_IS_MIDDLEBOX(s)) {
        for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
             tmis = tlmsp_middlebox_next(s, tmis)) {
            if (!tlmsp_derive_keys(s, TLMSP_KEY_SET_NORMAL, tmis)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_KEY_BLOCK,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }
    }

    return 1;
}

static int
tlmsp_digest_certificate(SSL *s, EVP_MD_CTX *mdctx, X509 *cert)
{
    uint8_t *certdata;
    int certlen;

    certdata = NULL;
    certlen = i2d_X509(cert, &certdata);
    if (certlen < 0) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DIGEST_CERTIFICATE,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (certlen != 0) {
        if (EVP_DigestUpdate(mdctx, certdata, certlen) <= 0) {
            OPENSSL_free(certdata);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DIGEST_CERTIFICATE,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        OPENSSL_free(certdata);
    }

    return 1;
}

static int
tlmsp_digest_middlebox_certificate(SSL *s, EVP_MD_CTX *mdctx, TLMSP_MiddleboxInstance *tmis)
{
    X509 *cert;

    if (!tlmsp_middlebox_certificate(s, tmis, &cert))
        return 0;
    if (cert == NULL) {
        /* No certificate, continue.  */
        return 1;
    }
    return tlmsp_digest_certificate(s, mdctx, cert);
}

static int
tlmsp_reset_cipher(SSL *s, int write)
{
    enum tlmsp_direction d;
    EVP_CIPHER_CTX **cipher_ctx;
    EVP_MD_CTX **md_ctx;
    const EVP_CIPHER **cipherp;
    const EVP_MD **mdp;

    if (write) {
        cipher_ctx = &s->enc_write_ctx;
        md_ctx = &s->write_hash;

        cipherp = &s->tlmsp.write_cipher;
        mdp = &s->tlmsp.write_md;

        /*
         * If our ultimate remote peer is the client, then when we write, we
         * are writing server-to-client.  Otherwise, we are writing
         * client-to-server.
         *
         * The reverse follows likewise.
         */
        if (TLMSP_MIDDLEBOX_ID_PEER(s) == TLMSP_MIDDLEBOX_ID_CLIENT)
            d = TLMSP_D_STOC;
        else
            d = TLMSP_D_CTOS;
    } else {
        cipher_ctx = &s->enc_read_ctx;
        md_ctx = &s->read_hash;

        cipherp = &s->tlmsp.read_cipher;
        mdp = &s->tlmsp.read_md;

        if (TLMSP_MIDDLEBOX_ID_PEER(s) == TLMSP_MIDDLEBOX_ID_CLIENT)
            d = TLMSP_D_CTOS;
        else
            d = TLMSP_D_STOC;
    }

    if (*cipher_ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RESET_CIPHER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * We set ciphers like this rather than doing CipherInit_ex or
     * DigestSignInit, because we will do the initialization every time we use
     * the cipher context or message digest context, since we swap out keys and
     * IVs.  We just track what's currently in use here.
     */
    *cipherp = s->s3->tmp.new_sym_enc;

    if (*md_ctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RESET_CIPHER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * XXX
     * In the AEAD case, do we need to explicitly set this to NULL or is it
     * properly ignored.
     */
    *mdp = s->s3->tmp.new_hash;

    if (!tlmsp_key_activate_all(s, TLMSP_KEY_SET_NORMAL, d, NULL)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RESET_CIPHER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_sequence_reset(s, write)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RESET_CIPHER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_derive_keys(SSL *s, enum tlmsp_key_set keys, TLMSP_MiddleboxInstance *tmis)
{
    uint8_t context_secret[EVP_MAX_KEY_LENGTH * 2];
    const TLMSP_MiddleboxInstance *iter;
    struct tlmsp_middlebox_key_block *mk;
    const uint8_t *a_random, *b_random;
    const uint8_t *client_random, *server_random;
    tlmsp_context_id_t cid;
    size_t template_count;
    size_t keylen;
    unsigned j;

    keylen = tlmsp_key_size(s);

    switch (keys) {
    case TLMSP_KEY_SET_NORMAL:
        mk = &tmis->key_block;
        break;
    case TLMSP_KEY_SET_ADVANCE:
        mk = &tmis->advance_key_block;
        break;
    }

    if (!TLMSP_MIDDLEBOX_ID_ENDPOINT(tmis->state.id) ||
        !TLMSP_MIDDLEBOX_ID_ENDPOINT(s->tlmsp.self->state.id)) {
        if (!tlmsp_generate_middlebox_master_secret(s, tmis)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!tlmsp_get_random_pair(s, tmis, &a_random, &b_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_get_client_server_random(s, &client_random, &server_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_prf_init(s, TLS_MD_KEY_EXPANSION_CONST) ||
        !tlmsp_prf_update(s, a_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_update(s, b_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_finish(s, tmis->master_secret, sizeof tmis->master_secret, mk->key_block, sizeof mk->key_block)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * We only need the A-to-B secrets for advance keys, return before
     * generating context keys.
     */
    if (keys == TLMSP_KEY_SET_ADVANCE)
        return 1;

    /*
     * Only when deriving keys for our peer do we need to derive context keys
     * as well.
     */
    if (tmis->state.id != TLMSP_MIDDLEBOX_ID_PEER(s))
        return 1;

    /*
     * Set up the pseudorandom function's seed template for all of our
     * various block expansions.
     *
     * They differ only in label and outputs.
     *
     * Note that the cid value is also different each time, because the
     * template points to cid, which we update in the loop.
     */
    if (!tlmsp_prf_init(s, NULL) ||
        !tlmsp_prf_update(s, &cid, sizeof cid)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }
    for (iter = tlmsp_middlebox_first(s); iter != NULL;
         iter = tlmsp_middlebox_next(s, iter)) {
        if (!tlmsp_prf_update(s, iter->to_server_random, SSL3_RANDOM_SIZE) ||
            !tlmsp_prf_update(s, iter->to_client_random, SSL3_RANDOM_SIZE)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
    if (!tlmsp_prf_update(s, server_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_update(s, client_random, SSL3_RANDOM_SIZE) ||
        !tlmsp_prf_save(s, &template_count)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        struct tlmsp_context_instance_state *tcis;
        struct tlmsp_context_key_block *tckb;

        tcis = &s->tlmsp.context_states[j];
        if (!tcis->state.present)
            continue;
        tckb = &tcis->key_block;

        cid = (tlmsp_context_id_t)j;

        if (cid == TLMSP_CONTEXT_CONTROL) {
            struct tlmsp_synch_key_block *tskb;

            tskb = &s->tlmsp.synch_keys;

            memcpy(context_secret, tckb->contributions[TLMSP_CONTRIBUTION_SERVER].synch, keylen);
            memcpy(&context_secret[keylen], tckb->contributions[TLMSP_CONTRIBUTION_CLIENT].synch, keylen);

            if (!tlmsp_prf_reinit(s, TLMSP_CONTEXT_SYNCH_KEYS_CONST, template_count) ||
                !tlmsp_prf_finish(s, context_secret, 2 * keylen, tskb->key_block, sizeof tskb->key_block)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        memcpy(context_secret, tckb->contributions[TLMSP_CONTRIBUTION_SERVER].reader, keylen);
        memcpy(&context_secret[keylen], tckb->contributions[TLMSP_CONTRIBUTION_CLIENT].reader, keylen);

        if (!tlmsp_prf_reinit(s, TLMSP_CONTEXT_READER_KEYS_CONST, template_count) ||
            !tlmsp_prf_finish(s, context_secret, 2 * keylen, tckb->reader_key_block, sizeof tckb->reader_key_block)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        memcpy(context_secret, tckb->contributions[TLMSP_CONTRIBUTION_SERVER].writer, keylen);
        memcpy(&context_secret[keylen], tckb->contributions[TLMSP_CONTRIBUTION_CLIENT].writer, keylen);

        if (!tlmsp_prf_reinit(s, TLMSP_CONTEXT_WRITER_KEYS_CONST, template_count) ||
            !tlmsp_prf_finish(s, context_secret, 2 * keylen, tckb->writer_key_block, sizeof tckb->writer_key_block)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

static int
tlmsp_get_client_server_random(SSL *s, const uint8_t **client_randomp, const uint8_t **server_randomp)
{
    switch (s->tlmsp.self->state.id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
    case TLMSP_MIDDLEBOX_ID_SERVER:
        *client_randomp = s->s3->client_random;
        *server_randomp = s->s3->server_random;
        return 1;
    default:
        *client_randomp = s->tlmsp.client_middlebox.to_server_random;
        *server_randomp = s->tlmsp.server_middlebox.to_client_random;
        return 1;
    }
}

static int
tlmsp_get_random_pair(SSL *s, const TLMSP_MiddleboxInstance *tmis, const uint8_t **a_randomp, const uint8_t **b_randomp)
{
    const uint8_t *a_random, *b_random;

    /*
     * If we are an endpoint and so is the other middlebox, we always use the
     * order of client_random and server_random.
     */
    if (TLMSP_MIDDLEBOX_ID_ENDPOINT(s->tlmsp.self->state.id) &&
        TLMSP_MIDDLEBOX_ID_ENDPOINT(tmis->state.id)) {
        return tlmsp_get_client_server_random(s, a_randomp, b_randomp);
    }

    /*
     * If we are an endpoint, we are always party A.
     */
    switch (s->tlmsp.self->state.id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        a_random = s->s3->client_random;
        b_random = tmis->to_client_random;
        break;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        a_random = s->s3->server_random;
        b_random = tmis->to_server_random;
        break;
    default:
        /*
         * We are a middlebox, A is the endpoint we are talking to.
         *
         * This should be the same as our peer.
         */
        if (tmis->state.id != TLMSP_MIDDLEBOX_ID_PEER(s) || !TLMSP_MIDDLEBOX_ID_ENDPOINT(tmis->state.id))
            return 0;
        switch (tmis->state.id) {
        case TLMSP_MIDDLEBOX_ID_CLIENT:
            a_random = tmis->to_server_random;
            b_random = s->tlmsp.self->to_client_random;
            break;
        case TLMSP_MIDDLEBOX_ID_SERVER:
            a_random = tmis->to_client_random;
            b_random = s->tlmsp.self->to_server_random;
            break;
        default:
            return 0;
        }
        break;
    }

    *a_randomp = a_random;
    *b_randomp = b_random;

    return 1;
}

static int
tlmsp_hash_idlist(SSL *s, unsigned char *hash, size_t *hashlenp)
{
    TLMSP_MiddleboxInstance *tmis;
    const EVP_MD *hashmd;
    EVP_MD_CTX *mdctx;
    unsigned hashlen;

    hashmd = ssl_prf_md(s);
    if (hashmd == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * Hash the IDList.
     */
    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_DigestInit_ex(mdctx, hashmd, NULL) <= 0) {
        EVP_MD_CTX_free(mdctx);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Add the client certificate (if any.)  */
    if (!tlmsp_digest_middlebox_certificate(s, mdctx, &s->tlmsp.client_middlebox)) {
        EVP_MD_CTX_free(mdctx);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /* Add each middlebox certificate.  */
    for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
         tmis = tlmsp_middlebox_next(s, tmis)) {
        if (!tlmsp_digest_middlebox_certificate(s, mdctx, tmis)) {
            EVP_MD_CTX_free(mdctx);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /* Add the server certificate.  */
    if (!tlmsp_digest_middlebox_certificate(s, mdctx, &s->tlmsp.server_middlebox)) {
        EVP_MD_CTX_free(mdctx);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, &hashlen) <= 0) {
        EVP_MD_CTX_free(mdctx);
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);

    *hashlenp = hashlen;

    return 1;
}

/*
 * The key layout allows for enc_key_length to be different to mac_key_length,
 * but in practice TLMSP only allows them to be identical at present.
 *
 * XXX TODO XXX
 * Should mac_key_length be 0 when in AEAD mode?  Only for key blocks which
 * have encryption keys to use instead?
 */
static int
tlmsp_key_activate(const SSL *s, const struct tlmsp_key_derivation_layout *tkdl, const uint8_t *kb, void *sp)
{
    size_t keylen;
    size_t bo;
    const uint8_t **op;
#if 0
    unsigned i;
#endif

    /* XXX mac_secret_size?  */
    keylen = tlmsp_key_size(s);

    bo = (tkdl->offset_mac_keys * keylen) + (tkdl->offset_cipher_keys * keylen);
    op = (const uint8_t **)((uintptr_t)sp + tkdl->output_offset);

    *op = kb + bo;

#if 0
    fprintf(stderr, "%s: activating %s in %p at %p: ", __func__, tkdl->name, sp, op);
    for (i = 0; i < keylen; i++)
        fprintf(stderr, "%02x", (*op)[i]);
    fprintf(stderr, "\n");
#endif

    return 1;
}

static int
tlmsp_key_activate_all(SSL *s, enum tlmsp_key_set keys, enum tlmsp_direction d, TLMSP_MiddleboxInstance *target)
{
    const struct tlmsp_key_derivation_layout *tkdl;
    unsigned i, j;

    /*
     * Update keys in the direction of this ChangeCipherSpec.
     */
    for (i = 0; i < OSSL_NELEM(tlmsp_key_derivation_layouts); i++) {
        int ok;

        tkdl = &tlmsp_key_derivation_layouts[i];

        /*
         * Select keys which change in the direction the ChangeCipherSpec is
         * moving.
         *
         * For most keys, this means we just check the direction field.
         *
         * For middlebox keys, i.e. A_to_B keys, we have to process keys in
         * both directions and do the filtering per-middlebox because of how
         * A_to_B keys are defined.
         *
         * If they were defined such that A was always the client and B was
         * always the server if either A or B was an endpoint, we could use the
         * CTOS/STOC logic exactly as is.
         *
         * Instead, however, we have to special case the case where A is the
         * server, i.e. where one of i and self_id is the server and neither i
         * nor self_id is the server, in which case the direction is reversed.
         *
         * Because of this, the middlebox case below has its own direction
         * checks.
         */
        if (tkdl->key_block != TLMSP_KB_MIDDLEBOX &&
            tkdl->direction != d) {
            continue;
        }

        ok = 1;

        switch (tkdl->key_block) {
        case TLMSP_KB_CONTEXT_READER:
            if (keys == TLMSP_KEY_SET_ADVANCE)
                continue;
            for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
                struct tlmsp_context_instance_state *tcis = &s->tlmsp.context_states[j];
                struct tlmsp_context_key_block *tckb = &tcis->key_block;
                if (!tcis->state.present)
                    continue;

                if (!tlmsp_key_activate(s, tkdl, tckb->reader_key_block, (void *)tckb)) {
                    ok = 0;
                    break;
                }
            }
            break;
        case TLMSP_KB_CONTEXT_WRITER:
            if (keys == TLMSP_KEY_SET_ADVANCE)
                continue;
            for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
                struct tlmsp_context_instance_state *tcis = &s->tlmsp.context_states[j];
                struct tlmsp_context_key_block *tckb = &tcis->key_block;
                if (!tcis->state.present)
                    continue;

                if (!tlmsp_key_activate(s, tkdl, tckb->writer_key_block, (void *)tckb)) {
                    ok = 0;
                    break;
                }
            }
            break;
        case TLMSP_KB_MIDDLEBOX:
            /* XXX This should walk the actual middlebox list plus client and server, right?  */
            for (j = 0; j < TLMSP_MIDDLEBOX_COUNT; j++) {
                struct tlmsp_middlebox_key_block *tmkb;
                TLMSP_MiddleboxInstance *tmis;

                /*
                 * We don't need any keys for talking to ourselves.
                 */
                if (j == s->tlmsp.self->state.id)
                    continue;

                /*
                 * If we have been told to look for a specific middlebox, skip
                 * anything else.
                 */
                if (target != NULL && target->state.id != j)
                    continue;

                /*
                 * If we are a middlebox, do not generate keys for talking to
                 * another middlebox.
                 */
                if (TLMSP_IS_MIDDLEBOX(s) && !TLMSP_MIDDLEBOX_ID_ENDPOINT(j))
                    continue;

                /*
                 * We don't need keys for middleboxes that aren't present.
                 *
                 * XXX
                 * In the target != NULL case, is tmis always target?  Or is it
                 * sometimes an instance from the other SSL on a middlebox?
                 */
                tmis = tlmsp_middlebox_lookup(s, j);
                if (tmis == NULL)
                    continue;

                /*
                 * This is the case where A is the server and B is a middlebox
                 * (whether we are the server or the middlebox), and so we
                 * reverse the direction sense to compensate for the server
                 * being on the "left" and the away-from-server side being on
                 * the "right", where all other keys follow the modality that
                 * client is the "left" and server is the "right", to ensure
                 * that we activate the keys in the right direction in response
                 * to ChangeCipherSpec.
                 */
                if ((j == TLMSP_MIDDLEBOX_ID_SERVER ||
                     s->tlmsp.self->state.id == TLMSP_MIDDLEBOX_ID_SERVER) &&
                    (j != TLMSP_MIDDLEBOX_ID_CLIENT &&
                     s->tlmsp.self->state.id != TLMSP_MIDDLEBOX_ID_CLIENT)) {
                    if (tkdl->direction == d)
                        continue;
                } else {
                    if (tkdl->direction != d)
                        continue;
                }

                switch (keys) {
                case TLMSP_KEY_SET_NORMAL:
                    tmkb = &tmis->key_block;
                    break;
                case TLMSP_KEY_SET_ADVANCE:
                    tmkb = &tmis->advance_key_block;
                    break;
                }

                if (!tlmsp_key_activate(s, tkdl, tmkb->key_block, (void *)tmkb)) {
                    ok = 0;
                    break;
                }
            }
            break;
        case TLMSP_KB_SYNCH:
            if (keys == TLMSP_KEY_SET_ADVANCE)
                continue;
            if (!tlmsp_key_activate(s, tkdl, s->tlmsp.synch_keys.key_block, (void *)&s->tlmsp.synch_keys)) {
                ok = 0;
                break;
            }
            break;
        }

        if (!ok) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_KEY_ACTIVATE_ALL,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

static const struct tlmsp_middlebox_key_block *
tlmsp_middlebox_key_block_get(const SSL *s, const struct tlmsp_envelope *env)
{
    const TLMSP_MiddleboxInstance *tmis;
    tlmsp_middlebox_id_t id;

    if (env->src == s->tlmsp.self->state.id)
        id = env->dst;
    else if (env->dst == s->tlmsp.self->state.id)
        id = env->src;
    else
        return NULL;

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL)
        return NULL;
    switch (env->keys) {
    case TLMSP_KEY_SET_NORMAL:
        return &tmis->key_block;
    case TLMSP_KEY_SET_ADVANCE:
        return &tmis->advance_key_block;
    }

    /* should not reach here */
    return NULL;
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
