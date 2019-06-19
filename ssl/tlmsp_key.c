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

#pragma clang diagnostic error "-Wmissing-prototypes"

#define TLMSP_CONTEXT_SYNCH_KEYS_CONST          "synch keys"
#define TLMSP_CONTEXT_SYNCH_KEYS_CONST_SIZE     ((sizeof TLMSP_CONTEXT_SYNCH_KEYS_CONST) - 1)
#define TLMSP_CONTEXT_READER_KEYS_CONST         "reader keys"
#define TLMSP_CONTEXT_READER_KEYS_CONST_SIZE    ((sizeof TLMSP_CONTEXT_READER_KEYS_CONST) - 1)
#define TLMSP_CONTEXT_WRITER_KEYS_CONST         "writer keys"
#define TLMSP_CONTEXT_WRITER_KEYS_CONST_SIZE    ((sizeof TLMSP_CONTEXT_WRITER_KEYS_CONST) - 1)

/*
 * XXX TODO XXX
 *
 * Some details around key derivation/selection with AEAD ciphers need
 * to be reviewed.
 *
 * Key block expansion needs to all happen here.
 *
 * IDList stuff needs to be cleaned up.
 *
 * We need to add the messages required to do all of the context derivation.
 *
 * After that, all the details with adding actual middleboxes to the mix.
 */

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
 *
 * XXX
 * The key activation logic here may be wrong with the new key scheme; do we
 * need to specialize the middlebox key activation differently?  Argh!
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

/*
 * Key derivation local functions.
 */
static int tlmsp_derive_keys(SSL *, enum tlmsp_key_set, tlmsp_middlebox_id_t);
static int tlmsp_get_client_server_random(SSL *, const uint8_t **, const uint8_t **);
static int tlmsp_get_random_pair(SSL *, tlmsp_middlebox_id_t, const uint8_t **, const uint8_t **);
static int tlmsp_hash_idlist(SSL *, unsigned char *, size_t *, tlmsp_middlebox_id_t);
static int tlmsp_reset_cipher(SSL *, int);

static int tlmsp_key_activate(const SSL *, const struct tlmsp_key_derivation_layout *, const uint8_t *, void *);
static int tlmsp_key_activate_all(SSL *, enum tlmsp_key_set, enum tlmsp_direction, tlmsp_middlebox_id_t);
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
tlmsp_setup_advance_keys(SSL *s, tlmsp_middlebox_id_t id)
{
    if (!tlmsp_derive_keys(s, TLMSP_KEY_SET_ADVANCE, id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_ADVANCE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_key_activate_all(s, TLMSP_KEY_SET_ADVANCE, TLMSP_D_CTOS, id) ||
        !tlmsp_key_activate_all(s, TLMSP_KEY_SET_ADVANCE, TLMSP_D_STOC, id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_ADVANCE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int
tlmsp_generate_master_secret(SSL *s, unsigned char *out, unsigned char *p, size_t len, size_t *secret_size)
{
    struct tlmsp_middlebox_instance_state *tmis;
    struct tlmsp_middlebox_key_block *mk;
    uint8_t idlist_hash[EVP_MAX_MD_SIZE];
    size_t hashlen;

    /*
     * In clients, this happens as part of ClientKeyExchange post-work
     * processing.  In servers, in processing ClientKeyExchange.
     *
     * We will need to do likewise, probably with this abstracted slightly, for
     * generating the master secrets for middleboxes.
     */

    tmis = &s->tlmsp.middlebox_states[s->tlmsp.peer_id];
    mk = &tmis->key_block;

    if (!tlmsp_hash_idlist(s, idlist_hash, &hashlen, s->tlmsp.peer_id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tls1_PRF(s,
                  TLS_MD_MASTER_SECRET_CONST,
                  TLS_MD_MASTER_SECRET_CONST_SIZE,
                  idlist_hash, hashlen,
                  s->s3->client_random, SSL3_RANDOM_SIZE,
                  s->s3->server_random, SSL3_RANDOM_SIZE,
                  NULL, 0, p, len, tmis->master_secret,
                  sizeof tmis->master_secret, 1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    memcpy(out, tmis->master_secret, sizeof tmis->master_secret);
    *secret_size = sizeof tmis->master_secret;
    return 1;
}

int
tlmsp_generate_middlebox_master_secret(SSL *s, tlmsp_middlebox_id_t id)
{
    struct tlmsp_middlebox_instance_state *tmis;
    uint8_t idlist_hash[EVP_MAX_MD_SIZE];
    struct tlmsp_middlebox_key_block *mk;
    const uint8_t *a_random, *b_random;
    uint8_t premaster_secret[8];
    size_t hashlen;

    tmis = &s->tlmsp.middlebox_states[id];
    mk = &tmis->key_block;

    /*
     * XXX
     * For the Hackathon, we are not generating the premaster secret.
     */
    memset(premaster_secret, 0xa5, sizeof premaster_secret);

    if (!tlmsp_hash_idlist(s, idlist_hash, &hashlen, id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_get_random_pair(s, id, &a_random, &b_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tls1_PRF(s,
                  TLS_MD_MASTER_SECRET_CONST,
                  TLS_MD_MASTER_SECRET_CONST_SIZE,
                  idlist_hash, hashlen,
                  a_random, SSL3_RANDOM_SIZE,
                  b_random, SSL3_RANDOM_SIZE,
                  NULL, 0,
                  premaster_secret, sizeof premaster_secret,
                  tmis->master_secret, sizeof tmis->master_secret, 1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_GENERATE_MIDDLEBOX_MASTER_SECRET,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

int
tlmsp_setup_key_block(SSL *s)
{
    SSL_COMP *comp;

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

    if (!tlmsp_derive_keys(s, TLMSP_KEY_SET_NORMAL, s->tlmsp.peer_id)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_SETUP_KEY_BLOCK,
                 ERR_R_INTERNAL_ERROR);
        return 0;
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
tlmsp_reset_cipher(SSL *s, int write)
{
    enum tlmsp_direction d;
    EVP_CIPHER_CTX **cipher_ctx;
    EVP_MD_CTX **md_ctx;
    COMP_CTX **comp_ctx;
    const EVP_CIPHER **cipherp;
    const EVP_MD **mdp;

    if (write) {
        cipher_ctx = &s->enc_write_ctx;
        md_ctx = &s->write_hash;
        comp_ctx = &s->compress;

        cipherp = &s->tlmsp.write_cipher;
        mdp = &s->tlmsp.write_md;

        /*
         * If our ultimate remote peer is the client, then when we write, we
         * are writing server-to-client.  Otherwise, we are writing
         * client-to-server.
         *
         * The reverse follows likewise.
         */
        if (s->tlmsp.peer_id == TLMSP_MIDDLEBOX_ID_CLIENT)
            d = TLMSP_D_STOC;
        else
            d = TLMSP_D_CTOS;
    } else {
        cipher_ctx = &s->enc_read_ctx;
        md_ctx = &s->read_hash;
        comp_ctx = &s->expand;

        cipherp = &s->tlmsp.read_cipher;
        mdp = &s->tlmsp.read_md;

        if (s->tlmsp.peer_id == TLMSP_MIDDLEBOX_ID_CLIENT)
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

    /*
     * Note that the TLMSP spec includes compression support although
     * compression is deeply deprecated in mainline TLS for several
     * reasons.  The compression code works so long as the contexts share
     * compression state, which is not how it should work, but the
     * compression behaviour of TLMSP is underspecified and probably should
     * just be removed.
     */
#ifndef OPENSSL_NO_COMP
    if (*comp_ctx != NULL) {
        COMP_CTX_free(*comp_ctx);
        *comp_ctx = NULL;
    }
    if (s->s3->tmp.new_compression != NULL) {
        *comp_ctx = COMP_CTX_new(s->s3->tmp.new_compression->method);
        if (*comp_ctx == NULL) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RESET_CIPHER,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }
#endif

    if (!tlmsp_key_activate_all(s, TLMSP_KEY_SET_NORMAL, d, TLMSP_MIDDLEBOX_ID_NONE)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_RESET_CIPHER,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    return 1;
}

static int
tlmsp_derive_keys(SSL *s, enum tlmsp_key_set keys, tlmsp_middlebox_id_t id)
{
    uint8_t context_secret[EVP_MAX_KEY_LENGTH * 2];
    struct tlmsp_middlebox_instance_state *tmis;
    struct tlmsp_middlebox_key_block *mk;
    const uint8_t *a_random, *b_random;
    const uint8_t *client_random, *server_random;
    tlmsp_context_id_t cid;
    size_t keylen;
    unsigned j;

    keylen = tlmsp_key_size(s);

    tmis = &s->tlmsp.middlebox_states[id];

    switch (keys) {
    case TLMSP_KEY_SET_NORMAL:
        mk = &tmis->key_block;
        break;
    case TLMSP_KEY_SET_ADVANCE:
        mk = &tmis->advance_key_block;
        break;
    }

    if (id != s->tlmsp.peer_id ||
        (s->tlmsp.self_id != TLMSP_MIDDLEBOX_ID_CLIENT &&
         s->tlmsp.self_id != TLMSP_MIDDLEBOX_ID_SERVER)) {
        if (!tlmsp_generate_middlebox_master_secret(s, id)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    if (!tlmsp_get_random_pair(s, id, &a_random, &b_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tlmsp_get_client_server_random(s, &client_random, &server_random)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                 ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!tls1_PRF(s,
                  TLS_MD_KEY_EXPANSION_CONST,
                  TLS_MD_KEY_EXPANSION_CONST_SIZE,
                  NULL, 0,
                  a_random, SSL3_RANDOM_SIZE,
                  b_random, SSL3_RANDOM_SIZE,
                  NULL, 0,
                  tmis->master_secret, sizeof tmis->master_secret,
                  mk->key_block, sizeof mk->key_block, 1)) {
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
    if (id != s->tlmsp.peer_id)
        return 1;

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

            if (!tls1_PRF(s,
                          TLMSP_CONTEXT_SYNCH_KEYS_CONST,
                          TLMSP_CONTEXT_SYNCH_KEYS_CONST_SIZE,
                          &cid, sizeof cid,
                          NULL, 0, /* XXX MiddleboxRandom values.  */
                          server_random, SSL3_RANDOM_SIZE,
                          client_random, SSL3_RANDOM_SIZE,
                          context_secret, 2 * keylen,
                          tskb->key_block, sizeof tskb->key_block, 1)) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                         ERR_R_INTERNAL_ERROR);
                return 0;
            }
        }

        memcpy(context_secret, tckb->contributions[TLMSP_CONTRIBUTION_SERVER].reader, keylen);
        memcpy(&context_secret[keylen], tckb->contributions[TLMSP_CONTRIBUTION_CLIENT].reader, keylen);

        if (!tls1_PRF(s,
                      TLMSP_CONTEXT_READER_KEYS_CONST,
                      TLMSP_CONTEXT_READER_KEYS_CONST_SIZE,
                      &cid, sizeof cid,
                      NULL, 0, /* XXX MiddleboxRandom values.  */
                      server_random, SSL3_RANDOM_SIZE,
                      client_random, SSL3_RANDOM_SIZE,
                      context_secret, 2 * keylen,
                      tckb->reader_key_block, sizeof tckb->reader_key_block, 1)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_DERIVE_KEYS,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }

        memcpy(context_secret, tckb->contributions[TLMSP_CONTRIBUTION_SERVER].writer, keylen);
        memcpy(&context_secret[keylen], tckb->contributions[TLMSP_CONTRIBUTION_CLIENT].writer, keylen);

        if (!tls1_PRF(s,
                      TLMSP_CONTEXT_WRITER_KEYS_CONST,
                      TLMSP_CONTEXT_WRITER_KEYS_CONST_SIZE,
                      &cid, sizeof cid,
                      NULL, 0, /* XXX MiddleboxRandom values.  */
                      server_random, SSL3_RANDOM_SIZE,
                      client_random, SSL3_RANDOM_SIZE,
                      context_secret, 2 * keylen,
                      tckb->writer_key_block, sizeof tckb->writer_key_block, 1)) {
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
    switch (s->tlmsp.self_id) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
    case TLMSP_MIDDLEBOX_ID_SERVER:
        *client_randomp = s->s3->client_random;
        *server_randomp = s->s3->server_random;
        return 1;
    default:
        *client_randomp = s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].to_server_random;
        *server_randomp = s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].to_client_random;
        return 1;
    }
}

static int
tlmsp_get_random_pair(SSL *s, tlmsp_middlebox_id_t id, const uint8_t **a_randomp, const uint8_t **b_randomp)
{
    const struct tlmsp_middlebox_instance_state *self, *tmis;
    const uint8_t *a_random, *b_random;

    tmis = &s->tlmsp.middlebox_states[id];

    /*
     * If we are an endpoint and so is the other middlebox, we always use the
     * order of client_random and server_random.
     */
    if ((s->tlmsp.self_id == TLMSP_MIDDLEBOX_ID_CLIENT ||
         s->tlmsp.self_id == TLMSP_MIDDLEBOX_ID_SERVER) &&
        id == s->tlmsp.peer_id) {
        return tlmsp_get_client_server_random(s, a_randomp, b_randomp);
    }

    /*
     * If we are an endpoint, we are always party A.
     */
    switch (s->tlmsp.self_id) {
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
         * XXX
         * This should be the same as our peer_id.
         */
        self = &s->tlmsp.middlebox_states[s->tlmsp.self_id];
        switch (id) {
        case TLMSP_MIDDLEBOX_ID_CLIENT:
            a_random = tmis->to_server_random;
            b_random = self->to_client_random;
            break;
        case TLMSP_MIDDLEBOX_ID_SERVER:
            a_random = tmis->to_client_random;
            b_random = self->to_server_random;
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
tlmsp_hash_idlist(SSL *s, unsigned char *hash, size_t *hashlenp, tlmsp_middlebox_id_t id)
{
    const EVP_MD *hashmd;
    EVP_MD_CTX *mdctx;
    unsigned hashlen;
    X509 *cert;

    /*
     * XXX
     * For the Hackathon, we are not processing certificates in the middlebox;
     * as a result, we need to use a uniform value for the idlist hash.  We use
     * a single 0x05 as the idlist hash when talking to a middlebox.
     */
    if (id != s->tlmsp.peer_id ||
        (s->tlmsp.self_id != TLMSP_MIDDLEBOX_ID_CLIENT &&
         s->tlmsp.self_id != TLMSP_MIDDLEBOX_ID_SERVER)) {
        *hash = 0x05;
        *hashlenp = 1;
        return 1;
    }

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
    if (!s->server) {
        if (s->cert != NULL && s->cert->key != NULL)
            cert = s->cert->key->x509;
        else
            cert = NULL;
    } else {
        if (s->session != NULL)
            cert = s->session->peer;
        else
            cert = NULL;
    }
    if (cert != NULL) {
        if (!tlmsp_digest_certificate(s, mdctx, cert)) {
            EVP_MD_CTX_free(mdctx);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    /* XXX Add each middlebox certificate (if present.)  */

    /* Add the server certificate.  */
    if (s->server) {
        if (s->cert != NULL && s->cert->key != NULL)
            cert = s->cert->key->x509;
        else
            cert = NULL;
    } else {
        if (s->session != NULL)
            cert = s->session->peer;
        else
            cert = NULL;
    }
    if (cert != NULL) {
        if (!tlmsp_digest_certificate(s, mdctx, cert)) {
            EVP_MD_CTX_free(mdctx);
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_HASH_IDLIST,
                     ERR_R_INTERNAL_ERROR);
            return 0;
        }
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
    uint8_t *o;
#if 0
    unsigned i;
#endif

    /* XXX mac_secret_size?  */
    keylen = tlmsp_key_size(s);

    bo = (tkdl->offset_mac_keys * keylen) + (tkdl->offset_cipher_keys * keylen);
    o = (uint8_t *)sp + tkdl->output_offset;

    memcpy(o, kb + bo, keylen);

#if 0
    fprintf(stderr, "%s: activating %s in %p: ", __func__, tkdl->name, sp);
    for (i = 0; i < keylen; i++)
        fprintf(stderr, "%02x", o[i]);
    fprintf(stderr, "\n");
#endif

    return 1;
}

static int
tlmsp_key_activate_all(SSL *s, enum tlmsp_key_set keys, enum tlmsp_direction d, tlmsp_middlebox_id_t id)
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

        /* XXX Only for configured contexts and middleboxes!  */
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
            for (j = 0; j < TLMSP_MIDDLEBOX_COUNT; j++) {
                struct tlmsp_middlebox_instance_state *tmis = &s->tlmsp.middlebox_states[j];
                struct tlmsp_middlebox_key_block *tmkb;
                switch (keys) {
                case TLMSP_KEY_SET_NORMAL:
                    tmkb = &tmis->key_block;
                    break;
                case TLMSP_KEY_SET_ADVANCE:
                    tmkb = &tmis->advance_key_block;
                    break;
                }

                /*
                 * We don't need any keys for talking to ourselves.
                 */
                if (j == s->tlmsp.self_id)
                    continue;

                /*
                 * If we have been told to look for a specific middlebox, skip
                 * anything else.
                 */
                if (id != TLMSP_MIDDLEBOX_ID_NONE && id != j)
                    continue;

                /*
                 * We don't need keys for middleboxes that aren't present.
                 */
                if (!tmis->state.present)
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
                     s->tlmsp.self_id == TLMSP_MIDDLEBOX_ID_SERVER) &&
                    (j != TLMSP_MIDDLEBOX_ID_CLIENT &&
                     s->tlmsp.self_id != TLMSP_MIDDLEBOX_ID_CLIENT)) {
                    if (tkdl->direction == d)
                        continue;
                } else {
                    if (tkdl->direction != d)
                        continue;
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
    const struct tlmsp_middlebox_instance_state *tmis;
    tlmsp_middlebox_id_t id;

    if (env->src == s->tlmsp.self_id)
        id = env->dst;
    else if (env->dst == s->tlmsp.self_id)
        id = env->src;
    else
        return NULL;

    tmis = &s->tlmsp.middlebox_states[id];
    if (!tmis->state.present)
        return NULL;
    switch (env->keys) {
    case TLMSP_KEY_SET_NORMAL:
        return &tmis->key_block;
    case TLMSP_KEY_SET_ADVANCE:
        return &tmis->advance_key_block;
    }
}
