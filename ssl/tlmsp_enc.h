/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_ENC_H
# define HEADER_TLMSP_ENC_H

# define IMPLEMENT_tlmsp_meth_func(version, flags, mask, func_name, s_accept,   \
                                 s_connect, enc_data) \
const SSL_METHOD *func_name(void)  \
        { \
        static const SSL_METHOD func_name##_data= { \
                version, \
                flags, \
                mask, \
                tls1_new, \
                tls1_clear, \
                tls1_free, \
                s_accept, \
                s_connect, \
                ssl3_read, \
                ssl3_peek, \
                ssl3_write, \
                ssl3_shutdown, \
                ssl3_renegotiate, \
                ssl3_renegotiate_check, \
                tlmsp_read_bytes, \
                tlmsp_write_bytes, \
                ssl3_dispatch_alert, \
                ssl3_ctrl, \
                ssl3_ctx_ctrl, \
                ssl3_get_cipher_by_char, \
                ssl3_put_cipher_by_char, \
                ssl3_pending, \
                ssl3_num_ciphers, \
                ssl3_get_cipher, \
                tls1_default_timeout, \
                &enc_data, \
                ssl_undefined_void_function, \
                ssl3_callback_ctrl, \
                ssl3_ctx_callback_ctrl, \
        }; \
        return &func_name##_data; \
        }

# define TLMSP_IS_MIDDLEBOX(s) (SSL_IS_TLMSP(s) && ((s)->method->flags & SSL_METHOD_MIDDLEBOX) != 0)

struct tlmsp_buffer {
    uint8_t *data;
    size_t length;
};

enum tlmsp_enc_kind {
    TLMSP_ENC_CONTAINER,
    TLMSP_ENC_RECORD,
    TLMSP_ENC_KEY_MATERIAL,
};

enum tlmsp_mac_kind {
    TLMSP_MAC_CHECK,
    TLMSP_MAC_INBOUND_CHECK,
    TLMSP_MAC_KEY_MATERIAL_CONTRIBUTION,
    TLMSP_MAC_OUTBOUND_READER_CHECK,
    TLMSP_MAC_READER,
    TLMSP_MAC_WRITER,
};

int tlmsp_enc(SSL *, const struct tlmsp_envelope *, enum tlmsp_enc_kind, struct tlmsp_buffer *, const void *, size_t);
int tlmsp_mac(SSL *, const struct tlmsp_envelope *, enum tlmsp_mac_kind, const void *, const void *, size_t, void *);
int tlmsp_hash(SSL *, const void *, size_t, void *, size_t *);

EVP_CIPHER_CTX *tlmsp_cipher_context(const SSL *, const struct tlmsp_envelope *, const EVP_CIPHER **);
int tlmsp_cipher_suite(const SSL *, const struct tlmsp_envelope *, const EVP_CIPHER **, const EVP_MD **);
const EVP_MD_CTX *tlmsp_hash_context(const SSL *, const struct tlmsp_envelope *, const EVP_MD **);

size_t tlmsp_block_size(const SSL *, const struct tlmsp_envelope *);
size_t tlmsp_reader_mac_size(const SSL *, const struct tlmsp_envelope *);
size_t tlmsp_eiv_size(const SSL *, const struct tlmsp_envelope *);
size_t tlmsp_key_size(const SSL *);
size_t tlmsp_tag_size(const SSL *, const struct tlmsp_envelope *);
size_t tlmsp_additional_mac_size(const SSL *, const struct tlmsp_envelope *);
int tlmsp_want_aad(const SSL *, const struct tlmsp_envelope *);

int tlmsp_generate_nonce(SSL *, tlmsp_middlebox_id_t, void *, size_t);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
