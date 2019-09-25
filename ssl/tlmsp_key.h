/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_KEY_H
# define HEADER_TLMSP_KEY_H

struct tlmsp_envelope;
struct tlmsp_middlebox_instance_st;

typedef struct tlmsp_middlebox_instance_st TLMSP_MiddleboxInstance;

enum tlmsp_key_set {
    TLMSP_KEY_SET_NORMAL,
    /*
     * We use the keys and cipher that will be used as a result of this
     * handshake around after the next ChangeCipherSpec early.  This is done to
     * support early encryption of KeyMaterialContribution before the first
     * ChangeCipherSpec, and the behaviour is maintained after that point,
     * requiring the addition of this second general key management approach.
     */
    TLMSP_KEY_SET_ADVANCE,
};

struct tlmsp_context_contributions {
    uint8_t synch[EVP_MAX_KEY_LENGTH]; /* Only for context 0.  */
    uint8_t reader[EVP_MAX_KEY_LENGTH];
    uint8_t writer[EVP_MAX_KEY_LENGTH];
};

#define TLMSP_CONTRIBUTION_SERVER   0
#define TLMSP_CONTRIBUTION_CLIENT   1
struct tlmsp_context_key_block {
    uint8_t reader_key_block[EVP_MAX_KEY_LENGTH * 4];
    /*
     * XXX
     * The key pointers into each key block are set once and never change
     * unless the key size changes.  We could use macros to make this into
     * offsets multiplied by the key size, so that we don't need the extra
     * pointers.
     */
    const uint8_t *client_reader_mac_key;
    const uint8_t *client_reader_enc_key;
    const uint8_t *server_reader_mac_key;
    const uint8_t *server_reader_enc_key;

    uint8_t writer_key_block[EVP_MAX_KEY_LENGTH * 2];
    const uint8_t *client_writer_mac_key;
    const uint8_t *server_writer_mac_key;

    struct tlmsp_context_contributions contributions[2];
};

struct tlmsp_context_confirmation {
    struct tlmsp_context_contributions contributions[2];
};

struct tlmsp_middlebox_key_block {
    uint8_t key_block[EVP_MAX_KEY_LENGTH * 4];
    const uint8_t *btoa_mac_key;
    const uint8_t *atob_mac_key;
    const uint8_t *btoa_enc_key;
    const uint8_t *atob_enc_key;
};

struct tlmsp_synch_key_block {
    uint8_t key_block[EVP_MAX_KEY_LENGTH * 2];
    const uint8_t *client_mac_key;
    const uint8_t *server_mac_key;
};

enum tlmsp_key_kind {
    TLMSP_KEY_SYNCH_MAC,    /* Used to generate synchronization MACs.  (4.2.7.2.3) */
    TLMSP_KEY_A_B_MAC,      /* Used to verify messages from A to B.  (4.3.9.2) */
    TLMSP_KEY_A_B_ENC,      /* Encryption counterpart to TLMSP_KEY_A_B_MAC.  */
    TLMSP_KEY_C_READER_MAC, /* Used to verify client<->server containers, per-context.  (4.3.9.3) */
    TLMSP_KEY_C_READER_ENC, /* Encryption counterpart to TLMSP_KEY_C_READER_MAC.  */
    TLMSP_KEY_C_WRITER_MAC, /* Writer MAC counterpart to TLMSP_KEY_C_READER_MAC.  */
};

const uint8_t *tlmsp_key(const SSL *, const struct tlmsp_envelope *, enum tlmsp_key_kind);

int tlmsp_change_cipher_state(SSL *, int);
int tlmsp_generate_master_secret(SSL *, unsigned char *, unsigned char *, size_t, size_t *);
int tlmsp_generate_middlebox_master_secret(SSL *, TLMSP_MiddleboxInstance *);
int tlmsp_setup_key_block(SSL *);

int tlmsp_setup_advance_keys(SSL *, TLMSP_MiddleboxInstance *);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
