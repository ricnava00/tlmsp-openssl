/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_MBX_H
# define HEADER_TLMSP_MBX_H

# define TLMSP_HAVE_MIDDLEBOXES(s)  ((s)->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_FIRST].state.present)

struct tlmsp_middlebox_config {
    TLMSP_address_match_cb_fn address_match_callback;
    void *address_match_arg;
};

struct tlmsp_middlebox_state {
    int present;
    int transparent;
    TLMSP_ContextAccess access;
    struct tlmsp_address address;
};

struct tlmsp_middlebox_instance_state {
    uint8_t to_client_random[SSL3_RANDOM_SIZE];
    uint8_t to_server_random[SSL3_RANDOM_SIZE];
    uint8_t master_secret[SSL3_MASTER_SECRET_SIZE];
    struct tlmsp_middlebox_state state;
    struct tlmsp_middlebox_key_block key_block;
    struct tlmsp_middlebox_key_block advance_key_block;

    /*
     * XXX TODO XXX
     * We should not be copying these parameters when we use memcpy to copy
     * instance state between middlebox halves.  These should probably be
     * duplicated explicitly, or up-ref'd, or similar.
     */
    EVP_PKEY *to_client_pkey;
    EVP_PKEY *to_server_pkey;
};

struct tlmsp_middlebox_st {
    struct tlmsp_middlebox_state state;
};

struct tlmsp_middlebox_write_queue_item {
    int type;
    size_t length;
    uint8_t buffer[TLMSP_MAX_HANDSHAKE_BUFFER];
    int (*completion)(SSL *, int);
};
typedef struct tlmsp_middlebox_write_queue_item TLMSP_MWQI;
DEFINE_STACK_OF(TLMSP_MWQI);
typedef STACK_OF(TLMSP_MWQI) TLMSP_MWQIs;

void tlmsp_middlebox_free(TLMSP_Middlebox *);

tlmsp_middlebox_id_t tlmsp_middlebox_first(const SSL *);
tlmsp_middlebox_id_t tlmsp_middlebox_next(const SSL *, tlmsp_middlebox_id_t);
int tlmsp_middlebox_present(const SSL *, tlmsp_middlebox_id_t id);

int tlmsp_middlebox_accept(SSL *);
int tlmsp_middlebox_connect(SSL *);

int tlmsp_middlebox_handshake_flush(SSL *);
void tlmsp_middlebox_handshake_free(SSL *);
int tlmsp_middlebox_handshake_process(SSL *, int);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
