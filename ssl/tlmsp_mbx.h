/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_MBX_H
# define HEADER_TLMSP_MBX_H

# include "tlmsp_ctx_idx.h"
# include "tlmsp_seq.h"

struct tlmsp_middlebox_write_queue_item;

# define TLMSP_HAVE_MIDDLEBOXES(s)  ((s)->tlmsp.current_middlebox_list != NULL)
# define TLMSP_MIDDLEBOX_ID_PEER(s) ((s)->server ? TLMSP_MIDDLEBOX_ID_CLIENT : TLMSP_MIDDLEBOX_ID_SERVER)
# define TLMSP_MIDDLEBOX_ID_SELF(s) ((s)->tlmsp.self != NULL ? (s)->tlmsp.self->state.id : TLMSP_MIDDLEBOX_ID_NONE)

# define TLMSP_MIDDLEBOX_ID_ENDPOINT(id)    ((id == TLMSP_MIDDLEBOX_ID_CLIENT) || (id == TLMSP_MIDDLEBOX_ID_SERVER))

struct tlmsp_middlebox_config {
    struct tlmsp_address transparent_address;
    TLMSP_address_match_cb_fn address_match_callback;
    void *address_match_arg;
};

struct tlmsp_middlebox_st {
    tlmsp_middlebox_id_t id;
    int inserted; /* 0 = static, 1 = dynamic, 2 = forbidden */
    int transparent;
    TLMSP_ContextAccess access;
    struct tlmsp_address address;
};

TLMSP_CONTEXT_INDEXED(struct tlmsp_context_confirmation, TLMSP_ContextConfirmationTable);

struct tlmsp_middlebox_instance_st {
    uint8_t to_client_random[SSL3_RANDOM_SIZE];
    uint8_t to_server_random[SSL3_RANDOM_SIZE];
    uint8_t master_secret[SSL3_MASTER_SECRET_SIZE];
    TLMSP_Middlebox state;
    struct tlmsp_middlebox_key_block key_block;
    struct tlmsp_middlebox_key_block advance_key_block;

    TLMSP_ContextConfirmationTable confirmations;

    struct tlmsp_finish_state finish_state;

    /*
     * For ourselves, this represents our transmit sequence number.
     *
     * For other entities, it is our receive sequence number for that entity.
     */
    struct tlmsp_sequence_number sequence_number;

    STACK_OF(X509) *cert_chain;
    EVP_PKEY *to_client_pkey;
    EVP_PKEY *to_server_pkey;
};
typedef struct tlmsp_middlebox_instance_st TLMSP_MiddleboxInstance;
DEFINE_STACK_OF(TLMSP_MiddleboxInstance)
typedef STACK_OF(TLMSP_MiddleboxInstance) TLMSP_MiddleboxInstances;

typedef struct tlmsp_middlebox_write_queue_item TLMSP_MWQI;
DEFINE_STACK_OF(TLMSP_MWQI)
typedef STACK_OF(TLMSP_MWQI) TLMSP_MWQIs;

int tlmsp_middlebox_add(TLMSP_Middleboxes **, const TLMSP_Middlebox *);
void tlmsp_middlebox_free(TLMSP_Middlebox *);
void tlmsp_middlebox_instance_cleanup(TLMSP_MiddleboxInstance *);
void tlmsp_middlebox_instance_free(TLMSP_MiddleboxInstance *);

int tlmsp_middleboxes_dup(TLMSP_MiddleboxInstances **, const TLMSP_MiddleboxInstances *);
void tlmsp_middleboxes_free(const TLMSP_MiddleboxInstances *);

int tlmsp_get_middleboxes_list(TLMSP_Middleboxes **, const TLMSP_MiddleboxInstances *);
int tlmsp_set_middlebox_list(TLMSP_MiddleboxInstances **, const TLMSP_Middleboxes *);
int tlmsp_middleboxes_compare(const TLMSP_MiddleboxInstances *, const TLMSP_Middleboxes *, int, int *);

TLMSP_MiddleboxInstance *tlmsp_middlebox_first_initial(const SSL *);
TLMSP_MiddleboxInstance *tlmsp_middlebox_next_initial(const SSL *, const TLMSP_MiddleboxInstance *);
TLMSP_MiddleboxInstance *tlmsp_middlebox_lookup_initial(const SSL *, tlmsp_middlebox_id_t);
TLMSP_MiddleboxInstance *tlmsp_middlebox_insert_after_initial(SSL *, const TLMSP_MiddleboxInstance *, tlmsp_middlebox_id_t);
int tlmsp_middlebox_table_compile_initial(SSL *);
void tlmsp_middleboxes_clear_initial(SSL *);
TLMSP_MiddleboxInstance *tlmsp_middlebox_first(const SSL *);
TLMSP_MiddleboxInstance *tlmsp_middlebox_next(const SSL *, const TLMSP_MiddleboxInstance *);
TLMSP_MiddleboxInstance *tlmsp_middlebox_next_direction(const SSL *, const TLMSP_MiddleboxInstance *, enum tlmsp_direction);
TLMSP_MiddleboxInstance *tlmsp_middlebox_lookup(const SSL *, tlmsp_middlebox_id_t);
TLMSP_MiddleboxInstance *tlmsp_middlebox_insert_after(SSL *, const TLMSP_MiddleboxInstance *, tlmsp_middlebox_id_t);
int tlmsp_middlebox_table_compile_current(SSL *);
void tlmsp_middleboxes_clear_current(SSL *);
int tlmsp_middlebox_establish_id(SSL *);

tlmsp_middlebox_id_t tlmsp_middlebox_free_id(const SSL *);

int tlmsp_middlebox_accept(SSL *);
int tlmsp_middlebox_connect(SSL *);

int tlmsp_middlebox_handshake_flush(SSL *);
void tlmsp_middlebox_handshake_free(SSL *);
int tlmsp_middlebox_handshake_process(SSL *, int);

int tlmsp_middlebox_synchronize(SSL *, const SSL *, int);

int tlmsp_middlebox_certificate(SSL *, TLMSP_MiddleboxInstance *, X509 **);
int tlmsp_middlebox_choose_certificate(SSL *);
int tlmsp_middlebox_verify_certificate(SSL *, TLMSP_MiddleboxInstance *);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
