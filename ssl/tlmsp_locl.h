/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_LOCL_H
# define HEADER_TLMSP_LOCL_H

/*
 * Note that we use a lot of static buffers which are largely orthogonal in
 * use.  There are two things to note about this.
 *
 * The first is that where the buffers are definably orthogonal, they should be
 * in a union, to reduce space and increase data locality.
 *
 * The second is that at least the larger buffers and possibly all buffers
 * should be dynamically allocated and sized instead, but the OpenSSL
 * facilities for this are extremely clunky, which is a barrier to ensuring
 * correct implementation first.
 *
 * The current TLMSP implementation prioritizes correctness and completeness,
 * with the expectation that a pass to improve memory management will occur.
 *
 * The same as is said here about buffers is also true for other large data
 * structures, such as the per-context and per-middlebox states, which also
 * include large buffers in the form of key blocks and similar.
 */

# define TLMSP_CONTEXT_COUNT                    (0x100)

# define TLMSP_MAX_RECORD_PAYLOAD               (65535) /* 4.2.1.3 */

# define TLMSP_MAX_RECORD_WITH_HEADER           (17 + TLMSP_MAX_RECORD_PAYLOAD)

/*
 * This calculation is excessive, but it gives us a safe margin for all of the
 * stuff we might need to do in the course of encoding a fragment.  This
 * represents each component of the fragment's actual data and the space it can
 * maximally consume, which as those values shift over time should remain
 * robust.
 */
# define TLMSP_MAX_CONTAINER_FRAGMENT_SCRATCH   (EVP_MAX_IV_LENGTH + TLMSP_CONTAINER_MAX_SIZE + EVP_MAX_MD_SIZE + SSL_RT_MAX_CIPHER_BLOCK_SIZE)

# define TLMSP_MAX_M_INFO_SIZE                  (1 + 1 + 3 * 253)
# define TLMSP_MAX_MAC_INPUT_SIZE               (1 + 2 + 4 + 8 + 1 + TLMSP_MAX_M_INFO_SIZE + 2 + TLMSP_MAX_CONTAINER_FRAGMENT_SCRATCH)
# define TLMSP_MAX_AAD_SIZE                     (1 + 2 + 4 + 8 + 1 + TLMSP_MAX_M_INFO_SIZE + 2)
# define TLMSP_MAX_CHECK_MAC_INPUT_SIZE         (1 + 2 + 4 + 8 + 1 + TLMSP_MAX_M_INFO_SIZE + 2 + 1 + 1 + 1 + EVP_MAX_MD_SIZE + EVP_MAX_MD_SIZE)

# define TLMSP_MAX_KEY_MATERIAL_CONTRIBUTION_SIZE   (1 + EVP_MAX_IV_LENGTH + EVP_MAX_KEY_LENGTH + (TLMSP_CONTEXT_COUNT * (1 + (2 * (1 + EVP_MAX_KEY_LENGTH)))) + EVP_MAX_MD_SIZE + SSL_RT_MAX_CIPHER_BLOCK_SIZE + 1)

# define TLMSP_MAX_MIDDLEBOX_HELLO_SIZE             (1 + SSL3_RANDOM_SIZE + 131396/*CLIENT_HELLO_MAX_LENGTH*/)

# define TLMSP_MAX_MIDDLEBOX_CERT_SIZE              (1 + 3 + (100 * 1024)) /* XXX */

# define TLMSP_MAX_MIDDLEBOX_KEY_EXCHANGE_PARAMS_SIZE   (100 * 1024)
# define TLMSP_MAX_MIDDLEBOX_KEY_EXCHANGE_SIZE          (1 + (2 * TLMSP_MAX_MIDDLEBOX_KEY_EXCHANGE_PARAMS_SIZE))

# define TLMSP_MAX_MIDDLEBOX_DONE_SIZE              (4 * 1024) /* XXX */

# define TLMSP_MAX_MIDDLEBOX_FINISHED_SIZE          (1 + FINISHED_MAX_LENGTH)

/*
 * The most we need to buffer for a handshake message is 4 (for the header)
 * plus the largest message we might have to process.
 *
 * We assume that 100KB will be the largest message we have to process, which
 * is the baseline limit for certificate chains in OpenSSL.
 *
 * This number should be dynamic and able to grow.
 */
# define TLMSP_MAX_HANDSHAKE_BUFFER             (SSL3_HM_HEADER_LENGTH + (100 * 1024))

# define TLMSP_MAX_ADDRESS_LENGTH               (2048)  /* XXX Unspecified.  */

# ifndef TLS_CIPHER_LEN
#  define TLS_CIPHER_LEN                         2
# endif

# ifndef OPENSSL_NO_ERR
#  define TLMSPfatal(s, al, cid, f, r)  tlmsp_fatal((s), (al), (cid), (f), (r), OPENSSL_FILE, OPENSSL_LINE)
# else
#  define TLMSPfatal(s, al, cid, f, r)  tlmsp_fatal((s), (al), (cid), (f), (r), NULL, 0)
# endif

typedef uint8_t tlmsp_middlebox_id_t;
# define TLMSP_MIDDLEBOX_ID_NONE                (0x00)
# define TLMSP_MIDDLEBOX_ID_CLIENT              (0x01)
# define TLMSP_MIDDLEBOX_ID_SERVER              (0xfe)
# define TLMSP_MIDDLEBOX_ID_FIRST               (0x02)
# define TLMSP_MIDDLEBOX_ID_LAST                (0xfd)
# define TLMSP_MIDDLEBOX_COUNT                  (0x100)

struct tlmsp_address {
    int address_type;
    uint8_t address[TLMSP_MAX_ADDRESS_LENGTH];
    size_t address_len;
};

# include "tlmsp_buf.h"
# include "tlmsp_con.h"
# include "tlmsp_ctx.h"
# include "tlmsp_enc.h"
# include "tlmsp_fin.h"
# include "tlmsp_key.h"
# include "tlmsp_mbx.h"
# include "tlmsp_seq.h"

struct tlmsp_state {
    tlmsp_context_id_t default_context;
    struct tlmsp_context_state context_states[TLMSP_CONTEXT_COUNT];
    TLMSP_Middlebox client_middlebox_state;
    TLMSP_Middlebox server_middlebox_state;
    TLMSP_Middleboxes *middlebox_states;
    struct tlmsp_middlebox_config middlebox_config;
    TLMSP_discovery_cb_fn discovery_cb;
    void *discovery_cb_arg;

    /*
     * If true, always reconnect when new middleboxes are discovered during
     * the initial handshake, even if all of the discovered middleboxes are
     * transparent.
     */
    int always_reconnect;
};

/*
 * XXX
 * We have a lot of large buffers here which could easily be, in some cases,
 * folded into a union because their users are orthogonal.
 *
 * XXX
 * Some rational sorting of this structure's members would be helpful.
 */
struct tlmsp_instance_state {
    TLMSP_MiddleboxInstance *self;

    int have_sid;
    uint32_t sid;
    int record_sid;

    int alert_container;
    tlmsp_context_id_t alert_context;

    tlmsp_context_id_t current_context;

    size_t stream_read_offset;
    TLMSP_Container *stream_read_container;

    tlmsp_context_id_t read_last_context;

    size_t container_read_offset;
    size_t container_read_length;
    uint8_t container_read_buffer[TLMSP_MAX_RECORD_PAYLOAD];

    uint8_t aad_buffer[TLMSP_MAX_AAD_SIZE];
    uint8_t mac_input_buffer[TLMSP_MAX_MAC_INPUT_SIZE];
    uint8_t check_mac_input_buffer[TLMSP_MAX_CHECK_MAC_INPUT_SIZE];

    uint8_t write_packet_buffer[TLMSP_MAX_RECORD_PAYLOAD];

    uint8_t record_buffer[TLMSP_MAX_RECORD_WITH_HEADER];

    uint8_t key_material_contribution_buffer[TLMSP_MAX_KEY_MATERIAL_CONTRIBUTION_SIZE];

    size_t handshake_buffer_length;
    uint8_t handshake_buffer[TLMSP_MAX_HANDSHAKE_BUFFER];

    uint8_t handshake_output_buffer[TLMSP_MAX_HANDSHAKE_BUFFER];

    uint8_t middlebox_signed_params_buffer[TLMSP_MAX_MIDDLEBOX_KEY_EXCHANGE_PARAMS_SIZE];

    struct tlmsp_context_instance_state context_states[TLMSP_CONTEXT_COUNT];

    /*
     * XXX
     * Could middlebox state (and context state) be in a separate structure,
     * which could be shared by both halves (with reference counting) of a
     * middlebox?
     */
    TLMSP_MiddleboxInstance client_middlebox;
    TLMSP_MiddleboxInstance server_middlebox;

    /*
     * On the client, this holds the a copy of the intitial middlebox list
     * to be used when constructing a second, post-discovery ClientHello.
     *
     * On middleboxes and on the server, this is not used.
     */
    TLMSP_MiddleboxInstances *initial_middlebox_list;
    TLMSP_MiddleboxInstance *initial_middlebox_table[TLMSP_MIDDLEBOX_COUNT];

    /*
     * The current middlebox list is the one that maintains the current
     * middlebox knowledge on all entities.
     */
    TLMSP_MiddleboxInstances *current_middlebox_list;
    TLMSP_MiddleboxInstance *current_middlebox_table[TLMSP_MIDDLEBOX_COUNT];

    TLMSP_discovery_cb_fn discovery_cb;
    void *discovery_cb_arg;

    int always_reconnect;
    int need_reconnect;
    int do_reconnect;
    int is_post_discovery;

    struct tlmsp_synch_key_block synch_keys;

    /*
     * If we are a middlebox, key exchange public parts from the peer.
     *
     * If we are an endpoint, we also capture our sent key material.
     */
    EVP_PKEY *kex_from_peer;
    EVP_PKEY *kex_sent;

    /*
     * The active cipher and message digest in each direction are stored here,
     * and then used each time we initialize a context (using the keys
     * provisioned.)
     */
    const EVP_CIPHER *read_cipher;
    const EVP_CIPHER *write_cipher;
    const EVP_MD *read_md;
    const EVP_MD *write_md;

    int middlebox_handshake_error;
    SSL *middlebox_other_ssl;

    struct tlmsp_middlebox_config middlebox_config;

    int send_middlebox_key_material;
    TLMSP_MiddleboxInstance *next_middlebox_key_material_middlebox;
    uint8_t middlebox_cipher[TLS_CIPHER_LEN];

    /*
     * XXX
     * We can use a single pointer for the iterator mechanism when sending to
     * multiple middleboxes, and combine next_*_middlebox into, say,
     * next_target_middlebox?
     */
    int send_middlebox_finished;
    TLMSP_MiddleboxInstance *next_middlebox_finished_middlebox;

    TLMSP_MWQIs *middlebox_write_queue;

    /*
     * These is used to buffer the ClientHello and ServerHello while we
     * determine what middleboxes are present, so that we can then feed the
     * Hello messages into the tlmsp_finish_state associated with each
     * middlebox.
     */
    struct tlmsp_buffer client_hello_buffer;
    struct tlmsp_buffer server_hello_buffer;

    struct tlmsp_finish_state middlebox_finish_state;

    struct tlmsp_input_data prf_input[TLMSP_MAX_PRF_INPUTS];
    size_t prf_input_count;

    uint8_t post_discovery_hash[EVP_MAX_MD_SIZE];
    size_t post_discovery_hashlen;
};

struct tlmsp_reconnect_state_st {
    uint32_t sid;
    struct tlmsp_address client_address;
    struct tlmsp_address server_address;
    TLMSP_Middleboxes *initial_middleboxes;
    TLMSP_Middleboxes *final_middleboxes;
    TLMSP_Contexts *contexts;
    uint8_t hash[EVP_MAX_MD_SIZE];
    size_t hashlen;
};

int tlmsp_state_init(SSL_CTX *);
void tlmsp_state_free(SSL_CTX *);

int tlmsp_instance_state_init(SSL *, SSL_CTX *);
int tlmsp_instance_state_reset(SSL *);
void tlmsp_instance_state_free(SSL *);

int tlmsp_read_sid(SSL *, PACKET *);
int tlmsp_write_sid(SSL *, WPACKET *);

int tlmsp_read_bytes(SSL *, int, int *, unsigned char *, size_t, int, size_t *);
int tlmsp_write_bytes(SSL *, int, const void *, size_t, size_t *);

int tlmsp_address_get(const struct tlmsp_address *, int *, uint8_t **, size_t *);
int tlmsp_address_set(struct tlmsp_address *, int, const uint8_t *, size_t);
int tlmsp_address_equal(const struct tlmsp_address *, const struct tlmsp_address *);

void tlmsp_fatal(SSL *, int, tlmsp_context_id_t, int, int, const char *, int);
int tlmsp_process_alert(SSL *, tlmsp_context_id_t, const uint8_t *, size_t);
int tlmsp_alert_code(int);

tlmsp_middlebox_id_t tlmsp_record_author(SSL *, const void *, size_t);
int tlmsp_record_context0(const SSL *, int);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
