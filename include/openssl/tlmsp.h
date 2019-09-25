/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_H
# define HEADER_TLMSP_H

# include <openssl/opensslconf.h>

# include <openssl/safestack.h>
# include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Types and definitions.  */

/*
 * This version numbering is used internal to the OpenSSL codebase, but similar
 * defines are exported for other protocols.  Note that care has been taken to
 * avoid collision with any other version numbering in current OpenSSL use, but
 * this should be coordinated with upstream OpenSSL in the future.
 */
# define TLMSP_VERSION_BIT              (0x30000)
# define TLMSP_ANY_VERSION              (TLMSP_VERSION_BIT | 0xffff)            /* Use any supported TLMSP version.  */

# define TLMSP1_0_VERSION               (TLMSP_VERSION_BIT | TLS1_2_VERSION)
# define TLMSP_MAX_VERSION              TLMSP1_0_VERSION

# define TLMSP_TLS_VERSION(v)           ((v) & ~TLMSP_VERSION_BIT)

/*
 * The TLMSP_version for the TLMSP extension, which is different to the version
 * used in the rest of the protocol and the record versioning.
 */
# define TLMSP_VERSION_MAJOR            (1u)
# define TLMSP_VERSION_MINOR            (0u)

/*
 * Handshake protocol message types.
 */
# define TLMSP_MT_MIDDLEBOX_HELLO               (41)
# define TLMSP_MT_MIDDLEBOX_CERT                (42)
# define TLMSP_MT_MIDDLEBOX_KEY_EXCHANGE        (45)
# define TLMSP_MT_MIDDLEBOX_HELLO_DONE          (46)
# define TLMSP_MT_MIDDLEBOX_KEY_MATERIAL        (48)
# define TLMSP_MT_MIDDLEBOX_KEY_CONFIRMATION    (49)
# define TLMSP_MT_MIDDLEBOX_FINISHED            (51)

/*
 * API types and parameter values.
 */

# define TLMSP_CONTEXT_CONTROL          (0u)            /* Reserved/control context.  */
# define TLMSP_CONTEXT_DEFAULT          (1u)            /* Default/initial context.  (implementation-defined) */

typedef uint32_t tlmsp_sid_t;

typedef unsigned char tlmsp_context_id_t;

# define TLMSP_CONTEXT_AUTH_READ        (0x00000001u)   /* Read access. */
# define TLMSP_CONTEXT_AUTH_WRITE       (0x00000002u)   /* Write access (implies read access).  */

typedef unsigned char tlmsp_context_auth_t;

# define TLMSP_CONTEXT_AUDIT_UNCONFIRMED    (0x00000000u)   /* No audit trail.  (default) */
# define TLMSP_CONTEXT_AUDIT_CONFIRMED      (0x00000001u)   /* Audit trail.  */

typedef unsigned char tlmsp_context_audit_t;

# define TLMSP_AUDIT_ORDER_ANY          (0x00000001u)   /* Any order is acceptable.  (default) */
# define TLMSP_AUDIT_ORDER_NETWORK      (0x00000002u)   /* Require audit info in network order.  */

typedef unsigned int tlmsp_audit_order_t;

# define TLMSP_ADDRESS_MAX_SIZE         (2048)

# define TLMSP_CONTAINER_MAX_SIZE       (16383)     /* 4.2.1.3 */

struct tlmsp_container_st;
typedef struct tlmsp_container_st TLMSP_Container;

struct tlmsp_context_st;
typedef struct tlmsp_context_st TLMSP_Context;
DEFINE_STACK_OF(TLMSP_Context)
typedef STACK_OF(TLMSP_Context) TLMSP_Contexts;

struct tlmsp_context_access_st;
typedef struct tlmsp_context_access_st TLMSP_ContextAccess;

struct tlmsp_middlebox_st;
typedef struct tlmsp_middlebox_st TLMSP_Middlebox;
DEFINE_STACK_OF(TLMSP_Middlebox)
typedef STACK_OF(TLMSP_Middlebox) TLMSP_Middleboxes;

struct tlmsp_middlebox_configuration {
    int address_type;
    const char *address;
    int transparent;
    TLMSP_ContextAccess *contexts;
    const char *ca_file_or_dir;
};

struct tlmsp_reconnect_state_st;
typedef struct tlmsp_reconnect_state_st TLMSP_ReconnectState;

/* Alert descriptions.  */
# define TLMSP_AD_MIDDLEBOX_ROUTE_FAILURE           (170)
# define TLMSP_AD_MIDDLEBOX_AUTHORIZATION_FAILURE   (171)
# define TLMSP_AD_MIDDLEBOX_REQUIRED                (172)
# define TLMSP_AD_DISCOVERY_ACK                     (173)
# define TLMSP_AD_UNKNOWN_CONTEXT                   (174)
# define TLMSP_AD_UNSUPPORTED_CONTEXT               (175)
# define TLMSP_AD_MIDDLEBOX_KEY_VERIFY_FAILURE      (176)
# define TLMSP_AD_BAD_READER_MAC                    (177)
# define TLMSP_AD_BAD_WRITER_MAC                    (178)
# define TLMSP_AD_MIDDLEBOX_KEYCONFIRMATION_FAULT   (179)
# define TLMSP_AD_AUTHENTICATION_REQUIRED           (180)

/* SSL_METHODs.  */

const SSL_METHOD *TLMSP_method(void);
const SSL_METHOD *TLMSP_client_method(void);
const SSL_METHOD *TLMSP_server_method(void);
const SSL_METHOD *TLMSP_middlebox_method(void);

/* Connection configuration.  */

int TLMSP_set_contexts(SSL_CTX *, const TLMSP_Contexts *);
int TLMSP_set_contexts_instance(SSL *, const TLMSP_Contexts *);

int TLMSP_set_initial_middleboxes(SSL_CTX *, const TLMSP_Middleboxes *);
int TLMSP_set_initial_middleboxes_instance(SSL *, const TLMSP_Middleboxes *);

int TLMSP_set_audit_order(SSL_CTX *, tlmsp_audit_order_t);
int TLMSP_set_audit_order_instance(SSL *, tlmsp_audit_order_t);

int TLMSP_set_transparent(SSL_CTX *, int, const uint8_t *, size_t);
int TLMSP_set_transparent_instance(SSL *, int, const uint8_t *, size_t);

int TLMSP_get_sid(const SSL *, tlmsp_sid_t *);

typedef int (*TLMSP_discovery_cb_fn) (SSL *s, void *, TLMSP_Middleboxes *);
void TLMSP_set_discovery_cb(SSL_CTX *, TLMSP_discovery_cb_fn, void *);
void TLMSP_set_discovery_cb_instance(SSL *, TLMSP_discovery_cb_fn, void *);

int TLMSP_discovery_get_hash(SSL *, unsigned char *, size_t); /* XXX how does caller determine which hash is in use in order to size buffer / result */

const TLMSP_ReconnectState *TLMSP_get_reconnect_state(SSL *);
int TLMSP_set_reconnect_state(SSL *, const TLMSP_ReconnectState *);
void TLMSP_reconnect_state_free(const TLMSP_ReconnectState *);

# define TLMSP_ADDRESS_URL  0
# define TLMSP_ADDRESS_FQDN 1
# define TLMSP_ADDRESS_IPV4 2
# define TLMSP_ADDRESS_IPV6 3
# define TLMSP_ADDRESS_MAC  4

typedef int (*TLMSP_address_match_cb_fn) (SSL *s, int, const uint8_t *, size_t, void *);
void TLMSP_set_address_match_cb(SSL_CTX *, TLMSP_address_match_cb_fn, void *);
void TLMSP_set_address_match_cb_instance(SSL *, TLMSP_address_match_cb_fn, void *);

int TLMSP_set_client_address(SSL_CTX *, int, const uint8_t *, size_t);
int TLMSP_set_client_address_instance(SSL *, int, const uint8_t *, size_t);
int TLMSP_get_client_address(SSL_CTX *, int *, uint8_t **, size_t *);
int TLMSP_get_client_address_instance(SSL *, int *, uint8_t **, size_t *);
int TLMSP_set_server_address(SSL_CTX *, int, const uint8_t *, size_t);
int TLMSP_set_server_address_instance(SSL *, int, const uint8_t *, size_t);
int TLMSP_get_server_address(SSL_CTX *, int *, uint8_t **, size_t *);
int TLMSP_get_server_address_instance(SSL *, int *, uint8_t **, size_t *);
int TLMSP_get_first_hop_address(SSL_CTX *, int *, uint8_t **, size_t *);
int TLMSP_get_first_hop_address_reconnect(const TLMSP_ReconnectState *, int *, uint8_t **, size_t *);
int TLMSP_get_first_hop_address_reconnect_ex(const TLMSP_ReconnectState *, int *, uint8_t **, size_t *, int);
int TLMSP_get_next_hop_address_instance(SSL *, int *, uint8_t **, size_t *);
int TLMSP_get_next_hop_address_instance_ex(SSL *, int *, uint8_t **, size_t *, int);
int TLMSP_get_next_hop_address_reconnect(const TLMSP_ReconnectState *, int *, uint8_t **, size_t *);
int TLMSP_get_next_hop_address_reconnect_ex(const TLMSP_ReconnectState *, int *, uint8_t **, size_t *, int);

int TLMSP_context_add(TLMSP_Contexts **, tlmsp_context_id_t, const char *, tlmsp_context_audit_t);
void TLMSP_contexts_free(TLMSP_Contexts *);

int TLMSP_context_access_add(TLMSP_ContextAccess **, tlmsp_context_id_t, tlmsp_context_auth_t);
void TLMSP_context_access_free(TLMSP_ContextAccess *);
int TLMSP_context_access_first(const TLMSP_ContextAccess *, tlmsp_context_id_t *);
int TLMSP_context_access_next(const TLMSP_ContextAccess *, tlmsp_context_id_t *);

tlmsp_context_auth_t TLMSP_context_access_auth(const TLMSP_ContextAccess *, tlmsp_context_id_t);

int TLMSP_middlebox_add(TLMSP_Middleboxes **, const struct tlmsp_middlebox_configuration *);
void TLMSP_middleboxes_free(TLMSP_Middleboxes *);
TLMSP_Middlebox *TLMSP_middleboxes_first(const TLMSP_Middleboxes *);
TLMSP_Middlebox *TLMSP_middleboxes_last(const TLMSP_Middleboxes *);
TLMSP_Middlebox *TLMSP_middleboxes_next(const TLMSP_Middleboxes *, const TLMSP_Middlebox *);
int TLMSP_middleboxes_insert_before(TLMSP_Middleboxes *, const TLMSP_Middlebox *, const struct tlmsp_middlebox_configuration *);
int TLMSP_middleboxes_insert_after(TLMSP_Middleboxes *, const TLMSP_Middlebox *, const struct tlmsp_middlebox_configuration *);

int TLMSP_get_middlebox_address(const TLMSP_Middlebox *, int *, uint8_t **, size_t *);
const TLMSP_ContextAccess *TLMSP_middlebox_context_access(const TLMSP_Middlebox *);
int TLMSP_middlebox_dynamic(const TLMSP_Middlebox *);
int TLMSP_middlebox_forbid(TLMSP_Middlebox *);

/* Connection establishment.  */

int TLMSP_middlebox_handshake(SSL *, SSL *, int *);

/* Client and Server read/write.  */

int TLMSP_set_current_context(SSL *, tlmsp_context_id_t);
int TLMSP_get_current_context(SSL *, tlmsp_context_id_t *);
int TLMSP_get_last_read_context(SSL *, tlmsp_context_id_t *);

/* Container access.  */

int TLMSP_container_read(SSL *, TLMSP_Container **);
int TLMSP_container_write(SSL *, TLMSP_Container *);
int TLMSP_container_delete(SSL *, TLMSP_Container *);

int TLMSP_container_verify(SSL *, const TLMSP_Container *);

int TLMSP_container_create(SSL *, TLMSP_Container **, tlmsp_context_id_t, const void *, size_t);
int TLMSP_container_create_alert(SSL *, TLMSP_Container **, tlmsp_context_id_t, int);
void TLMSP_container_free(SSL *, TLMSP_Container *);

tlmsp_context_id_t TLMSP_container_context(const TLMSP_Container *);
size_t TLMSP_container_length(const TLMSP_Container *);
int TLMSP_container_alert(const TLMSP_Container *c, int *);
int TLMSP_container_deleted(const TLMSP_Container *c);
int TLMSP_container_readable(const TLMSP_Container *c);
int TLMSP_container_writable(const TLMSP_Container *c);
const void *TLMSP_container_get_data(const TLMSP_Container *);
int TLMSP_container_set_data(TLMSP_Container *, const void *, size_t);

#ifdef __cplusplus
}
#endif

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
