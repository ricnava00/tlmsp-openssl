/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_CON_H
# define HEADER_TLMSP_CON_H

#include "tlmsp_key.h"

enum tlmsp_container_status {
    TLMSP_CS_SENDING,
    TLMSP_CS_RECEIVED_NO_ACCESS,
    TLMSP_CS_RECEIVED_READONLY,
    /* XXX Not yet: TLMSP_CS_RECEIVED_FAULT, for containers with detectable errors.  */
    TLMSP_CS_RECEIVED_PRISTINE,
    TLMSP_CS_RECEIVED_MODIFIED,
    TLMSP_CS_DELETED,
};

/*
 * True if we are sending, i.e. if we are going to encrypt and generate new
 * MACs.  Otherwise, in the send path, we should use the original MAC and
 * ciphertext; we are just forwarding.
 *
 * XXX
 * In the RECEIVED_MODIFIED case, there is additional logic needed to enable
 * the correct nonce behaviour per spec, and modification flags, etc.
 */
#define TLMSP_ENVELOPE_SENDING(e)               ((e)->status == TLMSP_CS_SENDING || (e)->status == TLMSP_CS_RECEIVED_MODIFIED || (e)->status == TLMSP_CS_DELETED)

/*
 * True if this is a container we are forwarding verbatim, either:
 *
 * 1. We couldn't decrypt it if we wanted to;
 * 2. We had only read-only access to it in the first place;
 * 3. Or we had access to write it, but left it pristine.
 */
#define TLMSP_ENVELOPE_FORWARDING(e)            ((e)->status == TLMSP_CS_RECEIVED_NO_ACCESS || (e)->status == TLMSP_CS_RECEIVED_READONLY || (e)->status == TLMSP_CS_RECEIVED_PRISTINE)

struct tlmsp_envelope {
    tlmsp_context_id_t cid;
    tlmsp_middlebox_id_t src;
    tlmsp_middlebox_id_t dst;
    enum tlmsp_key_set keys;
    enum tlmsp_container_status status;
};

#define TLMSP_ENVELOPE_INIT(env, xcid, xsrc, xdst, xstatus) do { \
    (env)->cid = (xcid); \
    (env)->src = (xsrc); \
    (env)->dst = (xdst); \
    (env)->keys = TLMSP_KEY_SET_NORMAL; \
    (env)->status = (xstatus); \
} while (0)

#define TLMSP_ENVELOPE_INIT_SSL_WRITE(env, xcid, ssl)   TLMSP_ENVELOPE_INIT((env), (xcid), TLMSP_MIDDLEBOX_ID_SELF(ssl), TLMSP_MIDDLEBOX_ID_PEER(ssl), TLMSP_CS_SENDING)
#define TLMSP_ENVELOPE_INIT_SSL_READ(env, xcid, ssl)    TLMSP_ENVELOPE_INIT((env), (xcid), TLMSP_MIDDLEBOX_ID_PEER(ssl), TLMSP_MIDDLEBOX_ID_SELF(ssl), TLMSP_CS_RECEIVED_PRISTINE)

enum tlmsp_direction {
    TLMSP_D_CTOS,
    TLMSP_D_STOC,
};

#define TLMSP_CONTAINER_FLAG_INSERTED                   (0x8000)
#define TLMSP_CONTAINER_FLAG_DELETED                    (0x4000)
#define TLMSP_CONTAINER_FLAG_AUDIT_CONTENT              (0x2000)
#define TLMSP_CONTAINER_FLAG_ADDITIONAL_FORWARDING_MACS (0x1000)
#define TLMSP_CONTAINER_FLAGS_DEFAULT                   (0x0000)

#define TLMSP_CONTAINER_HAVE_M_INFO(c)                  (((c)->flags & (TLMSP_CONTAINER_FLAG_INSERTED | TLMSP_CONTAINER_FLAG_DELETED)) != 0)

#define TLMSP_CONTAINER_ORDER_RESERVED                  (255)

#define TLMSP_CONTAINER_MAX_AF                          (255)

#define TLMSP_CONTAINER_M_INFO_MAX_DELETE_INDICATORS    (255)

#define TLMSP_CONTAINER_FM_FLAG_INSERTED                (0x80)
#define TLMSP_CONTAINER_FM_FLAG_DELETED                 (0x40)
#define TLMSP_CONTAINER_FM_FLAG_AUDIT_CONTENT           (0x20)

/*
 * These correspond to (but are in-memory representations and not wire format)
 * TLMSP container-related protocol data types.
 */
struct tlmsp_delete_indicator {
    uint8_t source_ID;
    uint16_t delete_count;
};

struct tlmsp_forwarding_mac {
    uint8_t id;
    uint8_t order;
    uint8_t flags;
    uint8_t outboundReaderCheckMAC[EVP_MAX_MD_SIZE];
    uint8_t nonce[EVP_MAX_IV_LENGTH];
    uint8_t checkMAC[EVP_MAX_MD_SIZE];
};

struct tlmsp_m_info {
    uint8_t m_id;
    uint8_t n;
    struct tlmsp_delete_indicator delete_indicators[256];
};

struct tlmsp_container_st {
    int type;
    struct tlmsp_envelope envelope;

    uint16_t flags;
    struct tlmsp_m_info mInfo;
    size_t ciphertextlen;
    uint8_t ciphertext[TLMSP_MAX_CONTAINER_FRAGMENT_SCRATCH];
    size_t plaintextlen;
    uint8_t plaintext[TLMSP_CONTAINER_MAX_SIZE];
    uint8_t writer_mac[EVP_MAX_MD_SIZE];
    struct tlmsp_forwarding_mac forwarding_mac;
    uint8_t nAF;
    struct tlmsp_forwarding_mac additional_forwarding_macs[256];

    uint8_t audit_flags;
};

int tlmsp_container_deliver_alert(SSL *, TLMSP_Container *);
int tlmsp_container_parse(SSL *, TLMSP_Container **, int, const uint8_t *, size_t);

enum tlmsp_direction tlmsp_envelope_direction(const SSL *, const struct tlmsp_envelope *);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
