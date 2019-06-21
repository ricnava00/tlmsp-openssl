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
#define TLMSP_ENVELOPE_SENDING(e)               ((e)->status == TLMSP_CS_SENDING || (e)->status == TLMSP_CS_RECEIVED_MODIFIED)

/*
 * True if this is a container we are forwarding verbatim, either:
 *
 * 1. We couldn't decrypt it if we wanted to;
 * 2. We had only read-only access to it in the first place;
 * 3. Or we had access to write it, but left it pristine.
 */
#define TLMSP_ENVELOPE_FORWARDING(e)            ((e)->status == TLMSP_CS_RECEIVED_NO_ACCESS || (e)->status == TLMSP_CS_RECEIVED_READONLY || (e)->status == TLMSP_CS_RECEIVED_PRISTINE)

/*
 * XXX
 * Should we just put an enum tlmsp_direction in here?  Isn't CTOS vs. STOC
 * more meaningful than source/destination for most things?  It seems like that
 * should be checked rather than checking src/dst except for a small, small
 * number of messages.
 */
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

#define TLMSP_ENVELOPE_INIT_SSL_WRITE(env, xcid, ssl)   TLMSP_ENVELOPE_INIT((env), (xcid), (ssl)->tlmsp.self_id, (ssl)->tlmsp.peer_id, TLMSP_CS_SENDING)
#define TLMSP_ENVELOPE_INIT_SSL_READ(env, xcid, ssl)    TLMSP_ENVELOPE_INIT((env), (xcid), (ssl)->tlmsp.peer_id, (ssl)->tlmsp.self_id, TLMSP_CS_RECEIVED_PRISTINE)

enum tlmsp_direction {
    TLMSP_D_CTOS,
    TLMSP_D_STOC,
};

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

    uint8_t contextId;
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

    /*
     * XXX
     * Here is where we will add verification information, i.e. about whether
     * we have been able to decrypt, whether we have been able to verify MACs,
     * etc.
     */
};

enum tlmsp_direction tlmsp_envelope_direction(const SSL *, const struct tlmsp_envelope *);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
