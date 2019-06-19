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

/*
 * XXX
 * Should we just put an enum tlmsp_direction in here?  Isn't CTOS vs. STOC
 * more meaningful than source/destination for most things?  It seems like that
 * should be checked rather than checking src/dst except for a small, small
 * number of messages.
 */
struct tlmsp_envelope {
    /*
     * XXX
     * State tracking enum to base crypto treatment decisions on
     *
     * Received,
     * Sending,
     * Forwarding, XXX Including whether we are intending to verify, to decrypt, whether we have changed it, etc.
     */
    tlmsp_context_id_t cid;
    tlmsp_middlebox_id_t src;
    tlmsp_middlebox_id_t dst;
    enum tlmsp_key_set keys;
};

#define TLMSP_ENVELOPE_INIT(env, xcid, xsrc, xdst) do { \
    (env)->cid = (xcid); \
    (env)->src = (xsrc); \
    (env)->dst = (xdst); \
    (env)->keys = TLMSP_KEY_SET_NORMAL; \
} while (0)

#define TLMSP_ENVELOPE_INIT_SSL_WRITE(env, xcid, ssl)   TLMSP_ENVELOPE_INIT((env), (xcid), (ssl)->tlmsp.self_id, (ssl)->tlmsp.peer_id)
#define TLMSP_ENVELOPE_INIT_SSL_READ(env, xcid, ssl)    TLMSP_ENVELOPE_INIT((env), (xcid), (ssl)->tlmsp.peer_id, (ssl)->tlmsp.self_id)

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
    /*
     * XXX Internal bits to track whether we know this to have been modified
     * by us, i.e. whether we are rewriting the fragment, go here.
     */
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
};

enum tlmsp_direction tlmsp_envelope_direction(const SSL *, const struct tlmsp_envelope *);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
