/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#include "internal/cryptlib.h"
#include "ssl_locl.h"
#include "record/record_locl.h"
#include "statem/statem_locl.h"
#include <openssl/rand.h>
#include <openssl/tlmsp.h>

static int tlmsp_construct_address(SSL *, WPACKET *, const struct tlmsp_address *);
static int tlmsp_parse_address(SSL *, PACKET *, int, struct tlmsp_address *);

static int tlmsp_construct_context_list(SSL *, WPACKET *);
static int tlmsp_parse_context_list(SSL *, PACKET *);

static int tlmsp_construct_middlebox_list(SSL *, WPACKET *, int, int);
static int tlmsp_parse_middlebox_list(SSL *, PACKET *, int, int);

/* TLMSP extension.  */

int
init_tlmsp(SSL *s, unsigned int context)
{
    return 1;
}

int
final_tlmsp(SSL *s, unsigned int context, int sent)
{
    /*
     * Don't do any finalization for a non-TLMSP SSL.
     *
     * We won't have done any parse work in a non-TLMSP case because the
     * extension is not "relevant" in the terms of extensions.c.
     */
    if (!SSL_IS_TLMSP(s))
        return 1;

    if (s->server) {
        if (!sent) {
            /*
             * Server did not receive a TLMSP extension, this is an error.
             */
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_FINAL_TLMSP, SSL_R_EXTENSION_NOT_RECEIVED);
            return 0;
        }

        s->tlmsp.self = &s->tlmsp.server_middlebox;

        s->tlmsp.alert_container = 1;
        return 1;
    }

    if (sent) {
        s->tlmsp.self = &s->tlmsp.client_middlebox;

        s->tlmsp.alert_container = 1;
        return 1;
    }

    /*
     * Client did not receive a TLMSP extension.  Fall back to TLS.
     *
     * TODO
     * Annex B.1 suggests we may want to add a knob for determining whether to
     * allow the observed middleboxes to remain on path, i.e. whether to
     * fallback automatically as we do now or to error out and connect without
     * the middleboxes.  This is only meaningful for non-transparent
     * middleboxes.
     */
    fprintf(stderr, "session %p fallback to TLSv1.2\n", (void *)s);
    s->method = tlsv1_2_client_method();
    s->version = TLMSP_TLS_VERSION(s->version);
    return 1;
}

EXT_RETURN
tlmsp_construct_ctos_tlmsp(SSL *s, WPACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{
    if (!SSL_IS_TLMSP(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_tlmsp) ||
        !WPACKET_start_sub_packet_u16(pkt) ||
        !WPACKET_put_bytes_u8(pkt, TLMSP_VERSION_MAJOR) ||
        !WPACKET_put_bytes_u8(pkt, TLMSP_VERSION_MINOR) ||
        !tlmsp_construct_address(s, pkt, &s->tlmsp.client_middlebox.state.address) ||
        !tlmsp_construct_address(s, pkt, &s->tlmsp.server_middlebox.state.address) ||
        !WPACKET_put_bytes_u8(pkt, s->tlmsp.is_post_discovery ? 1 : 0) ||
        !tlmsp_construct_middlebox_list(s, pkt, 0, 1)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_CTOS_TLMSP, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    if (s->tlmsp.is_post_discovery) {
        if (!WPACKET_put_bytes_u32(pkt, s->tlmsp.sid) ||
            !WPACKET_sub_memcpy_u8(pkt, s->tlmsp.post_discovery_hash, s->tlmsp.post_discovery_hashlen) ||
            !tlmsp_construct_middlebox_list(s, pkt, 0, 0)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_CTOS_TLMSP, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    }

    if (!WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_CTOS_TLMSP, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

int
tlmsp_parse_ctos_tlmsp(SSL *s, PACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{
    unsigned int major, minor;
    unsigned int client_discovery_ack;
    unsigned long sid;
    PACKET hash_data;    

    if (!SSL_IS_TLMSP(s)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!PACKET_get_1(pkt, &major) || !PACKET_get_1(pkt, &minor) ||
        major != TLMSP_VERSION_MAJOR || minor != TLMSP_VERSION_MINOR) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_parse_address(s, pkt, 0, &s->tlmsp.client_middlebox.state.address) ||
        !tlmsp_parse_address(s, pkt, 0, &s->tlmsp.server_middlebox.state.address)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!PACKET_get_1(pkt, &client_discovery_ack) || (client_discovery_ack > 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }
    s->tlmsp.is_post_discovery = client_discovery_ack;

    if (!tlmsp_parse_middlebox_list(s, pkt, 0, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (client_discovery_ack) {
        if (!PACKET_get_net_4(pkt, &sid)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
            return 0;
        }
        if (!PACKET_get_length_prefixed_1(pkt, &hash_data) ||
            (PACKET_remaining(&hash_data) > sizeof(s->tlmsp.post_discovery_hash))) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
            return 0;
        }
        s->tlmsp.post_discovery_hashlen = PACKET_remaining(&hash_data); 
        if (!PACKET_copy_bytes(&hash_data, s->tlmsp.post_discovery_hash, s->tlmsp.post_discovery_hashlen) || 
            !tlmsp_parse_middlebox_list(s, pkt, 0, 0)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
            return 0;
        }
        s->tlmsp.have_sid = 1;
        s->tlmsp.sid = sid;
    }

    /* Unrecognized additional data in TLMSP extension.  */
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    return 1;
}

EXT_RETURN
tlmsp_construct_stoc_tlmsp(SSL *s, WPACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{
    if (!SSL_IS_TLMSP(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_tlmsp) ||
        !WPACKET_start_sub_packet_u16(pkt) ||
        !WPACKET_put_bytes_u8(pkt, TLMSP_VERSION_MAJOR) ||
        !WPACKET_put_bytes_u8(pkt, TLMSP_VERSION_MINOR) ||
        !tlmsp_write_sid(s, pkt) ||
        !tlmsp_construct_address(s, pkt, &s->tlmsp.client_middlebox.state.address) ||
        !tlmsp_construct_address(s, pkt, &s->tlmsp.server_middlebox.state.address) ||
        !tlmsp_construct_middlebox_list(s, pkt, 1, 1) ||
        !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_STOC_TLMSP, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

int
tlmsp_parse_stoc_tlmsp(SSL *s, PACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{
    unsigned int major, minor;

    if (!SSL_IS_TLMSP(s)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_STOC_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!PACKET_get_1(pkt, &major) || !PACKET_get_1(pkt, &minor) ||
        major != TLMSP_VERSION_MAJOR || minor != TLMSP_VERSION_MINOR) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_STOC_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_read_sid(s, pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_STOC_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_parse_address(s, pkt, 1, &s->tlmsp.client_middlebox.state.address) ||
        !tlmsp_parse_address(s, pkt, 1, &s->tlmsp.server_middlebox.state.address)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_STOC_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_parse_middlebox_list(s, pkt, 1, 1)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_STOC_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* Unrecognized additional data in TLMSP extension.  */
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_STOC_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    return 1;
}

/* TLMSP ContextList extension.  */

int
init_tlmsp_context_list(SSL *s, unsigned int context)
{
    return 1;
}

int
final_tlmsp_context_list(SSL *s, unsigned int context, int sent)
{
    if (!SSL_IS_TLMSP(s))
        return 1;

    if (!sent) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_FINAL_TLMSP_CONTEXT_LIST, SSL_R_EXTENSION_NOT_RECEIVED);
        return 0;
    }

    return 1;
}

EXT_RETURN
tlmsp_construct_ctos_tlmsp_context_list(SSL *s, WPACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{
    if (!SSL_IS_TLMSP(s))
        return EXT_RETURN_NOT_SENT;

    if (!WPACKET_put_bytes_u16(pkt, TLSEXT_TYPE_tlmsp_context_list) ||
        !WPACKET_start_sub_packet_u16(pkt) ||
        !tlmsp_construct_context_list(s, pkt) ||
        !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_CTOS_TLMSP_CONTEXT_LIST, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

int
tlmsp_parse_ctos_tlmsp_context_list(SSL *s, PACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{

    if (!SSL_IS_TLMSP(s)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_parse_context_list(s, pkt)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /* Unrecognized additional data in TLMSP ContextList extension.  */
    if (PACKET_remaining(pkt) != 0) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    return 1;
}

/* Local functions.  */

static int
tlmsp_construct_address(SSL *s, WPACKET *pkt, const struct tlmsp_address *adr)
{
    if (!WPACKET_put_bytes_u8(pkt, adr->address_type) ||
        !WPACKET_sub_memcpy_u16(pkt, adr->address, adr->address_len))
        return 0;
    return 1;
}

static int
tlmsp_parse_address(SSL *s, PACKET *pkt, int checkonly, struct tlmsp_address *adr)
{
    unsigned int wire_type;
    PACKET wire_address;

    if (!PACKET_get_1(pkt, &wire_type) ||
        !PACKET_get_length_prefixed_2(pkt, &wire_address))
        return 0;

    if (adr == NULL)
        return 1;

    if (checkonly) {
        if ((int)wire_type != adr->address_type ||
            PACKET_remaining(&wire_address) != adr->address_len ||
            memcmp(PACKET_data(&wire_address), adr->address, adr->address_len) != 0)
            return 0;
        return 1;
    }

    if (PACKET_remaining(&wire_address) != 0) {
        if (!tlmsp_address_set(adr, wire_type, PACKET_data(&wire_address), PACKET_remaining(&wire_address)))
            return 0;
    } else {
        /*
         * XXX
         * This is a bit of a hack.  Really, we shouldn't allow this to happen,
         * and the address should have a sensible default retrieved from the
         * underlying BIO or similar.
         */
        adr->address_type = wire_type;
        adr->address_len = 0;
    }

    return 1;
}

static int
tlmsp_construct_context_list(SSL *s, WPACKET *pkt)
{
    const struct tlmsp_context_instance_state *tcis;
    unsigned j;

    if (!WPACKET_start_sub_packet_u16(pkt))
        return 0;

    for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
        tcis = &s->tlmsp.context_states[j];
        if (j == TLMSP_CONTEXT_CONTROL || !tcis->state.present)
            continue;

        if (!WPACKET_put_bytes_u8(pkt, j) ||
            !WPACKET_put_bytes_u8(pkt, tcis->state.audit) ||
            !WPACKET_put_bytes_u8(pkt, 0) || /* XXX origin_verification */
            !WPACKET_sub_memcpy_u8(pkt, tcis->state.purpose, tcis->state.purposelen))
            return 0;
    }

    if (!WPACKET_close(pkt))
        return 0;
    return 1;
}

static int
tlmsp_parse_context_list(SSL *s, PACKET *pkt)
{
    struct tlmsp_context_instance_state *tcis;
    unsigned int cid, audit, origin_verification;
    PACKET context_descriptions, purpose;

    if (!PACKET_get_length_prefixed_2(pkt, &context_descriptions)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    /*
     * If the TLMSP spec establishes that a ContextList should not change in
     * subsequent hellos, we should at this point do more than we do here,
     * which is to check for changes to contexts included in it, and also check
     * for contexts omitted from it.
     */
    while (PACKET_remaining(&context_descriptions)) {
        if (!PACKET_get_1(&context_descriptions, &cid) ||
            !PACKET_get_1(&context_descriptions, &audit) ||
            !PACKET_get_1(&context_descriptions, &origin_verification) ||
            !PACKET_get_length_prefixed_1(&context_descriptions, &purpose)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }
        if (cid == TLMSP_CONTEXT_CONTROL) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        tcis = &s->tlmsp.context_states[cid];
        if (!SSL_IS_FIRST_HANDSHAKE(s)) {
            /*
             * If this is a context that was not in the last ContextList, or if
             * any of the parameters have changed, alert accordingly.
             */
            if (!tcis->state.present ||
                tcis->state.audit != audit ||
                origin_verification != 0 ||
                tcis->state.purposelen != PACKET_remaining(&purpose) ||
                memcmp(tcis->state.purpose, PACKET_data(&purpose), tcis->state.purposelen) != 0) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }
            /* We have verified the extension during renegotiate.  */
            continue;
        }
        if (!TLMSP_IS_MIDDLEBOX(s)) {
            /*
             * We should not be told about a context twice.
             */
            if (tcis->state.present) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }
        } else {
            /*
             * We are a middlebox, we infer context presence earlier through
             * the context access information.  If the ContextList were a part
             * of the ClientHello and occurred prior to the MiddleboxList, this
             * would all flow better.
             */
        }

        switch (audit) {
        case TLMSP_CONTEXT_AUDIT_UNCONFIRMED:
        case TLMSP_CONTEXT_AUDIT_CONFIRMED:
            break;
        default:
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }
        tcis->state.audit = audit;

        switch (origin_verification) {
        case 0:
            break;
        default:
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CONTEXT_LIST, SSL_R_BAD_EXTENSION);
            return 0; /* XXX */
        }

        tcis->state.present = 1;
        tcis->state.purposelen = PACKET_remaining(&purpose);
        if (tcis->state.purposelen != 0)
            memcpy(tcis->state.purpose, PACKET_data(&purpose), tcis->state.purposelen);
    }

    return 1;
}

static int
tlmsp_construct_middlebox_list(SSL *s, WPACKET *pkt, int stoc, int primary)
{
    const TLMSP_MiddleboxInstance *tmis;
    const struct tlmsp_context_instance_state *tcis;
    int use_initial;
    unsigned ncontexts;
    unsigned wire_auth;
    unsigned j;

    /*
     * When constructing the primary middlebox list for in the
     * client-to-server direction after discovery, work from the initial
     * list.  In all other cases, work from the current list.
     */
    if (!stoc && s->tlmsp.is_post_discovery && primary)
        use_initial = 1;
    else
        use_initial = 0;
#if 0
    fprintf(stderr, "%s: direction=%s primary=%s post_discovery=%s use_initial=%s\n",
        __func__,
        stoc ? "stoc" : "ctos",
        primary ? "yes" : "no",
        s->tlmsp.is_post_discovery ? "yes" : "no",
        use_initial ? "yes" : "no");
#endif
    if (!WPACKET_start_sub_packet_u16(pkt))
        return 0;

    for (tmis = use_initial ? tlmsp_middlebox_first_initial(s) : tlmsp_middlebox_first(s);
         tmis != NULL;
         tmis = use_initial ? tlmsp_middlebox_next_initial(s, tmis) : tlmsp_middlebox_next(s, tmis)) {
#if 0
        fprintf(stderr, "%s:  id=%u inserted=%s transparent=%s\n",
            __func__, tmis->state.id,
            (tmis->state.inserted == 0) ? "static" :
            (tmis->state.inserted == 1) ? "dynamic" :
            (tmis->state.inserted == 2) ? "forbidden" : "<unknown>",
            tmis->state.transparent ? "yes" : "no");
#endif
        if (!WPACKET_put_bytes_u8(pkt, tmis->state.id) ||
            !tlmsp_construct_address(s, pkt, &tmis->state.address) ||
            !WPACKET_put_bytes_u8(pkt, tmis->state.inserted) ||
            !WPACKET_put_bytes_u8(pkt, tmis->state.transparent ? 1 : 0) ||
            !WPACKET_sub_memcpy_u16(pkt, NULL, 0)) { /* XXX ticket */
            return 0;
        }

        ncontexts = 0;
        for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
            tcis = &s->tlmsp.context_states[j];
            if (!tcis->state.present)
                continue;
            switch (tmis->state.access.contexts[j]) {
            case TLMSP_CONTEXT_AUTH_READ:
            case TLMSP_CONTEXT_AUTH_WRITE:
                break;
            default:
                continue;
            }
            ncontexts++;
        }

        if (!WPACKET_put_bytes_u8(pkt, ncontexts))
            return 0;
        for (j = 0; j < TLMSP_CONTEXT_COUNT; j++) {
            tcis = &s->tlmsp.context_states[j];
            if (!tcis->state.present)
                continue;
            switch (tmis->state.access.contexts[j]) {
            case TLMSP_CONTEXT_AUTH_READ:
                wire_auth = 0;
                break;
            case TLMSP_CONTEXT_AUTH_WRITE:
                wire_auth = 1;
                break;
            default:
                continue;
            }
            if (!WPACKET_put_bytes_u8(pkt, (tlmsp_context_id_t)j) ||
                !WPACKET_put_bytes_u8(pkt, wire_auth)) {
                return 0;
            }
        }
    }

    if (!WPACKET_close(pkt))
        return 0;
    return 1;
}

static int
tlmsp_parse_middlebox_list(SSL *s, PACKET *pkt, int stoc, int primary)
{
    TLMSP_Middleboxes *parsed_mboxes;
    TLMSP_Middlebox parsed_mbox;
    TLMSP_ContextAccess *access;
    uint8_t middlebox_ids[TLMSP_MIDDLEBOX_COUNT];
    uint8_t context_present[TLMSP_CONTEXT_COUNT];
    PACKET middlebox_infos, ticket;
    unsigned int uint_val;
    unsigned int ncontexts;
    unsigned int cid, wire_auth;
    tlmsp_context_auth_t auth;
    TLMSP_MiddleboxInstances **initial_list, **current_list;
    TLMSP_MiddleboxInstances **compare_list;
    int post_discovery;
    int strictly_equal;
    int path_changed;
    int check_reconnect;
    int do_callback;
    int set_initial;
    int set_current;
    int i;
    int ret;

    /*
     * In all cases, we begin by parsing the entire middlebox list and
     * performing basic validation.
     */
    ret = 0;
    parsed_mboxes = NULL;
    memset(middlebox_ids, 0, sizeof middlebox_ids);
    memset(context_present, 0, sizeof context_present);

    if (!PACKET_get_length_prefixed_2(pkt, &middlebox_infos)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
        goto out;
    }

    while (PACKET_remaining(&middlebox_infos) != 0) {
        if (!PACKET_get_1(&middlebox_infos, &uint_val)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }
        parsed_mbox.id = uint_val;

        if ((parsed_mbox.id < TLMSP_MIDDLEBOX_ID_FIRST) ||
            (parsed_mbox.id > TLMSP_MIDDLEBOX_ID_LAST)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }

        if (middlebox_ids[parsed_mbox.id] != TLMSP_MIDDLEBOX_ID_NONE) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }
        middlebox_ids[parsed_mbox.id] = 1;
        
        if (!tlmsp_parse_address(s, &middlebox_infos, 0, &parsed_mbox.address)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }

        if (!PACKET_get_1(&middlebox_infos, &uint_val)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }
        parsed_mbox.inserted = uint_val;

        if (!PACKET_get_1(&middlebox_infos, &uint_val)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }
        parsed_mbox.transparent = uint_val;

        if (!PACKET_get_length_prefixed_2(&middlebox_infos, &ticket)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }
#if 0
        fprintf(stderr, "%s:  id=%u inserted=%s transparent=%s\n",
            __func__, parsed_mbox.id,
            (parsed_mbox.inserted == 0) ? "static" :
            (parsed_mbox.inserted == 1) ? "dynamic" :
            (parsed_mbox.inserted == 2) ? "forbidden" : "<unknown>",
            parsed_mbox.transparent ? "yes" : "no");
#endif
        switch (parsed_mbox.inserted) {
        case 0: /* static */
        case 1: /* dynamic */
            break;
        case 2: /* XXX forbidden */
        default:
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }

        switch (parsed_mbox.transparent) {
        case 0:
        case 1:
            break;
        default:
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }

        if (PACKET_remaining(&ticket) != 0) { /* XXX - resumption not yet supported */
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }

        if (!PACKET_get_1(&middlebox_infos, &ncontexts) ||
            ncontexts > TLMSP_CONTEXT_COUNT) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }

        tlmsp_context_access_clear(&parsed_mbox.access);
        while (ncontexts--) {
            if (!PACKET_get_1(&middlebox_infos, &cid) ||
                !PACKET_get_1(&middlebox_infos, &wire_auth)) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                goto out;
            }

            switch (wire_auth) {
            case 0:
                auth = TLMSP_CONTEXT_AUTH_READ;
                break;
            case 1:
                auth = TLMSP_CONTEXT_AUTH_WRITE;
                break;
            default:
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                goto out;
            }
            context_present[cid] = 1;

#if 0
            fprintf(stderr, "%s:    context_id=%u auth=0x%02x\n",
                __func__, cid, auth);
#endif
            /*
             * TLMSP_context_access_add will detect duplicate cids in the list.
             */
            access = &parsed_mbox.access;
            if (!TLMSP_context_access_add(&access, cid, auth)) {
                /* Assume error was duplicate cid */
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                goto out;
            }
        }

        if (!tlmsp_middlebox_add(&parsed_mboxes, &parsed_mbox)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, ERR_R_INTERNAL_ERROR);
            goto out;
        }
    }

    /*
     * The next steps depend on a number of factors.
     *
     * +-----------+------+------+-------+-------------------------------------+
     * |           | post |      |       |                                     |
     * | entity    | disc.| stoc |primary| action                              |
     * +-----------+------+------+-------+-------------------------------------+
     * | client    | false| true | true  | Compare to initial middlebox list,  |
     * |           |      |      |       | give to application for auth, and   |
     * |           |      |      |       | set current middlebox list          |
     * |           +------+------+-------+-------------------------------------+
     * |           | true | true | true  | Compare to current middlebox list   |
     * +-----------+------+------+-------+-------------------------------------+
     * | middlebox | false| false| true  | Edit, set current middlebox list    |
     * |           +------+------+-------+-------------------------------------+
     * |           | false| true | true  | Parse w/ basic validation           |
     * |           +------+------+-------+-------------------------------------+
     * |           | true | false| true  | Set initial middlebox list          |
     * |           +------+------+-------+-------------------------------------+
     * |           | true | false| false | Set current middlebox list          |
     * |           +------+------+-------+-------------------------------------+
     * |           | true | true | true  | Parse w/ basic validation           |
     * +-----------+------+------+-------+-------------------------------------+
     * | server    | false| false| true  | Give to application for auth and    |
     * |           |      |      |       | edit; set current middlebox list    |
     * |           +------+------+-------+-------------------------------------+
     * |           | true | false| true  | Parse w/ basic validation           |
     * |           +------+------+-------+-------------------------------------+
     * |           | true | false| false | Give to application for auth;       |
     * |           |      |      |       | set current middlebox list          |
     * +-----------+------+------+-------+-------------------------------------+
     *
     */
    post_discovery = s->tlmsp.is_post_discovery;
    initial_list = &s->tlmsp.initial_middlebox_list;
    current_list = &s->tlmsp.current_middlebox_list;
    compare_list = NULL;
    strictly_equal = 0;
    path_changed = 0;
    check_reconnect = 0;
    do_callback = 0;
    set_initial = 0;
    set_current = 0;
    if (TLMSP_IS_MIDDLEBOX(s)) {
        /*
         * Middlebox
         */
        if (!post_discovery && !stoc && primary) {
            /* This is the middlebox list in an initial ClientHello */
            /* XXX if this is a transparent middlebox, insert into the parsed list here */
            set_current = 1;
        } else if (post_discovery && !stoc) {
            if (primary) {
                /*
                 * This is the mL list in a post-discovery ClientHello.  We
                 * use it to set the initial middlebox list so it can be
                 * used to construct the outbound ClientHello.
                 */
                set_initial = 1;
            } else {
                /* This is the mD list in a post-discovery ClientHello */
                set_current = 1;
            }
        }
    } else if (s->server) {
        /*
         * Server
         */
        if (!post_discovery && !stoc && primary) {
            /* This is the middlebox list in an initial ClientHello */
            do_callback = 1;
            set_current = 1;
        } else if (post_discovery && !stoc && !primary) {
            /*
             * This is the mD list in a post-discovery ClientHello.  We are
             * assuming in general there is a reconnect and we are handling
             * it statelessly, so just ask the application to re-authorize.
             */
            do_callback = 1;
            set_current = 1;
        }
    } else {
        /*
         * Client
         */
        if (!post_discovery && stoc && primary) {
            /* This is the middlebox list in an initial ServerHello */
            compare_list = initial_list;
            do_callback = 1;
            set_current = 1;
            check_reconnect = 1;
        } else if (post_discovery && stoc && primary) {
            /* This is the middlebox list in a post-discovery ServerHello */
            compare_list = current_list;
            strictly_equal = 1;
        }
    }

    if (compare_list &&
        !tlmsp_middleboxes_compare(*compare_list, parsed_mboxes, strictly_equal, &path_changed)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
        goto out;
    }

    if (do_callback) {
        /*
         * Ensure an empty middlebox list is represented by an empty list
         * and not NULL for the callback.
         */
        if (!tlmsp_middlebox_add(&parsed_mboxes, NULL)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, ERR_R_INTERNAL_ERROR);
            goto out;
        }
        if (!s->tlmsp.discovery_cb || !s->tlmsp.discovery_cb(s, s->tlmsp.discovery_cb_arg, parsed_mboxes)) {
            /* XXX default reject when no callback is installed may not be appropriate in all cases */
            SSLfatal(s, TLMSP_AD_MIDDLEBOX_AUTHORIZATION_FAILURE,
                     SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_TLMSP_ALERT_MIDDLEBOX_AUTHORIZATION_FAILURE);
            goto out;
        }
    }

    if (set_initial) {
        /*
         * This should only happen once, so there is no need to clear the
         * initial list first.  It is also only used for construction of an
         * outbound ClientHello, so there is no need to compile it after
         * setting it.
         */
        if (!tlmsp_set_middlebox_list(initial_list, parsed_mboxes)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }
    }

    if (set_current) {
        tlmsp_middleboxes_clear_current(s);
        if (!tlmsp_set_middlebox_list(current_list, parsed_mboxes)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }
        if (!tlmsp_middlebox_table_compile_current(s)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            goto out;
        }

        /*
         * On a middlebox, when the current middlebox list is updated,
         * establish context presence and update self.
         */
        if (TLMSP_IS_MIDDLEBOX(s)) {
            /*
             * XXX This is a hack to account for the context list extension
             * occurring after the TLMSP extension.
             */
            for (i = 0; i < TLMSP_CONTEXT_COUNT; i++) {
                if (context_present[i])
                    s->tlmsp.context_states[i].state.present = 1;
            }
            tlmsp_middlebox_establish_id(s);
        }
    }

    if (check_reconnect && (path_changed || s->tlmsp.always_reconnect)) {
        /*
         * Setting this flag will result in the ServerHello processing
         * terminating with an error after all extensions are processed, and
         * subsequent calls to SSL_get_error() will return
         * SSL_ERROR_WANT_RECONNECT.
         */
        s->tlmsp.need_reconnect = 1;
    }

    ret = 1;
out:
    TLMSP_middleboxes_free(parsed_mboxes);
    return ret;
}    

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
