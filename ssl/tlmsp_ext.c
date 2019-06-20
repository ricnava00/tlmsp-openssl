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

#pragma clang diagnostic error "-Wmissing-prototypes"

static int tlmsp_construct_address(SSL *, WPACKET *, const struct tlmsp_address *);
static int tlmsp_parse_address(SSL *, PACKET *, int, struct tlmsp_address *);

static int tlmsp_construct_context_list(SSL *, WPACKET *);
static int tlmsp_parse_context_list(SSL *, PACKET *);

static int tlmsp_construct_middlebox_list(SSL *, WPACKET *);
static int tlmsp_parse_middlebox_list(SSL *, PACKET *, int);

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

        s->tlmsp.self_id = TLMSP_MIDDLEBOX_ID_SERVER;
        s->tlmsp.peer_id = TLMSP_MIDDLEBOX_ID_CLIENT;

        s->tlmsp.alert_container = 1;
        return 1;
    }

    if (sent) {
        s->tlmsp.self_id = TLMSP_MIDDLEBOX_ID_CLIENT;
        s->tlmsp.peer_id = TLMSP_MIDDLEBOX_ID_SERVER;

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
    fprintf(stderr, "session %p fallback to TLSv1.2\n", s);
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
        !tlmsp_construct_address(s, pkt, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].state.address) ||
        !tlmsp_construct_address(s, pkt, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address) ||
        !tlmsp_construct_middlebox_list(s, pkt) ||
        !WPACKET_close(pkt)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_CONSTRUCT_CTOS_TLMSP, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

int
tlmsp_parse_ctos_tlmsp(SSL *s, PACKET *pkt, unsigned int context, X509 *x, size_t chainidx)
{
    unsigned int major, minor;

    if (!SSL_IS_TLMSP(s)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!PACKET_get_1(pkt, &major) || !PACKET_get_1(pkt, &minor) ||
        major != TLMSP_VERSION_MAJOR || minor != TLMSP_VERSION_MINOR) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_parse_address(s, pkt, 0, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].state.address) ||
        !tlmsp_parse_address(s, pkt, 0, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_parse_middlebox_list(s, pkt, 0)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_CTOS_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
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
        !tlmsp_construct_address(s, pkt, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].state.address) ||
        !tlmsp_construct_address(s, pkt, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address) ||
        !tlmsp_construct_middlebox_list(s, pkt) ||
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

    if (!tlmsp_parse_address(s, pkt, 1, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].state.address) ||
        !tlmsp_parse_address(s, pkt, 1, &s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_STOC_TLMSP, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!tlmsp_parse_middlebox_list(s, pkt, 1)) {
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

    if (checkonly) {
        if (wire_type != adr->address_type ||
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
        if (TLMSP_MIDDLEBOX_ID_ENDPOINT(s->tlmsp.self_id)) {
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
tlmsp_construct_middlebox_list(SSL *s, WPACKET *pkt)
{
    const struct tlmsp_middlebox_instance_state *tmis;
    const struct tlmsp_context_instance_state *tcis;
    unsigned ncontexts;
    unsigned wire_auth;
    unsigned i, j;

    if (!WPACKET_start_sub_packet_u16(pkt))
        return 0;

    for (i = TLMSP_MIDDLEBOX_ID_FIRST; i < TLMSP_MIDDLEBOX_COUNT; i++) {
        tmis = &s->tlmsp.middlebox_states[i];
        if (!tmis->state.present)
            continue;
        if (!WPACKET_put_bytes_u8(pkt, (tlmsp_middlebox_id_t)i) ||
            !tlmsp_construct_address(s, pkt, &tmis->state.address) ||
            !WPACKET_put_bytes_u8(pkt, 0) || /* XXX inserted (static) */
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
tlmsp_parse_middlebox_list(SSL *s, PACKET *pkt, int check)
{
    struct tlmsp_middlebox_instance_state *tmis;
    struct tlmsp_context_instance_state *tcis;
    PACKET middlebox_infos, ticket;
    unsigned int id;
    unsigned int ncontexts;
    unsigned int cid, wire_auth;
    unsigned int inserted, transparent;
    tlmsp_context_auth_t auth;

    if (!PACKET_get_length_prefixed_2(pkt, &middlebox_infos)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    while (PACKET_remaining(&middlebox_infos) != 0) {
        if (!PACKET_get_1(&middlebox_infos, &id)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        tmis = &s->tlmsp.middlebox_states[id];
        if (check) {
            if (!tmis->state.present) { /* XXX Handle insertion.  */
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }
        } else {
            tmis->state.present = 1;
        }

        if (!tlmsp_parse_address(s, &middlebox_infos, check, &tmis->state.address)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (!PACKET_get_1(&middlebox_infos, &inserted) ||
            !PACKET_get_1(&middlebox_infos, &transparent) ||
            !PACKET_get_length_prefixed_2(&middlebox_infos, &ticket)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        switch (inserted) {
        case 0:
            break;
        case 1: /* XXX dynamic */
        case 2: /* XXX forbidden */
        default:
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        switch (transparent) {
        case 0:
            if (check) {
                if (tmis->state.transparent) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                    return 0;
                }
            } else {
                tmis->state.transparent = 0;
            }
            break;
        case 1:
            if (check) {
                if (!tmis->state.transparent) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                    return 0;
                }
            } else {
                tmis->state.transparent = 1;
            }
            break;
        default:
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (PACKET_remaining(&ticket) != 0) { /* XXX */
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (!PACKET_get_1(&middlebox_infos, &ncontexts) ||
            ncontexts > TLMSP_CONTEXT_COUNT) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        /* XXX We can easily do a scan to check for missing contexts.  */
        while (ncontexts--) {
            if (!PACKET_get_1(&middlebox_infos, &cid) ||
                !PACKET_get_1(&middlebox_infos, &wire_auth)) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }
            tcis = &s->tlmsp.context_states[cid];
            /*
             * XXX
             * Because the ContextList is a separate extension we might not
             * have parsed it by this point.
             *
             * Really the ContextList should be part of the TLMSP extension as
             * sent from the client, and come before the MiddleboxList.
             */
#if 0
            if (!tcis->state.present) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }
#endif
            /*
             * If we are a middlebox, determine presence here.
             */
            if (!TLMSP_MIDDLEBOX_ID_ENDPOINT(s->tlmsp.self_id))
                tcis->state.present = 1;
            switch (wire_auth) {
            case 0:
                auth = TLMSP_CONTEXT_AUTH_READ;
                break;
            case 1:
                auth = TLMSP_CONTEXT_AUTH_WRITE;
                break;
            default:
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }
            if (check) {
                if (tmis->state.access.contexts[cid] != auth) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                    return 0;
                }
            } else {
                tmis->state.access.contexts[cid] = auth;
            }
        }
    }

    return 1;
}
