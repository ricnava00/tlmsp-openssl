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

    if (!tlmsp_parse_address(s, pkt, 0, &s->tlmsp.client_middlebox.state.address) ||
        !tlmsp_parse_address(s, pkt, 0, &s->tlmsp.server_middlebox.state.address)) {
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
        !tlmsp_construct_address(s, pkt, &s->tlmsp.client_middlebox.state.address) ||
        !tlmsp_construct_address(s, pkt, &s->tlmsp.server_middlebox.state.address) ||
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

    if (!tlmsp_parse_address(s, pkt, 1, &s->tlmsp.client_middlebox.state.address) ||
        !tlmsp_parse_address(s, pkt, 1, &s->tlmsp.server_middlebox.state.address)) {
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
tlmsp_construct_middlebox_list(SSL *s, WPACKET *pkt)
{
    const TLMSP_MiddleboxInstance *tmis;
    const struct tlmsp_context_instance_state *tcis;
    unsigned ncontexts;
    unsigned wire_auth;
    unsigned j;

    if (!WPACKET_start_sub_packet_u16(pkt))
        return 0;

    for (tmis = tlmsp_middlebox_first(s); tmis != NULL;
         tmis = tlmsp_middlebox_next(s, tmis)) {
        if (!WPACKET_put_bytes_u8(pkt, tmis->state.id) ||
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
tlmsp_parse_middlebox_list(SSL *s, PACKET *pkt, int stoc)
{
    TLMSP_MiddleboxInstance *tmis, *initial_tmis, *last;
    struct tlmsp_address *adr;
    struct tlmsp_context_instance_state *tcis;
    PACKET middlebox_infos, ticket;
    int is_client;
    int parseonly;
    unsigned int id;
    unsigned int ncontexts;
    unsigned int cid, wire_auth;
    unsigned int inserted, transparent;
    tlmsp_context_auth_t auth;

    if (!PACKET_get_length_prefixed_2(pkt, &middlebox_infos)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
        return 0;
    }

    if (!TLMSP_IS_MIDDLEBOX(s) && !s->server)
        is_client = 1;
    else
        is_client = 0;

    /*
     * A middlebox parses the contents of the middlebox list sent by the
     * server, but it ignores the contents.  If middleboxes have added
     * themselves upstream or the server has added middleboxes, the client
     * will issue a new ClientHello with the final list if the connection is
     * to continue, and the middlebox will obtain the new list there.
     * Otherwise, the state we have is already the most current.
     *
     * XXX Wait for update to 0.1.0a+ for self-insertion of transparent
     * middleboxes, as the new postion marker field in the TLMSP extension
     * will make that task much simpler.
     *
     * XXX We also want to avoid updating our state with the middlebox list
     * contents in a rengotiation ClientHello, although we may want to
     * check that they match what we have.
     */
    if (TLMSP_IS_MIDDLEBOX(s) && stoc)
        parseonly = 1;
    else {
        parseonly = 0;

        /*
         * Clear any existing state (as there would be on a middlebox or
         * server when processing a second ClientHello).
         *
         * XXX On middleboxes, this will invalidate self until the list
         * compile at the end of the parse - this might affect sending
         * alerts if we error out?
         */
        tlmsp_middleboxes_clear_current(s);
    }

    /*
     * Without this, the compiler worries about uninitialized use of tmis
     * because it can't see through the logic.  Easy to check manually
     * though: tmis is only used in the loop when parseonly is false, and it
     * is always set when parseonly is false.
     */
    tmis = NULL;
    last = NULL;
    while (PACKET_remaining(&middlebox_infos) != 0) {
        if (!PACKET_get_1(&middlebox_infos, &id)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (id == TLMSP_MIDDLEBOX_ID_NONE) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (!parseonly) {
            tmis = tlmsp_middlebox_lookup(s, id);
            /* Middlebox already present.  */
            if (tmis != NULL) {
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }
            tmis = tlmsp_middlebox_insert_after(s, last, id);
            if (tmis == NULL) {
                SSLfatal(s, SSL_AD_INTERNAL_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, ERR_R_INTERNAL_ERROR);
                return 0;
            }
            last = tmis;

            adr = &tmis->state.address;
        } else
            adr = NULL;

        if (!tlmsp_parse_address(s, &middlebox_infos, 0, adr)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        if (!PACKET_get_1(&middlebox_infos, &inserted) ||
            !PACKET_get_1(&middlebox_infos, &transparent) ||
            !PACKET_get_length_prefixed_2(&middlebox_infos, &ticket)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
            return 0;
        }

        initial_tmis = NULL;
        if (!parseonly) {
            switch (inserted) {
            case 0: /* static */
            case 1: /* dynamic */
                break;
            case 2: /* XXX forbidden */
            default:
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }

            switch (transparent) {
            case 0:
            case 1:
                break;
            default:
                SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                return 0;
            }

            tmis->state.transparent = transparent;

            /*
             * Perform client-side checks
             *
             * XXX we do not check whether the server has reordered entries
             */
            if (is_client) {
                initial_tmis = tlmsp_middlebox_lookup_initial(s, id);
                if (initial_tmis != NULL) {
                    if (initial_tmis) {
                        if (tmis->state.transparent != initial_tmis->state.transparent) {
                            SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                            return 0;
                        }
                    } else if (inserted != 1) {
                        /* not in the initial list and not marked dynamic */
                        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                        return 0;
                    }
                }
            }
        }

        if (PACKET_remaining(&ticket) != 0) { /* XXX - resumption not yet supported */
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

            if (parseonly)
                continue;

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
            if (TLMSP_IS_MIDDLEBOX(s))
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
            if (is_client && (initial_tmis != NULL)) {
                if (initial_tmis->state.access.contexts[cid] != auth) {
                    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_F_TLMSP_PARSE_MIDDLEBOX_LIST, SSL_R_BAD_EXTENSION);
                    return 0;
                }
            }
            tmis->state.access.contexts[cid] = auth;
        }
    }

    /*
     * If the current middlebox list has been updated, compile it
     */
    if (!parseonly) {
        if (!tlmsp_middlebox_table_compile_current(s))
            return 0;

        /*
         * On a middlebox, when the current middlebox list is updated,
         * update self.
         */
        if (TLMSP_IS_MIDDLEBOX(s))
            tlmsp_middlebox_establish_id(s);
    }

    /*
     * The endpoints get discovery callbacks if they want them
     */
    if (!TLMSP_IS_MIDDLEBOX(s)) {
        if (s->tlmsp.discovery_cb)
            return s->tlmsp.discovery_cb(s, s->tlmsp.discovery_cb_arg);
        else
            return 0;  /* XXX default reject might not be apporpriate in all cases */
    }

    return 1;
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
