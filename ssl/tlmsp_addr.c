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

/* API functions.  */

void
TLMSP_set_address_match_cb(SSL_CTX *ctx, TLMSP_address_match_cb_fn cb, void *arg)
{
    ctx->tlmsp.middlebox_config.address_match_callback = cb;
    ctx->tlmsp.middlebox_config.address_match_arg = arg;
}

void
TLMSP_set_address_match_cb_instance(SSL *s, TLMSP_address_match_cb_fn cb, void *arg)
{
    s->tlmsp.middlebox_config.address_match_callback = cb;
    s->tlmsp.middlebox_config.address_match_arg = arg;
}

void
TLMSP_set_transparent(SSL_CTX *ctx, int address_type, const char *address)
{
	/* XXX */
}

void
TLMSP_set_transparent_instance(SSL *s, int address_type, const char *address)
{
	/* XXX */
}

int
TLMSP_set_client_address(SSL_CTX *ctx, int address_type, const uint8_t *buf, size_t buflen)
{
    if (!SSL_CTX_IS_TLMSP(ctx))
        return 0;
    return tlmsp_address_set(&ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].address, address_type, buf, buflen);
}

int
TLMSP_set_client_address_instance(SSL *s, int address_type, const uint8_t *buf, size_t buflen)
{
    if (!SSL_IS_TLMSP(s))
        return 0;
    if (TLMSP_IS_MIDDLEBOX(s) || s->server)
        return 0;
    return tlmsp_address_set(&s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].state.address, address_type, buf, buflen);
}

int
TLMSP_get_client_address(SSL_CTX *ctx, int *address_type, uint8_t **outbuf, size_t *outlen)
{
    return tlmsp_address_get(&ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].address, address_type, outbuf, outlen);
}

int
TLMSP_get_client_address_instance(SSL *s, int *address_type, uint8_t **outbuf, size_t *outlen)
{
    return tlmsp_address_get(&s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_CLIENT].state.address, address_type, outbuf, outlen);
}

int
TLMSP_set_server_address(SSL_CTX *ctx, int address_type, const uint8_t *buf, size_t buflen)
{
    if (!SSL_CTX_IS_TLMSP(ctx))
        return 0;
    return tlmsp_address_set(&ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].address, address_type, buf, buflen);
}

int
TLMSP_set_server_address_instance(SSL *s, int address_type, const uint8_t *buf, size_t buflen)
{
    if (!SSL_IS_TLMSP(s))
        return 0;
    if (TLMSP_IS_MIDDLEBOX(s) || s->server)
        return 0;
    return tlmsp_address_set(&s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address, address_type, buf, buflen);
}

int
TLMSP_get_server_address(SSL_CTX *ctx, int *address_type, uint8_t **outbuf, size_t *outlen)
{
    return tlmsp_address_get(&ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].address, address_type, outbuf, outlen);
}

int
TLMSP_get_server_address_instance(SSL *s, int *address_type, uint8_t **outbuf, size_t *outlen)
{
    return tlmsp_address_get(&s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address, address_type, outbuf, outlen);
}

int
TLMSP_get_next_hop_address(SSL_CTX *ctx, int *address_type, uint8_t **outbuf, size_t *outlen)
{
    unsigned i;

    /*
     * This is only valid to call from a client, as only a client can have
     * the server address and middlebox list configured on an SSL_CTX.
     */
    if (ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].address.address_len == 0)
        return 0;

    /*
     * Find the first non-transparent middlebox and return it.
     *
     * XXX
     * If we are a middlebox, it should be "find the next," not "find the
     * first."  In that case, we would start at self_id.
     */
    for (i = TLMSP_MIDDLEBOX_ID_FIRST; i < TLMSP_MIDDLEBOX_COUNT; i++) {
        struct tlmsp_middlebox_state *tms;
        tms = &ctx->tlmsp.middlebox_states[i];
        if (!tms->present)
            continue;
        if (tms->transparent)
            continue;
        return tlmsp_address_get(&tms->address, address_type, outbuf, outlen);
    }

    return tlmsp_address_get(&ctx->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].address, address_type, outbuf, outlen);
}

int
TLMSP_get_next_hop_address_instance(SSL *s, int *address_type, uint8_t **outbuf, size_t *outlen)
{
    tlmsp_middlebox_id_t first;
    unsigned i;

    if (s->tlmsp.self_id == TLMSP_MIDDLEBOX_ID_NONE)
        return 0;
    first = tlmsp_middlebox_next(s, s->tlmsp.self_id);

    /*
     * We must at least have a server to connect to.
     */
    if (s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address.address_len == 0)
        return 0;

    /*
     * Find the next non-transparent middlebox and return it.
     */
    for (i = first; i != TLMSP_MIDDLEBOX_ID_NONE; i = tlmsp_middlebox_next(s, i)) {
        struct tlmsp_middlebox_instance_state *tmis;
        tmis = &s->tlmsp.middlebox_states[i];
        if (!tmis->state.present)
            continue;
        if (tmis->state.transparent)
            continue;
        return tlmsp_address_get(&tmis->state.address, address_type, outbuf, outlen);
    }

    return tlmsp_address_get(&s->tlmsp.middlebox_states[TLMSP_MIDDLEBOX_ID_SERVER].state.address, address_type, outbuf, outlen);
}

/* Internal functions.  */

int
tlmsp_address_set(struct tlmsp_address *adr, int buf_type, const uint8_t *buf, size_t buflen)
{
    if (adr == NULL)
        return 0;
    switch (buf_type) {
    case TLMSP_ADDRESS_URL:
    case TLMSP_ADDRESS_FQDN:
    case TLMSP_ADDRESS_IPV4:
    case TLMSP_ADDRESS_IPV6:
    case TLMSP_ADDRESS_MAC:
        /* valid type */
        break;
    default:
        return 0;
    }
    if (buf == NULL)
        return 0;
    if (buflen == 0)
        return 0;
    if (buflen > sizeof adr->address)
        return 0;
    if (memchr(buf, '\0', buflen) != NULL)
        return 0;

    memcpy(adr->address, buf, buflen);
    adr->address_type = buf_type;
    adr->address_len = buflen;

    return 1;
}

int
tlmsp_address_get(const struct tlmsp_address *adr, int *out_type, uint8_t **outbuf, size_t *outlen)
{
    unsigned char *p;

    if (adr == NULL)
        return 0;
    if (out_type == NULL)
        return 0;
    if (outbuf == NULL)
        return 0;
    if (outlen == NULL)
        return 0;

    p = OPENSSL_memdup(adr->address, adr->address_len);
    if (p == NULL)
        return 0;

    *out_type = adr->address_type;
    *outbuf = p;
    *outlen = adr->address_len;

    return 1;
}

/* Local functions.  */

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
