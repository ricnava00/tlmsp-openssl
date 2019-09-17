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

static int tlmsp_sequence_number_increment(struct tlmsp_sequence_number *, size_t);
static void tlmsp_sequence_number_reset(struct tlmsp_sequence_number *);

/* Internal functions.  */

int
tlmsp_sequence_receive(SSL *s, tlmsp_middlebox_id_t origin, size_t deletes)
{
    TLMSP_MiddleboxInstance *tmis;
    enum tlmsp_direction d;

    if (s->tlmsp.self == NULL)
        return 1;

    switch (TLMSP_MIDDLEBOX_ID_PEER(s)) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        d = TLMSP_D_STOC;
        break;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        d = TLMSP_D_CTOS;
        break;
    default:
        return 0;
    }

    tmis = tlmsp_middlebox_next_direction(s, s->tlmsp.self, d);
    if (tmis == NULL) {
        /*
         * No middleboxes, just our peer.
         */
        if (origin != TLMSP_MIDDLEBOX_ID_PEER(s))
            return 0;
        tmis = tlmsp_middlebox_lookup(s, origin);
        if (tmis == NULL)
            return 0;
    }

    if (!tlmsp_sequence_number_increment(&tmis->sequence_number, deletes))
        return 0;
    if (tmis->state.id == origin)
        return 1;

    /*
     * For each middlebox continuing back towards our peer, increment the
     * sequence number, until we hit the origin.
     */
    while ((tmis = tlmsp_middlebox_next_direction(s, tmis, d)) != NULL) {
        if (!tlmsp_sequence_number_increment(&tmis->sequence_number, deletes))
            return 0;
        if (tmis->state.id == origin)
            return 1;
    }

    /*
     * We ran out of middleboxes, the origin must be our peer.
     */
    if (origin != TLMSP_MIDDLEBOX_ID_PEER(s))
        return 0;
    tmis = tlmsp_middlebox_lookup(s, origin);
    if (tmis == NULL)
        return 0;
    if (!tlmsp_sequence_number_increment(&tmis->sequence_number, deletes))
        return 0;

    return 1;
}

int
tlmsp_sequence_transmit(SSL *s, size_t deletes)
{
    if (s->tlmsp.self == NULL)
        return 1;

    if (!tlmsp_sequence_number_increment(&s->tlmsp.self->sequence_number, deletes))
        return 0;

    return 1;
}

void
tlmsp_sequence_init(TLMSP_MiddleboxInstance *tmis)
{
    tlmsp_sequence_number_reset(&tmis->sequence_number);
}

void
tlmsp_sequence_copy(TLMSP_MiddleboxInstance *dst, const TLMSP_MiddleboxInstance *src)
{
    memcpy(dst, src, sizeof *dst);
}

int
tlmsp_sequence_reset(SSL *s, int sending)
{
    TLMSP_MiddleboxInstance *tmis;
    enum tlmsp_direction d;

    if (s->tlmsp.self == NULL)
        return 0;

    if (sending) {
        tlmsp_sequence_number_reset(&s->tlmsp.self->sequence_number);
        return 1;
    }

    /*
     * Reset the sequence number on each middlebox between us and our peer, and
     * at the last, on our peer.
     */
    switch (TLMSP_MIDDLEBOX_ID_PEER(s)) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        d = TLMSP_D_STOC;
        break;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        d = TLMSP_D_CTOS;
        break;
    default:
        return 0;
    }

    tmis = tlmsp_middlebox_next_direction(s, s->tlmsp.self, d);
    while (tmis != NULL) {
        tlmsp_sequence_number_reset(&tmis->sequence_number);
        tmis = tlmsp_middlebox_next_direction(s, tmis, d);
    }
    tmis = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
    if (tmis == NULL)
        return 0;
    tlmsp_sequence_number_reset(&tmis->sequence_number);
    return 1;
}

int
tlmsp_sequence_entity(const SSL *s, tlmsp_middlebox_id_t id, WPACKET *pkt)
{
    const TLMSP_MiddleboxInstance *tmis;

    if (id == TLMSP_MIDDLEBOX_ID_NONE || pkt == NULL)
        return 0;

    tmis = tlmsp_middlebox_lookup(s, id);
    if (tmis == NULL)
        return 0;

    if (!WPACKET_memcpy(pkt, tmis->sequence_number.value, 8))
        return 0;

    return 1;
}

int
tlmsp_sequence_record(const SSL *s, int sending, WPACKET *pkt)
{
    static const uint8_t empty_sequence[8];
    const TLMSP_MiddleboxInstance *tmis;
    enum tlmsp_direction d;

    if (pkt == NULL)
        return 0;

    if (s->tlmsp.self == NULL) {
        if (!WPACKET_memcpy(pkt, empty_sequence, 8))
            return 0;
        return 1;
    }

    if (sending) {
        if (!WPACKET_memcpy(pkt, s->tlmsp.self->sequence_number.value, 8))
            return 0;
        return 1;
    }

    switch (TLMSP_MIDDLEBOX_ID_PEER(s)) {
    case TLMSP_MIDDLEBOX_ID_CLIENT:
        d = TLMSP_D_STOC;
        break;
    case TLMSP_MIDDLEBOX_ID_SERVER:
        d = TLMSP_D_CTOS;
        break;
    default:
        return 0;
    }

    tmis = tlmsp_middlebox_next_direction(s, s->tlmsp.self, d);
    if (tmis == NULL) {
        /*
         * No middleboxes, just our peer.
         */
        tmis = tlmsp_middlebox_lookup(s, TLMSP_MIDDLEBOX_ID_PEER(s));
        if (tmis == NULL)
            return 0;
    }
    if (!WPACKET_memcpy(pkt, tmis->sequence_number.value, 8))
        return 0;

    return 1;
}

/* Local functions.  */

static int
tlmsp_sequence_number_increment(struct tlmsp_sequence_number *tsn, size_t deletes)
{
    uint8_t *seqp;
    unsigned i;
    size_t cnt;

    /*
     * If this is a run of deletes, just add it to the waiting increment count
     * and return.  Otherwise, apply the waiting increment count, and reset it.
     */
    if (deletes != 0) {
        tsn->next_increment += deletes;
        return 1;
    }
    cnt = tsn->next_increment;
    tsn->next_increment = 1;

    seqp = tsn->value;

    for (i = 0; i < 8; i++) {
        uint8_t a, o;
        uint8_t *p;

        if (cnt == 0)
            break;

        p = &seqp[7 - i];
        a = cnt & 0xff;
        cnt >>= 8;
        o = *p;
        *p = o + a;
        if (*p < o)
            cnt++;
    }

    return 1;
}

static void
tlmsp_sequence_number_reset(struct tlmsp_sequence_number *tsn)
{
    memset(tsn->value, 0, 8);
    tsn->next_increment = 0;
}

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
