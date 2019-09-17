/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_SEQ_H
# define HEADER_TLMSP_SEQ_H

struct tlmsp_sequence_number {
    uint8_t value[8];
    size_t next_increment;
};

int tlmsp_sequence_receive(SSL *, tlmsp_middlebox_id_t, size_t);
int tlmsp_sequence_transmit(SSL *, size_t);

void tlmsp_sequence_init(TLMSP_MiddleboxInstance *);
void tlmsp_sequence_copy(TLMSP_MiddleboxInstance *, const TLMSP_MiddleboxInstance *);
int tlmsp_sequence_reset(SSL *, int);

int tlmsp_sequence_entity(const SSL *, tlmsp_middlebox_id_t, WPACKET *);
int tlmsp_sequence_record(const SSL *, int, WPACKET *);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
