/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_FIN_H
# define HEADER_TLMSP_FIN_H

struct tlmsp_finish_state {
    struct tlmsp_buffer buf;
};

void tlmsp_finish_init(struct tlmsp_finish_state *); /* XXX Could take an SSL *, and we would use an EVP_MD_CTX, not a buffer.  */
void tlmsp_finish_clear(struct tlmsp_finish_state *);
int tlmsp_finish_copy(struct tlmsp_finish_state *, const struct tlmsp_finish_state *);

int tlmsp_finish_construct(SSL *, TLMSP_MiddleboxInstance *, WPACKET *);
int tlmsp_finish_verify(SSL *, TLMSP_MiddleboxInstance *, const void *, size_t);

int tlmsp_finish_append(SSL *, int, int, const void *, size_t);

int tlmsp_finish_endpoint_exclude(const SSL *, int, int, const void *, size_t);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
