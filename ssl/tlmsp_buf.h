/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_BUF_H
# define HEADER_TLMSP_BUF_H

/*
 * This data structure is for ease of constructing variable, and possibly
 * large, data buffers.  In many cases where there are trivial size limits in
 * place, we prefer to use WPACKET for its various additional features, but for
 * bulk data, this is more accessible.
 */
struct tlmsp_buffer {
    BUF_MEM *bmem;
};

void tlmsp_buffer_init(struct tlmsp_buffer *);
void tlmsp_buffer_clear(struct tlmsp_buffer *);
int tlmsp_buffer_copy(struct tlmsp_buffer *, const struct tlmsp_buffer *);

const void *tlmsp_buffer_data(const struct tlmsp_buffer *, size_t *);
int tlmsp_buffer_empty(const struct tlmsp_buffer *);

int tlmsp_buffer_append(struct tlmsp_buffer *, const void *, size_t);

#endif

/* Local Variables:       */
/* c-basic-offset: 4      */
/* tab-width: 4           */
/* indent-tabs-mode: nil  */
/* End:                   */
