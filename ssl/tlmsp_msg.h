/*
 * Copyright (c) 2019 Not for Radio, LLC
 *
 * Released under the ETSI Software License (see LICENSE)
 *
 */
/* vim: set ts=4 sw=4 et: */

#ifndef HEADER_TLMSP_MSG_H
# define HEADER_TLMSP_MSG_H

/* Handshake protocol messages.  */

int tlmsp_process_certificate(SSL *, PACKET *, STACK_OF(X509) **);
int tlmsp_process_client_key_exchange(SSL *, PACKET *, TLMSP_MiddleboxInstance *, EVP_PKEY **);
int tlmsp_process_server_key_exchange(SSL *, PACKET *, TLMSP_MiddleboxInstance *, EVP_PKEY **);

int tlmsp_construct_middlebox_hello(SSL *, WPACKET *);
MSG_PROCESS_RETURN tlmsp_process_middlebox_hello(SSL *, PACKET *);

int tlmsp_construct_middlebox_cert(SSL *, WPACKET *);
MSG_PROCESS_RETURN tlmsp_process_middlebox_cert(SSL *, PACKET *);

int tlmsp_construct_middlebox_key_exchange(SSL *, WPACKET *);
MSG_PROCESS_RETURN tlmsp_process_middlebox_key_exchange(SSL *, PACKET *);

int tlmsp_construct_middlebox_hello_done(SSL *, WPACKET *);
MSG_PROCESS_RETURN tlmsp_process_middlebox_hello_done(SSL *, PACKET *);

int tlmsp_construct_middlebox_key_material(SSL *, WPACKET *);
MSG_PROCESS_RETURN tlmsp_process_middlebox_key_material(SSL *, PACKET *);

int tlmsp_construct_middlebox_key_confirmation(SSL *, WPACKET *);
MSG_PROCESS_RETURN tlmsp_process_middlebox_key_confirmation(SSL *, PACKET *);

int tlmsp_construct_middlebox_finished(SSL *, WPACKET *);
MSG_PROCESS_RETURN tlmsp_process_middlebox_finished(SSL *, PACKET *);

#endif
