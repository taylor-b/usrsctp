/*
 * Copyright (C) 2017-2019 Felix Weinrank
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <usrsctp.h>

#include "../programs/programs_helper.h"

#define BUFFERSIZE 4096

static uint32_t assoc_vtag = 0;

#ifdef FUZZ_VERBOSE
#define fuzzer_printf(...)        \
  do {                            \
    fprintf(stderr, "[P]");       \
    debug_printf_runtime();       \
    fprintf(stderr, __VA_ARGS__); \
  } while (0)
#else
#define fuzzer_printf(...)
#endif

static void dump_packet(const void *buffer, size_t bufferlen, int inout) {
#ifdef FUZZ_VERBOSE
  static char *dump_buf;
  if ((dump_buf = usrsctp_dumppacket(buffer, bufferlen, inout)) != NULL) {
    fprintf(stderr, "%s", dump_buf);
    usrsctp_freedumpbuffer(dump_buf);
  }
#endif
}

static int conn_output(void *addr, void *buf, size_t length, uint8_t tos,
                       uint8_t set_df) {
  struct sctp_init_chunk *init_chunk;
  const char *init_chunk_first_bytes =
      "\x13\x88\x13\x89\x00\x00\x00\x00\x00\x00\x00\x00\x01";
  // length >= (12 Common + 16 min INIT)
  if ((length >= 28) && (memcmp(buf, init_chunk_first_bytes, 12) == 0)) {
    // fuzzer_printf("length %d / sizeof %lu\n", length, sizeof(struct
    // sctp_common_header));
    init_chunk = (struct sctp_init_chunk *)((char *)buf +
                                            sizeof(struct sctp_common_header));
    fuzzer_printf("Found outgoing INIT, extracting VTAG : %u\n",
                  init_chunk->initiate_tag);
    assoc_vtag = init_chunk->initiate_tag;
  }

  dump_packet(buf, length, SCTP_DUMP_OUTBOUND);
  return (0);
}

int initialize_fuzzer(void) {
#ifdef FUZZ_VERBOSE
  usrsctp_init(0, conn_output, debug_printf_stack);
#else
  usrsctp_init(0, conn_output, NULL);
#endif

  usrsctp_enable_crc32c_offload();
  /* set up a connected UDP socket */
#ifdef SCTP_DEBUG
  usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif
  usrsctp_register_address((void *)1);

  fuzzer_printf("usrsctp initialized\n");
  return (1);
}

int main(void) {
  static int initialized;
  struct sockaddr_in bind4;
  struct sockaddr_conn sconn;
  struct socket *socket_client;
  struct sctp_common_header *common_header;

  // WITH COMMON HEADER!
  char fuzz_packet1[] =
      "\x13\x89\x13\x88\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x50\x01\x00"
      "\x00\x00\x00\x00\x20\x00\x00\x08\x00\x08\x00\x00\x00\x01\x80\x08\x00\x07"
      "\xc1\x80\x0f\x00\x80\x03\x00\x07\x00\xc1\x80\x00\x80\x02\x00\x24\x41\x41"
      "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
      "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x80\x04\x00\x07\x00\x01"
      "\x00\x00";
  char fuzz_packet2[] =
      "\x13\x89\x13\x88\x7d\xa3\x27\xd0\x00\x00\x00\x00\x0f\x00\x00\x1c\x00\x00"
      "\x00\x01\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
      "\xaa\xaa\xaa\xaa\xc1\x0c\x00\x28\xff\xff\x9a\xc1\x53\xff\x00\x08\xff\x0c"
      "\x53\x1c\xc0\x01\x00\x0e\x00\x00\xfe\xff\x00\x05\x00\x08\x00\x00\x00\x00"
      "\x5d\x8b\x2c\xbd\xff\x04\xfc\xff";

  char fuzz_common_header[] =
      "\x13\x89\x13\x88\x54\xc2\x7c\x46\x00\x00\x00\x00";

  if (!initialized) {
    initialized = initialize_fuzzer();
  }

  if ((socket_client = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL,
                                      NULL, 0, 0)) == NULL) {
    perror("usrsctp_socket");
    exit(EXIT_FAILURE);
  }

  usrsctp_set_non_blocking(socket_client, 1);

  memset((void *)&bind4, 0, sizeof(struct sockaddr_in));
#ifdef HAVE_SIN_LEN
  bind4.sin_len = sizeof(struct sockaddr_in6);
#endif
  bind4.sin_family = AF_INET;
  bind4.sin_port = htons(5000);
  bind4.sin_addr.s_addr = htonl(INADDR_ANY);

  if (usrsctp_bind(socket_client, (struct sockaddr *)&bind4, sizeof(bind4)) <
      0) {
    perror("bind");
    usrsctp_close(socket_client);
    exit(EXIT_FAILURE);
  }

  memset(&sconn, 0, sizeof(struct sockaddr_conn));
  sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
  sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
  sconn.sconn_port = htons(5001);
  sconn.sconn_addr = (void *)1;

  fuzzer_printf("Calling usrsctp_connect()\n");
  if (usrsctp_connect(socket_client, (struct sockaddr *)&sconn,
                      sizeof(struct sockaddr_conn)) < 0) {
    if (errno != EINPROGRESS) {
      perror("usrsctp_connect");
      exit(EXIT_FAILURE);
    }
  }

  // Send out first packet - an INIT chunk
  fuzzer_printf("Injecting INIT\n");
  dump_packet(fuzz_packet1, sizeof(fuzz_packet1) - 1, SCTP_DUMP_INBOUND);
  usrsctp_conninput((void *)1, fuzz_packet1, sizeof(fuzz_packet1) - 1, 0);

  // TODO: Need to parse received INIT-ACK maybe?

  // Send out next packet
  fuzzer_printf("Injecting 2nd packet\n");
  common_header = (struct sctp_common_header*) fuzz_packet2;
  common_header->verification_tag = assoc_vtag;
  dump_packet(fuzz_packet2, sizeof(fuzz_packet2) - 1, SCTP_DUMP_INBOUND);
  usrsctp_conninput((void *)1, fuzz_packet2, sizeof(fuzz_packet2) - 1, 0);

  fuzzer_printf("Calling usrsctp_close()\n");
  usrsctp_close(socket_client);

  return (0);
}
