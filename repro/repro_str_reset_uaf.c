/*
 * Copyright (C) 2019 Mark Wodrich
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
#include <unistd.h>

#include "../programs/programs_helper.h"

#define BUFFERSIZE 4096

// Packets will be passed between these two sockets if nonnull.
static struct socket** client = NULL;
static struct socket** server = NULL;

// Needed to avoid recursively grabbing locks, very ugly but it works.
void* pending_packet_destination = NULL;
void* pending_packet_buf = NULL;
size_t pending_packet_len = 0;


static uint32_t last_vtag = 0;


#ifdef FUZZ_VERBOSE
#define fuzzer_printf debug_printf
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
  struct socket ** s = (struct socket **)(addr);
  dump_packet(buf, length, SCTP_DUMP_OUTBOUND);
  if (s == client && server != NULL) {
    fuzzer_printf("sending packet to server\n");
    pending_packet_destination = (void *)server;
    pending_packet_buf = malloc(length);
    memcpy(pending_packet_buf, buf, length);
    pending_packet_len = length;
  } else if (s == server && client != NULL) {
    last_vtag = ((uint32_t* )buf)[1];
    fuzzer_printf("sending packet to client\n");
    pending_packet_destination = (void *)client;
    pending_packet_buf = malloc(length);
    memcpy(pending_packet_buf, buf, length);
    pending_packet_len = length;
  }

  return (0);
}

void process_packets() {
  while (pending_packet_destination != NULL) {
    void* destination = pending_packet_destination;
    void* buf = pending_packet_buf;
    pending_packet_destination = NULL; 
    dump_packet(pending_packet_buf, pending_packet_len, SCTP_DUMP_INBOUND);
    usrsctp_conninput(destination, pending_packet_buf, pending_packet_len, 0);
    free(buf);
  }
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

  fuzzer_printf("usrsctp initialized\n");
  return (1);
}

int main(void) {
  static int initialized;
  struct sockaddr_conn client_sconn;
  struct sockaddr_conn server_sconn1;
  struct sockaddr_conn server_sconn2;
  struct socket *socket_client;
  struct socket *socket_server1;
  struct socket *socket_server2;
  struct sctp_common_header *common_header;

  if (!initialized) {
    initialized = initialize_fuzzer();
  }

  usrsctp_register_address((void *)&socket_client);
  if ((socket_client = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL,
                                      NULL, 0, 0)) == NULL) {
    perror("usrsctp_socket");
    exit(EXIT_FAILURE);
  }

  usrsctp_set_non_blocking(socket_client, 1);

  memset(&client_sconn, 0, sizeof(struct sockaddr_conn));
  client_sconn.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
  client_sconn.sconn_len = sizeof(struct sockaddr_conn);
#endif
  client_sconn.sconn_port = htons(5000);
  client_sconn.sconn_addr = (void *)&socket_client;

  if (usrsctp_bind(socket_client, (struct sockaddr *)&client_sconn, sizeof(client_sconn)) <
      0) {
    perror("bind");
    usrsctp_close(socket_client);
    exit(EXIT_FAILURE);
  }

  usrsctp_register_address((void *)&socket_server1);
  if ((socket_server1 = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL,
                                      NULL, 0, 0)) == NULL) {
    perror("usrsctp_socket");
    exit(EXIT_FAILURE);
  }

  usrsctp_set_non_blocking(socket_server1, 1);

  memset(&server_sconn1, 0, sizeof(struct sockaddr_conn));
  server_sconn1.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
  server_sconn1.sconn_len = sizeof(struct sockaddr_conn);
#endif
  server_sconn1.sconn_port = htons(5001);
  server_sconn1.sconn_addr = (void *)&socket_server1;

  if (usrsctp_bind(socket_server1, (struct sockaddr *)&server_sconn1, sizeof(server_sconn1)) <
      0) {
    perror("bind");
    usrsctp_close(socket_client);
    usrsctp_close(socket_server1);
    exit(EXIT_FAILURE);
  }

  server_sconn1.sconn_addr = (void *)&socket_client;
  fuzzer_printf("Calling usrsctp_connect() on client\n");
  if (usrsctp_connect(socket_client, (struct sockaddr *)&server_sconn1,
                      sizeof(struct sockaddr_conn)) < 0) {
    if (errno != EINPROGRESS) {
      perror("usrsctp_connect");
      exit(EXIT_FAILURE);
    }
  }

  client = &socket_client;
  server = &socket_server1;

  client_sconn.sconn_addr = (void *)&socket_server1;
  fuzzer_printf("Calling usrsctp_connect() on server\n");
  if (usrsctp_connect(socket_server1, (struct sockaddr *)&client_sconn,
                      sizeof(struct sockaddr_conn)) < 0) {
    if (errno != EINPROGRESS) {
      perror("usrsctp_connect");
      exit(EXIT_FAILURE);
    }
  }

  process_packets();

  // Prevents packets from being forwarded.
  server = NULL;

  // Close first "server" socket.
  struct linger linger_opt;
  linger_opt.l_onoff = 1;
  linger_opt.l_linger = 0;
  usrsctp_setsockopt(socket_server1, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));
  usrsctp_close(socket_server1);

  //  Initiate connection from a new endpoint.
  usrsctp_register_address((void *)&socket_server2);
  if ((socket_server2 = usrsctp_socket(AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL,
                                      NULL, 0, 0)) == NULL) {
    perror("usrsctp_socket");
    exit(EXIT_FAILURE);
  }

  usrsctp_set_non_blocking(socket_server2, 1);

  memset(&server_sconn2, 0, sizeof(struct sockaddr_conn));
  server_sconn2.sconn_family = AF_CONN;
#ifdef HAVE_SCONN_LEN
  server_sconn2.sconn_len = sizeof(struct sockaddr_conn);
#endif
  server_sconn2.sconn_port = htons(5001);
  server_sconn2.sconn_addr = (void *)&socket_server2;

  if (usrsctp_bind(socket_server2, (struct sockaddr *)&server_sconn2, sizeof(server_sconn2)) <
      0) {
    perror("bind");
    usrsctp_close(socket_client);
    usrsctp_close(socket_server2);
    exit(EXIT_FAILURE);
  }


  const size_t num_bytes =
      sizeof(struct sctp_reset_streams) + (sizeof(uint16_t));
  struct sctp_reset_streams* resetp = malloc(num_bytes);
  resetp->srs_assoc_id = SCTP_ALL_ASSOC;
  resetp->srs_flags = SCTP_STREAM_RESET_OUTGOING;
  resetp->srs_number_streams = 1;
  int result_idx = 0;
  resetp->srs_stream_list[result_idx++] = 1;
  usrsctp_setsockopt(socket_client, IPPROTO_SCTP, SCTP_RESET_STREAMS, resetp, num_bytes);
  free(resetp);

  server = &socket_server2;

  client_sconn.sconn_addr = (void *)&socket_server2;
  fuzzer_printf("Calling usrsctp_connect() on server 2\n");
  if (usrsctp_connect(socket_server2, (struct sockaddr *)&client_sconn,
                      sizeof(struct sockaddr_conn)) < 0) {
    if (errno != EINPROGRESS) {
      perror("usrsctp_connect");
      exit(EXIT_FAILURE);
    }
  }

  process_packets();

  server = NULL;

  // Need to cause control packets to be queued up to reproduce the issue, this
  // is what the fuzzer ended up doing.
  char malformed_heartbeat[] = "\x13\x89\x13\x88\x0\x0\x0\x0\x0\x0\x0\x0\x04\x00\x00\x0c" \
      "\xbe\xba\xfe\xca\x00\x00\x00\x00\x01\x00\x00\x04";
  while (1) {
    fuzzer_printf("Injecting malformed heartbeat packet\n");
    common_header = (struct sctp_common_header *)malformed_heartbeat;
    common_header->verification_tag = last_vtag;
    dump_packet(malformed_heartbeat, sizeof(malformed_heartbeat) - 1, SCTP_DUMP_INBOUND);
    usrsctp_conninput(&socket_client, malformed_heartbeat, sizeof(malformed_heartbeat) - 1, 0);
    usleep(10*10000);
  }

  return (0);
}
