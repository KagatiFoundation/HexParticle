#include "tcp_parser.h"
#include <string.h>

TCP_t* parse_tcp_packet(const char* stream) {
    TCP_t* tcp = malloc(sizeof(TCP_t));
	memcpy(tcp, stream, sizeof(TCP_t));
    return tcp;
}

void free_tcp_packet(TCP_t* packet) {
    if (packet != NULL) {
        free(packet);
    }
}