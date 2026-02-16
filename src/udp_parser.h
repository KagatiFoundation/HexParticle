#ifndef UDP_PARSER_H
#define UDP_PARSER_H

#include <stdint.h>

#include "proto_node.h"

#define UDP_HEADER_LEN		8 // bytes

typedef struct UDPHeader {
	uint16_t	sport;
	uint16_t	dport;
	uint16_t	length;
	uint16_t	cksum;
} UDPHeader_t;

ProtocolNode_t* parse_udp_packet(const uint8_t* stream);

#endif
