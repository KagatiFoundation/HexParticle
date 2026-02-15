#include "ipv4_parser.h"
#include "tcp_parser.h"
#include "proto_node.h"

#include <string.h>

ProtocolNode_t* parse_ipv4_packet(const char* stream, size_t len) {
	IPv4_t* ip_header = malloc(sizeof(IPv4_t));
	memcpy((void*) ip_header, stream, sizeof(IPv4_t));

	uint8_t ihl = ip_header->ver_ihl & 0x0F;
	
	ProtocolNode_t* ip_node = malloc(sizeof(ProtocolNode_t));
	ip_node->hdr = ip_header;

	if (ip_header->proto == IPV4_TCP) {
		size_t ip_head_len = ihl * 4;
        const char* tcp_stream = stream + ip_head_len;
		// TCP_t* tcp = parse_tcp_packet(tcp_stream);
	}
	return ip_header;
}

void free_ipv4_packet(IPv4_t* tcp) {
	if (tcp != NULL) free(tcp);
}