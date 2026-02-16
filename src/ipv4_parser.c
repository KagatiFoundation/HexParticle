#include "ipv4_parser.h"
#include "tcp_parser.h"
#include "proto_node.h"
#include "udp_parser.h"

#include <string.h>

ProtocolNode_t* parse_ipv4_packet(const uint8_t* stream, size_t len) {
	IPV4Header_t* ip_header = malloc(sizeof(IPV4Header_t));
	memcpy((void*) ip_header, stream, sizeof(IPV4Header_t));

	uint8_t ihl = ip_header->ver_ihl & 0x0F;
	
	ProtocolNode_t* ip_node = malloc(sizeof(ProtocolNode_t));
	ip_node->type = PROTO_IPV4;
	ip_node->hdr = ip_header;

	if (ip_header->proto == IPV4_TCP) {
		size_t ip_head_len = ihl * 4;
        const uint8_t* tcp_stream = stream + ip_head_len;

		ProtocolNode_t* tcp_node = parse_tcp_packet(tcp_stream);
		ip_node->next = tcp_node;
	}
	else if (ip_header->proto == IPV4_UDP) {
        const uint8_t* udp_stream = stream + UDP_HEADER_LEN;

		ProtocolNode_t* udp_node = parse_udp_packet(udp_stream);
		ip_node->next = udp_node;
	}
	return ip_node;
}
