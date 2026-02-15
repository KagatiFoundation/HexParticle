#include "ipv4_parser.h"
#include "tcp_parser.h"
#include <string.h>

IPv4_t* parse_ipv4_packet(const char* stream, size_t len) {
	IPv4_t* ip_pack = malloc(sizeof(IPv4_t));
	memcpy((void*) ip_pack, stream, sizeof(IPv4_t));

	uint8_t ihl = ip_pack->ver_ihl & 0x0F;

	if (ip_pack->proto == IPV4_TCP) {
		size_t ip_head_len = ihl * 4;
        const char* tcp_stream = stream + ip_head_len;
		TCP_t* tcp = parse_tcp_packet(tcp_stream);
	}
	return ip_pack;
}

void free_ipv4_packet(IPv4_t* tcp) {
	if (tcp != NULL) free(tcp);
}