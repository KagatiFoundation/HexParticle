#include "arp_parser.h"

ProtocolNode_t* parse_arp_packet(const uint8_t *stream) {
	const size_t arp_header_size = sizeof(ARPHeader_t);

	ARPHeader_t* arp_hdr = malloc(arp_header_size);
	memcpy(arp_hdr, stream, arp_header_size);

	ProtocolNode_t* arp_node = malloc(sizeof(ProtocolNode_t));
	arp_node->type = PROTO_ARP;
	arp_node->hdr = arp_hdr;
	arp_node->hdr_len = arp_header_size;
	arp_node->next = NULL;

	return arp_node;
}
