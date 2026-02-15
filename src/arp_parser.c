#include "arp_parser.h"

ARP_t* parse_arp_packet(const char *stream) {
	return NULL;
}

void free_arp_packet(const ARP_t* packet) {
	if (packet != NULL) free(packet);
}