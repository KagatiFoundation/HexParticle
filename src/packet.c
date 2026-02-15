#include "packet.h"
#include <string.h>

Packet_t* parse_packet(const char* stream, size_t len) {
    if (len < 14) {
        printf("Packet's length is too short for it to be an Ethernet header.\n");
        exit(EXIT_FAILURE);
    }

	Packet_t *packet = malloc(sizeof(Packet_t));
	memcpy(&packet->eth_header, stream, sizeof(EtherHeader_t));

	int payload_off = ETHER_PAYLOAD_OFF;
    while (packet->eth_header.type == 0x8100) {
        if (len < payload_off + 4) {
            fprintf(stderr, "Malformed packet.\n");
            return NULL;
        }

        packet->eth_header.type = (stream[payload_off + 2] << 8) | stream[payload_off + 3];
        payload_off += 4;
    }
    
    if (packet->eth_header.type <= 1500) {
        fprintf(stderr, "Skipping IEEE 802.3 frame (unsupported).\n");
        return NULL;
    }

	if (packet->eth_header.type == ETHER_TYPE_IPV4) {
		packet->payload = parse_ipv4_packet((stream + payload_off), 0);
	}
	return packet;
}

void free_packet(Packet_t* packet) {
	if (packet != NULL) free(packet);
}
