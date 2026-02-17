/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "proto_node.h"
#include "ether_parser.h"
#include "ipv4_parser.h"
#include "arp_parser.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

ProtocolNode_t* parse_ether_packet(const uint8_t* stream, size_t len) {
	EtherHeader_t* eth_header = malloc(sizeof(EtherHeader_t));
    memcpy(eth_header->dst_mac, stream, 6);
    memcpy(eth_header->src_mac, stream + 6, 6);
    eth_header->type = (stream[12] << 8) | stream[13];
    eth_header->len = len;

	int payload_off = ETHER_PAYLOAD_OFF;
    while (eth_header->type == 0x8100) {
        if (len < payload_off + 4) {
            fprintf(stderr, "Malformed packet.\n");
            return NULL;
        }

        eth_header->type = (stream[payload_off + 2] << 8) | stream[payload_off + 3];
        payload_off += 4;
    }

	ProtocolNode_t* ether_node = malloc(sizeof(ProtocolNode_t));
	ether_node->type = PROTO_ETH;
	ether_node->hdr = eth_header;
    
    if (eth_header->type <= 1500) {
        fprintf(stderr, "Skipping IEEE 802.3 frame (unsupported).\n");
        return NULL;
    }

	if (eth_header->type == ETHER_TYPE_IPV4) {
		ether_node->next = parse_ipv4_packet((stream + payload_off));
	}
	else if (eth_header->type == ETHER_TYPE_ARP) {
		ether_node->next = parse_arp_packet((stream + payload_off));
	}
	else if (eth_header->type == ETHER_TYPE_IPV6) {
		// parse ipv6
	}

	return ether_node;
}
