/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#ifndef ETHER_PARSER_H
#define ETHER_PARSER_H

#include <stdint.h>
#include <stdlib.h>

#include "proto_node.h"

// Ether types
#define ETHER_TYPE_IPV4 		0x0800
#define ETHER_TYPE_ARP 			0x0806
#define ETHER_TYPE_IPV6 		0x86DD

#define MAC_ADDR_LEN 			0x6 // Standard MAC address length is 6 bytes
#define ETHER_PAYLOAD_OFF 		0xE // Standard Ethernet header is 14 bytes

typedef struct {
    uint8_t  	src_mac[MAC_ADDR_LEN];
    uint8_t  	dst_mac[MAC_ADDR_LEN];
    uint16_t 	type;
    uint32_t 	len;
} __attribute__((packed)) EtherHeader_t;

ProtocolNode_t* parse_ether_packet(const uint8_t* stream, size_t len);

#endif
