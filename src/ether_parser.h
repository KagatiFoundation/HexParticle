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

#define MAC_ADDR_LEN 			0xC
#define ETHER_PAYLOAD_OFF 		0xE

typedef struct __attribute__((packed)) EtherHeader {
    uint8_t  	src_mac[MAC_ADDR_LEN];
    uint8_t  	dst_mac[MAC_ADDR_LEN];
    uint16_t 	type;
    size_t 		len;
} EtherHeader_t;

ProtocolNode_t* parse_ether_packet(const uint8_t* stream, size_t len);

#endif
