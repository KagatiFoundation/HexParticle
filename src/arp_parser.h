#ifndef ARP_PARSER_H
#define ARP_PARSER_H

#include "packet.h"

#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>

typedef struct __attribute__((__packed__)) ARP {
    uint16_t    htype;  // Hardware type (for e.g.: 1 for Ethernet)
    uint16_t    ptype;  // Protocol type (for: e.g.: 0x0800 for IPv4)
    uint8_t     hlen;   // Hardware address length (bytes) — 6 for MAC
    uint8_t     plen;   // Protocol address length (bytes) — 4 for IPv4
    uint16_t    op;     // Operation code: 1=Request, 2=Reply
    uint8_t     sha[6]; // Sender hardware address (MAC)
    uint8_t     spa[4]; // Sender protocol address (IPv4)
    uint8_t     tha[6]; // Target hardware address (MAC)
    uint8_t     tpa[4]; // Target protocol address (IPv4)
} ARP_t;

HEX_P ARP_t* parse_arp_packet(const char *stream);

HEX_P void free_arp_packet(const ARP_t* packet);

#endif
