#ifndef TCP_PARSER_H
#define TCP_PARSER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * TCP header
 */
typedef struct __attribute__((packed)) TCP {
    uint16_t    sport;
    uint16_t    dport;
    uint32_t    seq;
    uint32_t    ack;
    uint8_t     off_res;
    uint8_t     flags;
    uint16_t    win;
    uint16_t    chk;
    uint16_t    urg;
    uint8_t     options[];
} TCP_t;

TCP_t* parse_tcp_packet(const char* stream);

void free_tcp_packet(TCP_t* packet);

#endif
