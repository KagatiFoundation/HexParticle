#ifndef ETHERNET_H
#define ETHERNET_H

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define ETHER_TYPE_IPV4 0x0800
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_IPV6 0x86DD

#define MAC_ADDR_LEN 12
#define ETHER_PAYLOAD_OFF 14

typedef struct EtherHeader {
    char  src_mac[MAC_ADDR_LEN];
    char  dst_mac[MAC_ADDR_LEN];
    short type;
    int32_t len;
} EtherHeader_t;

#endif
