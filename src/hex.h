#ifndef HEX_H
#define HEX_H

#include <pcap.h>

#define HEX_P
#define HEX_OUT_BUF_SIZE 		4096
#define MAC_ADDR_LEN 			0xC
#define ETHER_PAYLOAD_OFF 		0xE

// Ether types
#define ETHER_TYPE_IPV4 		0x0800
#define ETHER_TYPE_ARP 			0x0806
#define ETHER_TYPE_IPV6 		0x86DD

typedef struct HexInstnace {
	pcap_t* handle;
} HexInstnace_t;

typedef struct EtherHeader {
    uint8_t  	src_mac[MAC_ADDR_LEN];
    uint8_t  	dst_mac[MAC_ADDR_LEN];
    uint16_t 	type;
    int32_t 	len;
} EtherHeader_t;

typedef struct Packet {
    EtherHeader_t 	eth_header;
    void* 			payload;
} Packet_t;

HEX_P HexInstnace_t create_hex_instance(const char* device);

HEX_P void free_hex_instance(const HexInstnace_t* handle);

HEX_P Packet_t* read_next_packet(const HexInstnace_t* handle);

Packet_t* parse_packet(const char* stream, size_t len);

void free_packet(Packet_t* packet);

#endif
