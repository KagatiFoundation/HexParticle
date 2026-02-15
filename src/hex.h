#ifndef HEX_H
#define HEX_H

#include <pcap.h>
#include "ether_parser.h"

#define HEX_P
#define HEX_OUT_BUF_SIZE 		4096

typedef struct HexInstnace {
	pcap_t* handle;
} HexInstnace_t;

HEX_P HexInstnace_t create_hex_instance(const char* device);

HEX_P void free_hex_instance(const HexInstnace_t* handle);

HEX_P ProtocolNode_t* read_next_packet(const HexInstnace_t* handle);

#endif
