#ifndef HEX_H
#define HEX_H

#define HEX_P

#define HEX_OUT_BUF_SIZE 4096

#include <pcap.h>

typedef struct HexInstnace {
	pcap_t* handle;
} HexInstnace_t;

HEX_P HexInstnace_t* create_new_hex_instance(const char* device);

HEX_P void free_hex_instance(const HexInstnace_t* handle);

HEX_P int next_packet(HexInstnace_t* instance, char *out_buf, size_t buf_size);

#endif
