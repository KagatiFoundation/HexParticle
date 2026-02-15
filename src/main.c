#include "hex.h"
#include <stdlib.h>

int main(int argc, char** argv) {
	HexInstnace_t instance = create_hex_instance("en0");

	while (1) {
		Packet_t* result = read_next_packet(&instance);
		if (result != NULL) {
			// printf("Ether type: 0x%X\n", result->eth_header.type);
			__builtin_dump_struct(result, &printf);
			free(result);
		}
	}

	free_hex_instance(&instance);
}
