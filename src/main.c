#include "hex.h"
#include <stdlib.h>

int main(int argc, char** argv) {
	HexInstnace_t instance = create_hex_instance("en0");
	char* stream = malloc(HEX_OUT_BUF_SIZE);

	while (1) {
		Packet_t* result = read_next_packet(&instance, stream, HEX_OUT_BUF_SIZE);
		if (result != NULL) {
			printf("Ether type: %2x\n", result->eth_header.type);
			free(result);
		}
	}

	free(stream);
	free_hex_instance(&instance);
}
