#include "hex.h"
#include "packet.h"

#include <stdlib.h>

HEX_P HexInstnace_t create_hex_instance(const char* device) {
	char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuff);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuff);
        exit(EXIT_FAILURE);
    }

	HexInstnace_t hex_instance;
	hex_instance.handle = handle;

    return hex_instance;
}

HEX_P void free_hex_instance(const HexInstnace_t* handle) {
	if (handle == NULL) return;

	pcap_close(handle->handle);
}

HEX_P int next_packet(HexInstnace_t* instance, char *out_buf, size_t buf_size) {
	if (buf_size > HEX_OUT_BUF_SIZE) {
        return -4;
    }

    struct pcap_pkthdr *header;
    const char *packet;
    int res = pcap_next_ex(instance->handle, &header, &packet);

    if (res == 1) {
		Packet_t* parsed_packet = parse_packet(packet, header->caplen);
		printf("%d\n", parsed_packet->eth_header.type);

		if (parsed_packet != NULL) free(parsed_packet);
        return 0;
    }
    else if (res == 0) {
        return -1;
    }
    else {
        return -2;
    }
}

#ifdef RUN_MAIN

int main(int argc, char** argv) {
	HexInstnace_t instance = create_hex_instance("en0");
	char* stream = malloc(HEX_OUT_BUF_SIZE);

	while (1) {
		int result = next_packet(&instance, stream, HEX_OUT_BUF_SIZE);
	}
	free_hex_instance(&instance);
}

#endif
