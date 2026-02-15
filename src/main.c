#include "hex.h"
#include "ipv4_parser.h"
#include <stdlib.h>

static void mac_to_string(const uint8_t mac[MAC_ADDR_LEN], char *out) {
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

void dump_ether_header(const EtherHeader_t *h) {
    if (!h) {
        printf("null");
        return;
    }

    char src[18];
    char dst[18];

    mac_to_string(h->src_mac, src);
    mac_to_string(h->dst_mac, dst);

    printf("{");
    printf("\"dst_mac\":\"%s\",", dst);
    printf("\"src_mac\":\"%s\",", src);
    printf("\"type\":%u,", h->type);
    printf("\"len\":%d", h->len);
    printf("}");
}

int main(int argc, char** argv) {
	HexInstnace_t instance = create_hex_instance("en0");

	while (1) {
		ProtocolNode_t* result = read_next_packet(&instance);
		if (result != NULL) {
			free_protocol_node(result);
		}
	}

	free_hex_instance(&instance);
}
