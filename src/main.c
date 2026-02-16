#include "hex.h"
#include "ipv4_parser.h"
#include "tcp_parser.h"
#include <stdlib.h>

static void mac_to_string(const uint8_t mac[MAC_ADDR_LEN], char *out) {
    sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2],
            mac[3], mac[4], mac[5]);
}

void dump_ether_header(const EtherHeader_t* header) {
    if (header == NULL) {
        printf("NULL\n");
        return;
    }

    char src[18];
    char dst[18];

    mac_to_string(header->src_mac, src);
    mac_to_string(header->dst_mac, dst);

    printf("{");
    printf("\"dst_mac\":\"%s\",", dst);
    printf("\"src_mac\":\"%s\",", src);
    printf("\"type\":%u,", header->type);
    printf("\"len\":%d", header->len);
    printf("}\n");
}

void dump_ipv4_header(const IPV4Header_t* header) {
	if (header == NULL) {
        printf("NULL\n");
        return;
	}

	printf("IPv4 Protocol: %d\n", header->proto);
}

void dump_tcp_header(const TCPHeader_t* header) {
	if (header == NULL) {
		printf("NULL\n");
		return;
	}

	printf("From %d to %d\n", header->sport, header->dport);
}

void dump_node(ProtocolNode_t* node) {
	ProtocolNode_t* current_node = node;
	
	while (current_node != NULL) {
		if (current_node->type == PROTO_ETH) {
			EtherHeader_t* eth_hdr = (EtherHeader_t*) current_node->hdr;
			dump_ether_header(eth_hdr);
		}

		if (current_node->type == PROTO_IPV4) {
			IPV4Header_t* ip_hdr = (IPV4Header_t*) current_node->hdr;
			dump_ipv4_header(ip_hdr);
		}

		if (current_node->type == PROTO_TCP) {
			TCPHeader_t* tcp_hdr = (TCPHeader_t*) current_node->hdr;
			dump_tcp_header(tcp_hdr);
		}

		current_node = current_node->next;
	}
}

int main(int argc, char** argv) {
	HexInstnace_t instance = create_hex_instance("en0");

	while (1) {
		ProtocolNode_t* result = read_next_packet(&instance);
		if (result != NULL) {
			dump_node(result);
			free_protocol_node(result);
		}
	}

	free_hex_instance(&instance);
}
