#include <stdint.h>

typedef enum {
    PROTO_ETH,
    PROTO_IPV4,
    PROTO_IPV6,
    PROTO_ARP,
    PROTO_TCP,
    PROTO_UDP,
    PROTO_RAW
} ProtoType_t;

typedef struct ProtocolNode {
    ProtoType_t 			type;
    void 					*hdr;
    uint32_t				hdr_len;
    ProtocolNode_t* 		next;
} ProtocolNode_t;

void free_protocol_node(ProtocolNode_t* node);
