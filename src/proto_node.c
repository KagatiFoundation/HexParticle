#include "proto_node.h"

#include <stdlib.h>

void free_protocol_node(ProtocolNode_t* node) {
	if (node == NULL) return;

	if (node->hdr != NULL) free(node->hdr);

	if (node->next != NULL) free_protocol_node(node->next);
}