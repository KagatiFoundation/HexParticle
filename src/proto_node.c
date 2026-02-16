/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) 2023 Kagati Foundation
 */

#include "proto_node.h"

#include <stdlib.h>

void free_protocol_node(ProtocolNode_t* head) {
	ProtocolNode_t* current = head;
    while (current != NULL) {
        ProtocolNode_t* next_node = current->next;
        
        if (current->hdr) free(current->hdr);
        free(current);
        
        current = next_node;
    }
}
