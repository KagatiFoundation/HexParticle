/*
MIT License

Copyright (c) 2023 Kagati Foundation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "eth_parser.h"

#define SNIF
#define OUT_BUF_SIZE 4096

SNIF pcap_t* particle_open(char *dev) {
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuff);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuff);
        return NULL;
    }
    return handle;
}

SNIF void particle_close(pcap_t *handle) {
    if (handle) pcap_close(handle);
}

SNIF int particle_next(pcap_t *handle, char *out_buf, size_t buf_size) {
    if (buf_size > OUT_BUF_SIZE) {
        return -4;
    }

    struct pcap_pkthdr *header;
    const u_char *packet;
    int res = pcap_next_ex(handle, &header, &packet);

    if (res == 1) {
        char *json = parse_pkt_to_json(packet, header->caplen);
        if (json == NULL) {
            return -3;
        }

        snprintf(out_buf, buf_size, "%s", json);
        free(json);
        return 0;
    }
    else if (res == 0) {
        return -1;
    }
    else {
        return -2;
    }
}
