#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

typedef uint8_t mac_t[6];

void parse_mac(const char* str, mac_t mac) {
    char* s = strdup(str);
    char* octet = strtok(s, ":");
    int i = 0;
    
    while (octet != NULL && i < 6) {
        mac[i++] = strtol(octet, NULL, 16);

        octet = strtok(NULL, ":");
    }

    free(s);
}

int main(int argc, char** argv) {
    // ifname hostMAC gatewayMAC targetMAC

    mac_t host, gateway, target;
    parse_mac(argv[2], host);
    parse_mac(argv[3], gateway);
    parse_mac(argv[4], target);

    int raw = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw < 0) {
        perror("socket");
        return 1;
    }
    setsockopt(raw, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1]));

    // test receive
    while (1) {
        uint8_t packet[1500];
        ssize_t rd = recv(raw, packet, 1500, 0);
        printf("%lu\n", rd);
    }

    return 0;
}