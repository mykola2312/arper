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

#define MTU 1500

void parse_mac(const char* str, uint8_t* mac) {
    char* s = strdup(str);
    char* octet = strtok(s, ":");
    int i = 0;
    
    while (octet != NULL && i < 6) {
        mac[i++] = strtol(octet, NULL, 16);

        octet = strtok(NULL, ":");
    }

    free(s);
}

void print_mac(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

struct linkinterface {
    char* if_name;
    socklen_t if_len;

    uint8_t host[ETH_ALEN];
    uint8_t gateway[ETH_ALEN];

    int fd; // raw socket
};

struct linkinterface* link_parse(const char* if_name, const char* host, const char* gateway) {
    struct linkinterface* link = (struct linkinterface*)malloc(sizeof(struct linkinterface));
    link->if_name = strdup(if_name);
    link->if_len = strlen(link->if_name);

    parse_mac(host, link->host);
    parse_mac(gateway, link->gateway);
}

int link_open(struct linkinterface* link) {
    link->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (link->fd < 0) {
        return 1;
    }
    setsockopt(link->fd, SOL_SOCKET, SO_BINDTODEVICE, link->if_name, link->if_name);
}

void link_free(struct linkinterface* link) {
    close(link->fd);
    free(link->if_name);
    free(link);
}

typedef struct arp_packet_s {
    struct ether_header ether;
    
    uint16_t hrd;           // Hardware address space (e.g., Ethernet, Packet Radio Net.)
    uint16_t pro;           // Protocol address space.  For Ethernet hardware, this is from the set of type fields ether_typ$<protocol>.
    uint8_t hln;            // byte length of each hardware address
    uint8_t pln;            // byte length of each protocol address
    uint16_t op;            // opcode (ares_op$REQUEST | ares_op$REPLY)
    uint8_t sha[ETH_ALEN];  // Hardware address of sender of this packet
    uint8_t spa[4];         // Protocol address of sender of this packet
    uint8_t tha[ETH_ALEN];  // Hardware address of sender of this packet
    uint8_t tpa[4];         // Protocol address of sender of this packet
} __attribute__((packed)) arp_packet_t;

#define ARP_OP_REQUEST      0x01
#define ARP_OP_REPLY        0x02

int link_send(struct linkinterface* link, uint16_t type, uint8_t* packet, size_t len) {
    struct ether_header* ether = (struct ether_header*)packet;
    memcpy(ether->ether_shost, link->host, ETH_ALEN);
    memcpy(ether->ether_dhost, link->gateway, ETH_ALEN);
    ether->ether_type = htons(type);

    return send(link->fd, packet, len, 0);
}

int link_recv(struct linkinterface* link, uint16_t type, uint8_t* packet, size_t len) {
    char buffer[MTU];
    uint16_t want_type = htons(type);
    do {
        ssize_t rd = recv(link->fd, buffer, MTU, 0);
        if (rd < 0) return -1;

        struct ether_header* ether = (struct ether_header*)buffer;
        // check received packet's source MAC
        // if its someone else than gateway - skip
        if (memcmp(ether->ether_shost, link->gateway, ETH_ALEN)) {
            continue; // not our gateway
        }
        if (memcmp(ether->ether_dhost, link->host, ETH_ALEN)) {
            continue; // not our host
        }
        if (ether->ether_type != want_type) {
            continue; // not wanted type
        }

        // copy packet to recv buffer
        memcpy(packet, buffer, rd);
        return rd;
    } while (1);

    // TODO: timeout
}

int main(int argc, char** argv) {
    // ifname hostMAC gatewayMAC targetMAC
    struct linkinterface* link = link_parse(argv[1], argv[2], argv[3]);

    uint8_t target[ETH_ALEN];
    parse_mac(argv[4], target);

    link_open(link);

    // test receive
    while (1) {
        uint8_t packet[MTU];
        ssize_t rd = recv(link->fd, packet, MTU, 0);
        
        struct ether_header *ether = (struct ether_header *)&packet[0];
        print_mac(ether->ether_shost);
    }

    link_free(link);
    return 0;
}