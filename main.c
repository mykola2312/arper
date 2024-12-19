#define _DEFAULT_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define FRAME_MIN_LEN 64
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

    int fd; // raw socket
    int if_idx;
};

typedef void* frame_t;

frame_t frame_new(size_t datalen) {
    return malloc(datalen);
}

frame_t frame_full() {
    return malloc(MTU);
}

void frame_free(frame_t frame) {
    free(frame);
}

struct linkinterface* link_open(const char* if_name) {
    struct linkinterface* link = (struct linkinterface*)malloc(sizeof(struct linkinterface));
    link->if_name = strdup(if_name);
    link->if_len = strlen(link->if_name);

    link->fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (link->fd < 0) {
        goto _bad0;
    }
    setsockopt(link->fd, SOL_SOCKET, SO_BINDTODEVICE, link->if_name, link->if_len);

    // get interface index and MAC
    struct ifreq netlink;
    memset(&netlink, '\0', sizeof(netlink));
    strncpy(netlink.ifr_ifrn.ifrn_name, link->if_name, IFNAMSIZ-1);
    if (ioctl(link->fd, SIOCGIFINDEX, &netlink) < 0) {
        goto _bad1;
    }
    link->if_idx = netlink.ifr_ifru.ifru_ivalue; // index

    memset(&netlink, '\0', sizeof(netlink));
    strncpy(netlink.ifr_ifrn.ifrn_name, link->if_name, IFNAMSIZ-1);
    if (ioctl(link->fd, SIOCGIFHWADDR, &netlink) < 0) {
        goto _bad1;
    }
    memcpy(link->host, netlink.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN); // MAC

    return link;
_bad1:
    close(link->fd);
_bad0:
    free(link->if_name);
    free(link);
    return NULL;
}

void link_free(struct linkinterface* link) {
    close(link->fd);
    free(link->if_name);
    free(link);
}

ssize_t link_send(struct linkinterface* link, const uint8_t* dstAddr,
    uint16_t type, frame_t frame, size_t len)
{
    // ETHER FRAME MUST NOT BE LESS THAN 64 (60)
    size_t frame_len = MAX(60, len + sizeof(struct ether_header));
    // add space for ether header and shift user data
    frame = realloc(frame, frame_len);
    memmove((uint8_t*)frame + sizeof(struct ether_header), frame, len);
    //uint8_t* frame = (uint8_t*)malloc(frame_len);
    //memset(frame, '\0', frame_len);

    struct ether_header* ether = (struct ether_header*)frame;
    memcpy(ether->ether_shost, link->host, ETH_ALEN);
    memcpy(ether->ether_dhost, dstAddr, ETH_ALEN);
    ether->ether_type = htons(type);

    struct sockaddr_ll ll_addr = {0};
    ll_addr.sll_family = PF_PACKET;
    ll_addr.sll_ifindex = link->if_idx;
    ll_addr.sll_halen = ETH_ALEN;
    memcpy(ll_addr.sll_addr, dstAddr, ETH_ALEN);

    size_t sent = sendto(link->fd, frame, frame_len, 0,
        (const struct sockaddr*)&ll_addr, sizeof(ll_addr));
    free(frame);
    
    return sent;
}

ssize_t link_recv(struct linkinterface* link, const uint8_t* srcAddr,
    uint16_t type, frame_t frame, size_t len)
{
    uint16_t want_type = htons(type);
    do {
        ssize_t rd = recv(link->fd, frame, len, 0);
        if (rd < 0) return -1;

        struct ether_header* ether = (struct ether_header*)frame;
        // check received packet's source MAC
        // if its someone else than source - skip
        if (memcmp(ether->ether_shost, srcAddr, ETH_ALEN)) {
            continue; // not our source
        }
        if (memcmp(ether->ether_dhost, link->host, ETH_ALEN)) {
            continue; // not our host
        }
        if (ether->ether_type != want_type) {
            continue; // not wanted type
        }

        return rd;
    } while (1);

    // TODO: timeout
}

uint16_t checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len / 2; i++) {
        sum += *((const uint16_t*)data + i);
        sum += sum >> 16;
    }

    return ~((uint16_t)sum);
}

int main(int argc, char** argv) {
    // ifname targetMAC
    struct linkinterface* link = link_open(argv[1]);
    if (!link) {
        perror("link_open");
        return 1;
    }
    print_mac(link->host);

    uint8_t target[ETH_ALEN];
    parse_mac(argv[2], target);

    srand(time(NULL));
    uint16_t id = (uint16_t)rand();

    // ICMP request
    struct icmphdr icmp;
    icmp.type = ICMP_ECHO;
    icmp.code = 0;
    icmp.checksum = 0;
    icmp.un.echo.id = (uint16_t)rand();
    icmp.un.echo.sequence = 1;
    // calculate checksum
    icmp.checksum = htons(checksum((const uint8_t*)&icmp, sizeof(icmp)));

    printf("%lu\n", sizeof(struct ip));

    // IPv4 local broadcast
    uint8_t ip_broadcast[4] = {255, 255, 255, 255};

    link_free(link);
    return 0;
}