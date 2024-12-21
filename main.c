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

void output_mac(uint8_t* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

typedef struct {
    char* if_name;
    socklen_t if_len;

    uint8_t host[ETH_ALEN];
    uint8_t host_ip[4];

    int fd; // raw socket
    int if_idx;
    int if_mtu;
} linkinterface_t;

// because C has retarded array types
typedef struct {
    uint8_t mac[ETH_ALEN];
} __attribute__((packed)) mac_t;

typedef struct {
    union {
        uint32_t addr;
        uint8_t octets[4];
    };
} __attribute__((packed)) ip4addr_t;

typedef struct {
    uint16_t id;
    void* data;
    size_t datalen;
} frame_t;

frame_t* frame_new(size_t datalen) {
    frame_t* frame = (frame_t*)malloc(sizeof(frame_t));
    frame->id = (uint16_t)rand();
    frame->data = malloc(datalen);
    frame->datalen = datalen;

    memset(frame->data, '\0', frame->datalen);
    return frame;
}

frame_t* frame_full(linkinterface_t* link) {
    return frame_new(link->if_mtu);
}

void frame_free(frame_t* frame) {
    free(frame->data);
    free(frame);
}

linkinterface_t* link_open(const char* if_name) {
    linkinterface_t* link = (linkinterface_t*)malloc(sizeof(linkinterface_t));
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
    // get interface IP address
    memset(&netlink, '\0', sizeof(netlink));
    strncpy(netlink.ifr_ifrn.ifrn_name, link->if_name, IFNAMSIZ-1);
    netlink.ifr_ifru.ifru_addr.sa_family = PF_INET;
    if (ioctl(link->fd, SIOCGIFADDR, &netlink) < 0) {
        goto _bad1;
    }
    memcpy(link->host_ip, &((struct sockaddr_in*)&netlink.ifr_ifru.ifru_addr)->sin_addr, 4);
    // get interface MTU
    memset(&netlink, '\0', sizeof(netlink));
    strncpy(netlink.ifr_ifrn.ifrn_name, link->if_name, IFNAMSIZ-1);
    if (ioctl(link->fd, SIOCGIFMTU, &netlink) < 0) {
        goto _bad1;
    }
    link->if_mtu = netlink.ifr_ifru.ifru_mtu;

    return link;
_bad1:
    close(link->fd);
_bad0:
    free(link->if_name);
    free(link);
    return NULL;
}

void link_free(linkinterface_t* link) {
    close(link->fd);
    free(link->if_name);
    free(link);
}

ssize_t link_send(linkinterface_t* link, const mac_t* dstAddr,
    uint16_t type, frame_t* frame)
{
    // ETHER FRAME MUST NOT BE LESS THAN 64 (60)
    size_t oldlen = frame->datalen;
    frame->datalen = MAX(60, frame->datalen + sizeof(struct ether_header));
    // add space for ether header and shift user data
    frame->data = realloc(frame->data, frame->datalen);
    memmove((uint8_t*)frame->data + sizeof(struct ether_header), frame->data, oldlen);

    struct ether_header* ether = (struct ether_header*)frame->data;
    memcpy(ether->ether_shost, link->host, ETH_ALEN);
    memcpy(ether->ether_dhost, dstAddr->mac, ETH_ALEN);
    ether->ether_type = htons(type);

    struct sockaddr_ll ll_addr = {0};
    ll_addr.sll_family = PF_PACKET;
    ll_addr.sll_ifindex = link->if_idx;
    ll_addr.sll_halen = ETH_ALEN;
    memcpy(ll_addr.sll_addr, dstAddr, ETH_ALEN);

    size_t sent = sendto(link->fd, frame->data, frame->datalen, 0,
        (const struct sockaddr*)&ll_addr, sizeof(ll_addr));
    
    return sent;
}

size_t link_recv_any_from(linkinterface_t* link, 
    const mac_t* srcAddrs, unsigned addrNum,
    uint16_t type, frame_t* frame, unsigned timeoutSec,
    mac_t* matchAddr)
{
    uint64_t deadline = time(NULL) + timeoutSec;

    uint16_t want_type = htons(type);
    do {
        ssize_t rd = recv(link->fd, frame->data, frame->datalen, 0);
        if (rd < 0) return -1;

        if (time(NULL) > deadline) return 0; // TIMEOUT

        struct ether_header* ether = (struct ether_header*)frame->data;
        
        unsigned matches = 0;
        for (unsigned i = 0; i < addrNum; i++) {
            if (!memcmp(ether->ether_shost, srcAddrs[i].mac, ETH_ALEN)) {
                matches = 1;

                if (matchAddr) {
                    memcpy(matchAddr->mac, ether->ether_shost, ETH_ALEN);
                }
                break;
            }
        }
        if (!matches) continue;

        if (memcmp(ether->ether_dhost, link->host, ETH_ALEN)) {
            continue; // not our host
        }
        if (ether->ether_type != want_type) {
            continue; // not wanted type
        }

        // shift back ether header and realloc
        frame->datalen = rd - sizeof(struct ether_header);
        memmove(frame->data, (const uint8_t*)frame->data + sizeof(struct ether_header), frame->datalen);
        frame->data = realloc(frame->data, frame->datalen);

        return frame->datalen;
    } while (1);
}

uint16_t checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i < len / 2; i++) {
        sum += *((const uint16_t*)data + i);
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return ~((uint16_t)sum);
}

ssize_t ip_send(linkinterface_t* link, const mac_t* dstAddr,
    const ip4addr_t dstIp, uint8_t proto, frame_t* frame)
{
    // shift data to add space for IP header
    size_t oldlen = frame->datalen;
    frame->datalen = sizeof(struct ip) + frame->datalen;
    frame->data = realloc(frame->data, frame->datalen);
    memmove((uint8_t*)frame->data + sizeof(struct ip), frame->data, oldlen);
    // create IP packet
    struct ip* ip = (struct ip*)frame->data;
    ip->ip_v = 4;
    ip->ip_hl = sizeof(struct ip) / 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(frame->datalen);
    ip->ip_id = htons(frame->id);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = proto;
    ip->ip_sum = 0;
    memcpy(&ip->ip_src, link->host_ip, 4);
    memcpy(&ip->ip_dst, dstIp.octets, 4);
    // calculate header checksum
    ip->ip_sum = checksum((const uint8_t*)frame->data, sizeof(struct ip));

    return link_send(link, dstAddr, ETHERTYPE_IP, frame);
}

ssize_t icmp_direct_broadcast(linkinterface_t* link, const mac_t* dstAddr, uint16_t seq) {
    size_t hdrlen = sizeof(struct icmphdr);
    const size_t payloadlen = 20;

    frame_t* frame = frame_new(hdrlen + payloadlen);
    struct icmphdr* icmp = (struct icmphdr*)frame->data;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(frame->id);
    icmp->un.echo.sequence = htons(seq);

    uint8_t* payload = (uint8_t*)frame->data + hdrlen;
    for (unsigned i = 0; i < payloadlen; i++) {
        payload[i] = rand() % 256;
    }

    icmp->checksum = checksum((const uint8_t*)frame->data, hdrlen + payloadlen);

    const ip4addr_t ip_broadcast = { .addr = 0xFFFFFFFF };
    size_t sent = ip_send(link, dstAddr, ip_broadcast, IPPROTO_ICMP, frame);
    
    frame_free(frame);
    return sent;
}

// 0 - no match, 1 - matched
unsigned icmp_match(linkinterface_t* link, const mac_t* srcAddrs, unsigned addrNum,
    unsigned timeoutSec,
    mac_t* matchAddr, ip4addr_t* matchIp)
{
    frame_t* frame = frame_full(link);
    size_t recv = link_recv_any_from(link, srcAddrs, addrNum,
        ETHERTYPE_IP, frame, timeoutSec, matchAddr);
    if (recv < 1) goto _match_bad1;

    // we got matching Ethernet frame, let's check IP
    const struct ip* ip = (const struct ip*)frame->data;
    if (memcmp(&ip->ip_dst.s_addr, link->host_ip, 4)) {
        // not originated to our host IP
        goto _match_bad1;
    }

    if (ip->ip_p != IPPROTO_ICMP) {
        goto _match_bad1;
    }

    // check ICMP
    const struct icmphdr* icmp = (const struct icmphdr*)
        ((uint8_t*)frame->data + (ip->ip_hl * 4));
    if (icmp->type != ICMP_ECHOREPLY) {
        goto _match_bad1;
    }

    // so ether frame directed to us, IP direct to us
    // and ICMP is echo reply, therefore we sure
    // that we got right target IP
    memcpy(matchIp->octets, &ip->ip_src.s_addr, 4);

    frame_free(frame);
    return 1;

_match_bad1:
    frame_free(frame);
    return 0;
}

typedef struct {
    mac_t addr;
    ip4addr_t ip;
} mac_ip_t;

mac_ip_t* icmp_resolve(linkinterface_t* link,
    const mac_t* targetAddrs, unsigned addrNum,
    unsigned timeoutSec,
    unsigned* resolvedNum)
{
    mac_ip_t* output = NULL;
    unsigned resolved = 0;
    // sent ICMP packets
    for (unsigned i = 0; i < addrNum; i++) {
        if (icmp_direct_broadcast(link, &targetAddrs[i], 0) < 1) {
            return NULL; // bad link?
        }
    }

    // receive ICMP packets as many as we match
    uint64_t deadline = time(NULL) + timeoutSec;
    do {
        mac_t matchAddr;
        ip4addr_t matchIp;

        if (icmp_match(link, targetAddrs, addrNum,
            timeoutSec, &matchAddr, &matchIp))
        {
            if (resolved) output = (mac_ip_t*)realloc(output, ++resolved * (sizeof(mac_ip_t)));
            else output = (mac_ip_t*)malloc(++resolved * (sizeof(mac_ip_t)));
            memcpy(&output[resolved - 1].addr, &matchAddr, sizeof(matchAddr));
            memcpy(&output[resolved - 1].ip, &matchIp, sizeof(matchIp));
        }
    } while (resolved < addrNum && time(NULL) < deadline);
    
    *resolvedNum = resolved;
    return output;
}

int main(int argc, char** argv) {
    // arper ifname targetMAC1 targetMAC2 ...
    srand(time(NULL)); 

    linkinterface_t* link = link_open(argv[1]);
    if (!link) {
        perror("link_open");
        return 1;
    }
    print_mac(link->host);
    printf("MTU: %d\n", link->if_mtu);

    unsigned targetNum = argc - 2;
    mac_t* targets = (mac_t*)calloc(sizeof(mac_t), targetNum);
    
    for (unsigned i = 0; i < targetNum; i++) {
        parse_mac(argv[2 + i], targets[i].mac);
    }

    unsigned resolvedNum;
    mac_ip_t* resolved = icmp_resolve(link, targets, targetNum, 5, &resolvedNum);
    printf("Resolved: %u\n", resolvedNum);

    if (resolved) {
        for (unsigned i = 0; i < resolvedNum; i++) {
            output_mac(resolved[i].addr.mac);
            printf(" -> %d.%d.%d.%d\n",
                resolved[i].ip.octets[0],
                resolved[i].ip.octets[1],
                resolved[i].ip.octets[2],
                resolved[i].ip.octets[3]
            );
        }
        free(resolved);
    }

    link_free(link);
    return 0;
}