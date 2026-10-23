/*
 * NSEC zone-walker. From example.com alone, recovers every name by following the
 * NSEC "next name" chain, querying domain-ns directly. libpcap only, DNS queries
 * (no AXFR, no wordlist). Build: cc -O2 -Wall -o walker walker.c -lpcap
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

#define IFACE   "eth0"
#define SELF_IP "172.16.2.100"
#define GW_IP   "172.16.2.3"     /* core-router: our gateway to the authoritative subnet */
#define NS_IP   "172.16.3.30"    /* domain-ns: authoritative for example.com (query it directly) */
#define APEX    "example.com"
#define T_NSEC  47

struct eth_h { uint8_t dst[6], src[6]; uint16_t type; } __attribute__((packed));
struct ip_h  { uint8_t ihl_ver, tos; uint16_t tot_len, id, frag;
               uint8_t ttl, proto; uint16_t check; uint32_t saddr, daddr; } __attribute__((packed));
struct udp_h { uint16_t sport, dport, len, check; } __attribute__((packed));
struct dns_h { uint16_t id, flags, qd, an, ns, ar; } __attribute__((packed));

static uint8_t  own_mac[6], gw_mac[6];
static uint32_t self_ip, gw_ip, ns_ip;
static int      have_gw_mac = 0;

static void get_own_mac(const char *ifn) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, ifn, IFNAMSIZ - 1);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    memcpy(own_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(s);
}

static void send_arp(pcap_t *h) {
    uint8_t f[42];
    struct eth_h *e = (struct eth_h *)f;
    memset(e->dst, 0xff, 6); memcpy(e->src, own_mac, 6); e->type = htons(0x0806);
    uint8_t *a = f + 14;
    a[0]=0;a[1]=1; a[2]=8;a[3]=0; a[4]=6; a[5]=4; a[6]=0;a[7]=1;
    memcpy(a + 8, own_mac, 6);
    memcpy(a + 14, &self_ip, 4); memset(a + 18, 0, 6); memcpy(a + 24, &gw_ip, 4);
    pcap_inject(h, f, sizeof f);
}

static uint16_t ip_checksum(struct ip_h *ip) {
    int ihl = (ip->ihl_ver & 0x0f) * 4; ip->check = 0;
    uint32_t s = 0; const uint8_t *p = (const uint8_t *)ip;
    for (int i = 0; i + 1 < ihl; i += 2) s += (p[i] << 8) | p[i+1];
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return htons(~s & 0xffff);
}
static uint16_t udp_checksum(struct ip_h *ip, struct udp_h *udp) {
    uint16_t ulen = ntohs(udp->len); uint32_t s = 0;
    const uint8_t *a = (const uint8_t *)&ip->saddr, *b = (const uint8_t *)&ip->daddr;
    s += (a[0]<<8)|a[1]; s += (a[2]<<8)|a[3]; s += (b[0]<<8)|b[1]; s += (b[2]<<8)|b[3];
    s += 17; s += ulen; udp->check = 0;
    const uint8_t *p = (const uint8_t *)udp;
    for (int i = 0; i + 1 < ulen; i += 2) s += (p[i]<<8)|p[i+1];
    if (ulen & 1) s += p[ulen-1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    uint16_t r = ~s; return htons(r ? r : 0xffff);
}

/* skip a wire name, return offset just past it (handles a compression pointer) */
static int skip_name(const uint8_t *d, int off, int len) {
    while (off < len) { uint8_t l = d[off];
        if (l == 0) return off + 1;
        if ((l & 0xC0) == 0xC0) return off + 2;
        off += l + 1; }
    return off;
}
/* decode a wire name to dotted text (strips trailing dot) */
static void decode_name(const uint8_t *d, int off, int len, char *out, int osz) {
    int o = 0, hops = 0;
    while (off < len && hops < 20) { uint8_t l = d[off];
        if (l == 0) break;
        if ((l & 0xC0) == 0xC0) { off = ((l & 0x3F) << 8) | d[off+1]; hops++; continue; }
        off++;
        for (int i = 0; i < l && off < len; i++) { if (o < osz-1) out[o++] = d[off]; off++; }
        if (o < osz-1) out[o++] = '.';
    }
    if (o && out[o-1] == '.') o--;
    out[o] = 0;
}

/* write a dotted name as wire labels, return length */
static int encode_name(uint8_t *dst, const char *name) {
    int o = 0; const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        int l = dot ? (int)(dot - p) : (int)strlen(p);
        dst[o++] = l; memcpy(dst + o, p, l); o += l;
        if (!dot) break; p = dot + 1;
    }
    dst[o++] = 0; return o;
}

/* build a DNS query <name>/NSEC with EDNS DO; return dns length */
static int build_query(uint8_t *dns, const char *name, uint16_t txid) {
    struct dns_h *dh = (struct dns_h *)dns; memset(dh, 0, 12);
    dh->id = htons(txid); dh->flags = htons(0x0100);   /* RD */
    dh->qd = htons(1); dh->ar = htons(1);              /* 1 question, 1 OPT */
    int o = 12;
    o += encode_name(dns + o, name);
    *(uint16_t *)(dns + o) = htons(T_NSEC); o += 2;
    *(uint16_t *)(dns + o) = htons(1);      o += 2;    /* IN */
    dns[o++] = 0;                                        /* OPT: root name */
    *(uint16_t *)(dns + o) = htons(41);   o += 2;       /* type OPT */
    *(uint16_t *)(dns + o) = htons(4096); o += 2;       /* UDP size */
    *(uint32_t *)(dns + o) = htonl(0x00008000); o += 4; /* DO bit */
    *(uint16_t *)(dns + o) = 0; o += 2;                 /* rdlen 0 */
    return o;
}

/* scan answer + authority for an NSEC RR, decode its next name into out */
static int find_nsec_next(const uint8_t *dns, int dnslen, char *out) {
    const struct dns_h *dh = (const struct dns_h *)dns;
    int qd = ntohs(dh->qd), an = ntohs(dh->an), ns = ntohs(dh->ns);
    int off = 12;
    for (int i = 0; i < qd; i++) { off = skip_name(dns, off, dnslen); off += 4; }
    for (int i = 0; i < an + ns && off < dnslen; i++) {
        int ne = skip_name(dns, off, dnslen);
        if (ne + 10 > dnslen) break;
        uint16_t type  = ntohs(*(uint16_t *)(dns + ne));
        uint16_t rdlen = ntohs(*(uint16_t *)(dns + ne + 8));
        if (type == T_NSEC) { decode_name(dns, ne + 10, dnslen, out, 256); return 1; }
        off = ne + 10 + rdlen;
    }
    return 0;
}

/* query <name>/NSEC at domain-ns, put the next name in out. 1 ok, 0 no NSEC, -1 timeout */
static int query_nsec(pcap_t *h, const char *name, char *out) {
    static uint8_t frame[1500];
    uint16_t txid = rand() & 0xffff;
    struct eth_h *e = (struct eth_h *)frame;
    memcpy(e->dst, gw_mac, 6); memcpy(e->src, own_mac, 6); e->type = htons(0x0800);
    struct ip_h  *ip  = (struct ip_h *)(frame + 14);
    struct udp_h *udp = (struct udp_h *)(frame + 14 + 20);
    uint8_t *dns = (uint8_t *)udp + 8;
    int dnslen = build_query(dns, name, txid);
    udp->sport = htons(40000 + (rand() % 20000)); udp->dport = htons(53);
    udp->len = htons(8 + dnslen);
    ip->ihl_ver = 0x45; ip->tos = 0; ip->tot_len = htons(20 + 8 + dnslen);
    ip->id = htons(txid); ip->frag = htons(0x4000); ip->ttl = 64; ip->proto = 17;
    ip->saddr = self_ip; ip->daddr = ns_ip;
    ip->check = ip_checksum(ip); udp->check = udp_checksum(ip, udp);
    int framelen = 14 + 20 + 8 + dnslen;

    for (int t = 0; t < 6; t++) {
        pcap_inject(h, frame, framelen);
        time_t t0 = time(NULL);
        while (time(NULL) - t0 < 2) {
            struct pcap_pkthdr *hd; const u_char *pkt;
            if (pcap_next_ex(h, &hd, &pkt) != 1) continue;
            if (hd->caplen < 14 + 20 + 8 + 12) continue;
            const struct ip_h *rip = (const struct ip_h *)(pkt + 14);
            if (rip->proto != 17) continue;
            int riphl = (rip->ihl_ver & 0x0f) * 4;
            const struct udp_h *rudp = (const struct udp_h *)(pkt + 14 + riphl);
            if (ntohs(rudp->sport) != 53 || rip->saddr != ns_ip) continue;
            const uint8_t *rdns = (const uint8_t *)rudp + 8;
            if (ntohs(((struct dns_h *)rdns)->id) != txid) continue;
            int rdnslen = ntohs(rudp->len) - 8;
            return find_nsec_next(rdns, rdnslen, out) ? 1 : 0;
        }
    }
    return -1;
}

int main(void) {
    srand(time(NULL) ^ getpid());
    self_ip = inet_addr(SELF_IP); gw_ip = inet_addr(GW_IP); ns_ip = inet_addr(NS_IP);
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *h = pcap_open_live(IFACE, 65535, 0, 10, err);
    if (!h) { fprintf(stderr, "pcap: %s\n", err); return 1; }
    get_own_mac(IFACE);

    char filt[128];
    snprintf(filt, sizeof filt, "arp or (udp and src port 53 and dst host %s)", SELF_IP);
    struct bpf_program bp;
    pcap_compile(h, &bp, filt, 1, PCAP_NETMASK_UNKNOWN); pcap_setfilter(h, &bp);

    /* learn the gateway's MAC (we route to domain-ns through core-router) */
    for (int i = 0; i < 50 && !have_gw_mac; i++) {
        send_arp(h); time_t t0 = time(NULL);
        while (time(NULL) - t0 < 1 && !have_gw_mac) {
            struct pcap_pkthdr *hd; const u_char *p;
            if (pcap_next_ex(h, &hd, &p) == 1) {
                const struct eth_h *e = (const struct eth_h *)p;
                if (ntohs(e->type) == 0x0806) { const uint8_t *a = p + 14;
                    if (a[6]==0 && a[7]==2 && memcmp(a+14, &gw_ip, 4)==0) {
                        memcpy(gw_mac, a+8, 6); have_gw_mac = 1; } }
            }
        }
    }
    if (!have_gw_mac) { fprintf(stderr, "could not ARP gateway\n"); return 1; }

    printf("NSEC zone-walk of %s (querying domain-ns %s directly)\n", APEX, NS_IP);
    printf("---------------------------------------------\n");
    char cur[256], next[256];
    strcpy(cur, APEX);
    int queries = 0, recovered = 0;
    for (int step = 0; step < 100; step++) {
        int r = query_nsec(h, cur, next);
        queries++;
        if (r != 1) { printf("  (no NSEC for %s -> walk stops)\n", cur); break; }
        if (strcasecmp(next, APEX) == 0) { printf("  %s -> %s  [wrapped to apex, done]\n", cur, next); break; }
        printf("  %-22s NSEC-> %s\n", cur, next);
        recovered++;
        strncpy(cur, next, sizeof cur - 1); cur[sizeof cur - 1] = 0;
    }
    printf("---------------------------------------------\n");
    printf("recovered %d names in %d queries\n", recovered, queries);
    return 0;
}
