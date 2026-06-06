#define _GNU_SOURCE
#include "ft_traceroute.h"

static void send_udp_packet(int sockfd, struct sockaddr_in *dest, int port, int packet_len) {
    dest->sin_port = htons((uint16_t)port);
    int  payload_len = packet_len - IP_HEADER_LEN - UDP_HEADER_LEN;
    char payload[payload_len + 1];
    ft_memset(payload, 0, (size_t)payload_len);
    (void)sendto(sockfd, payload, (size_t)payload_len, 0,
                 (struct sockaddr *)dest, sizeof(*dest));
}

static void send_icmp_packet(int sockfd, struct sockaddr_in *dest,
                             int seq, uint16_t id, int packet_len) {
    int  icmp_len = packet_len - IP_HEADER_LEN;
    char packet[icmp_len];
    ft_memset(packet, 0, (size_t)icmp_len);

    struct icmphdr *icmp   = (struct icmphdr *)packet;
    icmp->type             = ICMP_ECHO;
    icmp->un.echo.id       = htons(id);
    icmp->un.echo.sequence = htons((uint16_t)seq);
    icmp->checksum         = checksum(packet, icmp_len);

    (void)sendto(sockfd, packet, (size_t)icmp_len, 0,
                 (struct sockaddr *)dest, sizeof(*dest));
}

void send_hop_packets(int send_sock, struct sockaddr_in *dest,
                      int ttl, uint16_t id, t_hop *hop,
                      const t_options *opts) {
    struct timeval now;
    gettimeofday(&now, NULL);

    if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
        return;

    int base = opts->port + (ttl - 1) * opts->nqueries;

    for (int i = 0; i < opts->nqueries; i++) {
        t_packet *pkt = &hop->packets[i];
        pkt->send_time = now;
        pkt->deadline  = now;
        timeval_add_ms(&pkt->deadline, TIMEOUT_MS);

        if (opts->icmp_mode)
            send_icmp_packet(send_sock, dest, base + i, id, opts->packet_len);
        else
            send_udp_packet(send_sock, dest, base + i, opts->packet_len);
    }
}

int hop_is_complete(t_hop *hop, int nqueries) {
    for (int i = 0; i < nqueries; i++)
        if (!hop->packets[i].done) return 0;
    return 1;
}

void expire_packets(t_hop *hops, int from_ttl, int to_ttl,
                    int nqueries, struct timeval *now) {
    for (int ttl = from_ttl; ttl <= to_ttl; ttl++) {
        if (hops[ttl].done) continue;
        for (int i = 0; i < nqueries; i++) {
            t_packet *pkt = &hops[ttl].packets[i];
            if (!pkt->done && !timercmp(&pkt->deadline, now, >))
                pkt->done = 1;
        }
    }
}

int next_deadline(t_hop *hops, int from_ttl, int to_ttl,
                  int nqueries, struct timeval *now, struct timeval *wait_out) {
    struct timeval earliest = {0, 0};
    int found = 0;
    for (int ttl = from_ttl; ttl <= to_ttl; ttl++) {
        if (hops[ttl].done) continue;
        for (int i = 0; i < nqueries; i++) {
            t_packet *pkt = &hops[ttl].packets[i];
            if (pkt->done) continue;
            if (!found || timercmp(&pkt->deadline, &earliest, <)) {
                earliest = pkt->deadline;
                found = 1;
            }
        }
    }
    if (!found) return 0;
    if (timercmp(&earliest, now, >))
        timersub(&earliest, now, wait_out);
    else
        *wait_out = (struct timeval){0, 0};
    return 1;
}

static int match_icmp(struct icmphdr *icmp, uint16_t id, int bytes, int ip_len) {
    if (icmp->type == ICMP_ECHOREPLY) {
        if (ntohs(icmp->un.echo.id) != id) return -1;
        return ntohs(icmp->un.echo.sequence);
    }
    if (icmp->type == ICMP_TIME_EXCEEDED) {
        int min_size = ip_len + (int)sizeof(struct icmphdr) + (int)sizeof(struct iphdr) + 8;
        if (bytes < min_size) return -1;
        struct iphdr   *inner_ip   = (struct iphdr *)((char *)icmp + sizeof(struct icmphdr));
        if (inner_ip->ihl < 5) return -1;
        struct icmphdr *inner_icmp = (struct icmphdr *)((char *)inner_ip + inner_ip->ihl * 4);
        if (ntohs(inner_icmp->un.echo.id) != id) return -1;
        return ntohs(inner_icmp->un.echo.sequence);
    }
    return -1;
}

static int match_udp(struct icmphdr *icmp, int bytes, int ip_len) {
    if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_UNREACH) return -1;

    int icmp_hdr_end = ip_len + (int)sizeof(struct icmphdr);
    if (bytes < icmp_hdr_end + (int)sizeof(struct iphdr)) return -1;

    struct iphdr *inner_ip  = (struct iphdr *)((char *)icmp + sizeof(struct icmphdr));
    if (inner_ip->ihl < 5) return -1;

    int inner_ip_len = inner_ip->ihl * 4;
    if (bytes < icmp_hdr_end + inner_ip_len + 8) return -1;

    struct udphdr *inner_udp = (struct udphdr *)((char *)inner_ip + inner_ip_len);
    return ntohs(inner_udp->dest);
}

void receive_response(int recv_sock, t_hop *hops, uint16_t id,
                      int from_ttl, int to_ttl, const t_options *opts) {
    char buf[MAX_PACKET_SIZE];
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);

    while (1) {
        ssize_t n = recvfrom(recv_sock, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&from, &from_len);
        if (n < 0) break;
        struct timeval now;
        gettimeofday(&now, NULL);
        if (n < (ssize_t)sizeof(struct iphdr)) continue;
        struct iphdr *ip = (struct iphdr *)buf;
        int ip_len = ip->ihl * 4;
        if (ip_len < 20 || n < (ssize_t)(ip_len + (int)sizeof(struct icmphdr))) continue;
        struct icmphdr *icmp = (struct icmphdr *)(buf + ip_len);

        int packet_id = opts->icmp_mode
            ? match_icmp(icmp, id, (int)n, ip_len)
            : match_udp(icmp, (int)n, ip_len);
        if (packet_id < 0) continue;

        /* uint16_t cast for correct modular subtraction when port wraps past 65535 */
        int offset = (int)((uint16_t)(packet_id - opts->port));
        int ttl  = offset / opts->nqueries + 1;
        int pidx = offset % opts->nqueries;
        if (ttl < from_ttl || ttl > to_ttl || pidx >= opts->nqueries) continue;

        t_packet *pkt = &hops[ttl].packets[pidx];
        if (pkt->done) continue;
        pkt->done      = 1;
        pkt->got_reply = 1;
        pkt->rtt       = time_diff_ms(&pkt->send_time, &now);
        pkt->from_addr = from;
        inet_ntop(AF_INET, &from.sin_addr, pkt->from_ip, INET_ADDRSTRLEN);
        if (icmp->type == ICMP_ECHOREPLY ||
            (icmp->type == ICMP_UNREACH && icmp->code == ICMP_UNREACH_PORT))
            hops[ttl].reached = 1;
    }
}
