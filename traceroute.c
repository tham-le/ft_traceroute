#include "ft_traceroute.h"

static int create_icmp_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("ft_traceroute: socket");
        return -1;
    }
    return sockfd;
}

static int resolve_target(const char *target, struct sockaddr_in *dest) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int ret = getaddrinfo(target, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "ft_traceroute: %s: %s\n", target, gai_strerror(ret));
        return -1;
    }
    *dest = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return 0;
}

static unsigned short checksum(void *data, int len) {
    unsigned short *buf = data;
    unsigned long   sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

static void send_probe(int sockfd, struct sockaddr_in *dest,
                       int ttl, int seq, uint16_t id) {
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt IP_TTL");
        return;
    }

    char packet[sizeof(struct icmphdr) + PROBE_DATA_SIZE];
    memset(packet, 0, sizeof(packet));

    struct icmphdr *icmp   = (struct icmphdr *)packet;
    icmp->type             = ICMP_ECHO;
    icmp->code             = 0;
    icmp->un.echo.id       = htons(id);
    icmp->un.echo.sequence = htons((uint16_t)seq);
    icmp->checksum         = 0;
    icmp->checksum         = checksum(packet, sizeof(packet));

    if (sendto(sockfd, packet, sizeof(packet), 0,
               (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("sendto");
    }
}

static double time_diff_ms(struct timeval *start, struct timeval *end) {
    return (end->tv_sec  - start->tv_sec)  * 1000.0
         + (end->tv_usec - start->tv_usec) / 1000.0;
}

/*
 * select() on Linux updates the timeout struct with remaining time, so
 * looping on non-matching packets correctly consumes the per-probe budget.
 *
 * is_dest_out: 1 = ICMP Echo Reply (destination reached), 0 = Time Exceeded.
 */
static int wait_for_response(int sockfd, uint16_t id, int seq,
                             struct sockaddr_in *from_addr,
                             struct timeval *send_time,
                             double *rtt_out, int *is_dest_out,
                             int timeout_sec) {
    struct timeval timeout = { timeout_sec, 0 };
    char      buf[MAX_PACKET_SIZE];
    socklen_t addr_len;

    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);

        int ret = select(sockfd + 1, &fds, NULL, NULL, &timeout);
        if (ret == 0)
            return 0;
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        addr_len = sizeof(*from_addr);
        ssize_t bytes = recvfrom(sockfd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)from_addr, &addr_len);
        if (bytes < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            return -1;
        }

        struct timeval recv_time;
        gettimeofday(&recv_time, NULL);

        if (bytes < (ssize_t)sizeof(struct iphdr))
            continue;

        struct iphdr *ip     = (struct iphdr *)buf;
        int           ip_len = ip->ihl * 4;

        if (bytes < ip_len + (ssize_t)sizeof(struct icmphdr))
            continue;

        struct icmphdr *icmp = (struct icmphdr *)(buf + ip_len);

        if (icmp->type == ICMP_ECHOREPLY) {
            if (ntohs(icmp->un.echo.id) == id &&
                ntohs(icmp->un.echo.sequence) == (uint16_t)seq) {
                *rtt_out     = time_diff_ms(send_time, &recv_time);
                *is_dest_out = 1;
                return 1;
            }
        } else if (icmp->type == ICMP_TIME_EXCEEDED) {
            /* The router embeds the original IP header + first 8 bytes of the
             * original ICMP header so we can match the reply to our probe. */
            int nested_offset = ip_len + (int)sizeof(struct icmphdr);
            if (bytes < nested_offset + (int)sizeof(struct iphdr))
                continue;
            struct iphdr *orig_ip     = (struct iphdr *)(buf + nested_offset);
            int           orig_ip_len = orig_ip->ihl * 4;
            if (bytes < nested_offset + orig_ip_len + (int)sizeof(struct icmphdr))
                continue;
            struct icmphdr *orig_icmp =
                (struct icmphdr *)(buf + nested_offset + orig_ip_len);
            if (ntohs(orig_icmp->un.echo.id) == id &&
                ntohs(orig_icmp->un.echo.sequence) == (uint16_t)seq) {
                *rtt_out     = time_diff_ms(send_time, &recv_time);
                *is_dest_out = 0;
                return 1;
            }
        }
        /* Not our packet; keep waiting with remaining timeout. */
    }
}

int traceroute(char *target, struct s_options *opts) {
    struct sockaddr_in dest;
    if (resolve_target(target, &dest) < 0)
        return 1;

    int sockfd = create_icmp_socket();
    if (sockfd < 0)
        return 1;

    uint16_t id = (uint16_t)(getpid() & 0xFFFF);

    struct timeval send_time;
    gettimeofday(&send_time, NULL);
    send_probe(sockfd, &dest, 1, 0, id);

    struct sockaddr_in from;
    double rtt     = 0;
    int    is_dest = 0;
    int    got = wait_for_response(sockfd, id, 0, &from, &send_time,
                                   &rtt, &is_dest, opts->timeout_sec);
    if (got == 1) {
        char from_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip));
        printf("%s  %.3f ms  %s\n", from_ip, rtt,
               is_dest ? "(destination)" : "(time exceeded)");
    } else {
        printf("*\n");
    }

    close(sockfd);
    return 0;
}
