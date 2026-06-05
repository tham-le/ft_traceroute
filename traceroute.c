#include "ft_traceroute.h"

typedef struct {
    struct timeval     send_time;
    struct timeval     deadline;
    int                done;      /* timed out or reply received */
    int                got_reply;
    double             rtt;
    int                is_dest;
    struct sockaddr_in from_addr;
    char               from_ip[INET_ADDRSTRLEN];
} t_probe;

typedef struct {
    t_probe probes[MAX_NQUERIES];
    int     done;
    int     reached;
} t_hop;

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
                       int ttl, int seq, uint16_t id, int packet_len) {
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        fprintf(stderr, "setsockopt IP_TTL: %s\n", strerror(errno));
        return;
    }
    /* packet_len is the total IP packet size (as traceroute reports it).
     * The kernel prepends the IP header, so we emit packet_len - IP_HEADER_LEN
     * bytes of ICMP. The -l/packetlen range guarantees this is >= 8. */
    int icmp_len = packet_len - IP_HEADER_LEN;
    char packet[icmp_len];
    ft_memset(packet, 0, (size_t)icmp_len);
    struct icmphdr *icmp   = (struct icmphdr *)packet;
    icmp->type             = ICMP_ECHO;
    icmp->code             = 0;
    icmp->un.echo.id       = htons(id);
    icmp->un.echo.sequence = htons((uint16_t)seq);
    icmp->checksum         = checksum(packet, icmp_len);
    if (sendto(sockfd, packet, (size_t)icmp_len, 0,
               (struct sockaddr *)dest, sizeof(*dest)) < 0)
        fprintf(stderr, "ft_traceroute: sendto: %s\n", strerror(errno));
}

static double time_diff_ms(struct timeval *start, struct timeval *end) {
    return (double)(end->tv_sec  - start->tv_sec)  * 1000.0
         + (double)(end->tv_usec - start->tv_usec) / 1000.0;
}

static void timeval_add_ms(struct timeval *tv, long ms) {
    tv->tv_usec += ms * 1000L;
    tv->tv_sec  += tv->tv_usec / 1000000;
    tv->tv_usec %= 1000000;
}

static void send_hop_probes(int sockfd, struct sockaddr_in *dest,
                             int ttl, uint16_t id, int nqueries,
                             long timeout_ms, t_hop *hop,
                             int port_base, int packet_len) {
    struct timeval now;
    gettimeofday(&now, NULL);
    int seq_base = port_base + (ttl - 1) * nqueries;
    for (int p = 0; p < nqueries; p++) {
        t_probe *pr  = &hop->probes[p];
        pr->send_time = now;
        pr->deadline  = now;
        timeval_add_ms(&pr->deadline, timeout_ms);
        pr->done         = 0;
        pr->got_reply    = 0;
        pr->rtt          = 0;
        pr->is_dest      = 0;
        pr->from_ip[0]   = '\0';
        send_probe(sockfd, dest, ttl, seq_base + p, id, packet_len);
    }
    hop->done    = 0;
    hop->reached = 0;
}

static int hop_is_complete(t_hop *hop, int nqueries) {
    for (int p = 0; p < nqueries; p++)
        if (!hop->probes[p].done)
            return 0;
    return 1;
}

static void expire_probes(t_hop *hops, int from_ttl, int to_ttl,
                           int nqueries, struct timeval *now) {
    for (int ttl = from_ttl; ttl <= to_ttl; ttl++) {
        if (hops[ttl].done)
            continue;
        for (int p = 0; p < nqueries; p++) {
            t_probe *pr = &hops[ttl].probes[p];
            if (pr->done)
                continue;
            long diff_us = (pr->deadline.tv_sec  - now->tv_sec)  * 1000000L
                         + (pr->deadline.tv_usec - now->tv_usec);
            if (diff_us <= 0)
                pr->done = 1;
        }
    }
}

/*
 * Computes time until the earliest pending probe deadline.
 * Returns 0 if no pending probes exist, 1 otherwise (fills *out).
 */
static int next_deadline(t_hop *hops, int from_ttl, int to_ttl,
                          int nqueries, struct timeval *now,
                          struct timeval *out) {
    struct timeval earliest;
    int found = 0;

    for (int ttl = from_ttl; ttl <= to_ttl; ttl++) {
        if (hops[ttl].done)
            continue;
        for (int p = 0; p < nqueries; p++) {
            t_probe *pr = &hops[ttl].probes[p];
            if (pr->done)
                continue;
            if (!found || pr->deadline.tv_sec < earliest.tv_sec ||
                (pr->deadline.tv_sec == earliest.tv_sec &&
                 pr->deadline.tv_usec < earliest.tv_usec)) {
                earliest = pr->deadline;
                found    = 1;
            }
        }
    }
    if (!found)
        return 0;

    long diff_us = (earliest.tv_sec  - now->tv_sec)  * 1000000L
                 + (earliest.tv_usec - now->tv_usec);
    if (diff_us < 0)
        diff_us = 0;
    out->tv_sec  = diff_us / 1000000;
    out->tv_usec = diff_us % 1000000;
    return 1;
}

static void receive_response(int sockfd, t_hop *hops, uint16_t id,
                              int nqueries, int from_ttl, int to_ttl,
                              int port_base) {
    char               buf[MAX_PACKET_SIZE];
    struct sockaddr_in from;
    socklen_t          addr_len = sizeof(from);
    ssize_t bytes = recvfrom(sockfd, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &addr_len);
    if (bytes < 0)
        return;

    struct timeval recv_time;
    gettimeofday(&recv_time, NULL);

    if (bytes < (ssize_t)sizeof(struct iphdr))
        return;
    struct iphdr *ip     = (struct iphdr *)buf;
    int           ip_len = ip->ihl * 4;
    if (bytes < ip_len + (ssize_t)sizeof(struct icmphdr))
        return;
    struct icmphdr *icmp = (struct icmphdr *)(buf + ip_len);

    int seq     = -1;
    int is_dest = 0;

    if (icmp->type == ICMP_ECHOREPLY) {
        if (ntohs(icmp->un.echo.id) != id)
            return;
        seq     = ntohs(icmp->un.echo.sequence);
        is_dest = 1;
    } else if (icmp->type == ICMP_TIME_EXCEEDED) {
        int nested = ip_len + (int)sizeof(struct icmphdr);
        if (bytes < nested + (int)sizeof(struct iphdr))
            return;
        struct iphdr *orig_ip     = (struct iphdr *)(buf + nested);
        int           orig_ip_len = orig_ip->ihl * 4;
        if (bytes < nested + orig_ip_len + (int)sizeof(struct icmphdr))
            return;
        struct icmphdr *orig_icmp =
            (struct icmphdr *)(buf + nested + orig_ip_len);
        if (ntohs(orig_icmp->un.echo.id) != id)
            return;
        seq     = ntohs(orig_icmp->un.echo.sequence);
        is_dest = 0;
    } else {
        return;
    }

    int adjusted  = (int)((uint16_t)(seq - port_base));
    int ttl_idx   = adjusted / nqueries + 1;
    int probe_idx = adjusted % nqueries;

    if (ttl_idx < from_ttl || ttl_idx > to_ttl)
        return;
    if (probe_idx < 0 || probe_idx >= nqueries)
        return;

    t_hop   *hop   = &hops[ttl_idx];
    t_probe *probe = &hop->probes[probe_idx];
    if (probe->done)
        return;

    probe->done      = 1;
    probe->got_reply = 1;
    probe->rtt       = time_diff_ms(&probe->send_time, &recv_time);
    probe->is_dest   = is_dest;
    probe->from_addr = from;
    snprintf(probe->from_ip, INET_ADDRSTRLEN, "%s", inet_ntoa(from.sin_addr));

    if (is_dest)
        hop->reached = 1;
}

static void print_hop_line(int ttl, t_hop *hop, int nqueries,
                            const struct s_options *opts) {
    printf("%2d  ", ttl);
    const char *last_ip = "";
    int         first   = 1;
    for (int i = 0; i < nqueries; i++) {
        t_probe *pr = &hop->probes[i];
        if (!pr->got_reply) {
            printf("  *");
            continue;
        }
        if (first || ft_strcmp(pr->from_ip, last_ip) != 0) {
            if (!first)
                printf(" ");
            if (opts->do_dns) {
                char host[NI_MAXHOST];
                if (getnameinfo((struct sockaddr *)&pr->from_addr,
                                sizeof(pr->from_addr),
                                host, sizeof(host), NULL, 0, 0) == 0
                        && ft_strcmp(host, pr->from_ip) != 0)
                    printf("%s (%s)", host, pr->from_ip);
                else
                    printf("%s", pr->from_ip);
            } else {
                printf("%s", pr->from_ip);
            }
            last_ip = pr->from_ip;
            first   = 0;
        }
        printf("  %.3f ms", pr->rtt);
    }
    printf("\n");
    fflush(stdout);
}

static int resolve_target(const char *target, struct sockaddr_in *dest) {
    struct addrinfo hints, *res;
    ft_memset(&hints, 0, sizeof(hints));
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

static int create_icmp_socket(const struct s_options *opts) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        fprintf(stderr, "ft_traceroute: socket: %s\n", strerror(errno));
        if (errno == EPERM || errno == EACCES)
            fprintf(stderr, "ft_traceroute: raw socket requires root privileges\n");
        return -1;
    }
    if (opts->tos) {
        int tos = opts->tos;
        if (setsockopt(sockfd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
            fprintf(stderr, "ft_traceroute: IP_TOS: %s\n", strerror(errno));
            close(sockfd);
            return -1;
        }
    }
    if (opts->iface) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
                       opts->iface, (socklen_t)(ft_strlen(opts->iface) + 1)) < 0) {
            fprintf(stderr, "ft_traceroute: SO_BINDTODEVICE %s: %s\n",
                    opts->iface, strerror(errno));
            close(sockfd);
            return -1;
        }
    }
    if (opts->source) {
        struct sockaddr_in src;
        ft_memset(&src, 0, sizeof(src));
        src.sin_family = AF_INET;
        if (inet_pton(AF_INET, opts->source, &src.sin_addr) != 1) {
            fprintf(stderr, "ft_traceroute: invalid source address: %s\n",
                    opts->source);
            close(sockfd);
            return -1;
        }
        if (bind(sockfd, (struct sockaddr *)&src, sizeof(src)) < 0) {
            fprintf(stderr, "ft_traceroute: bind: %s\n", strerror(errno));
            close(sockfd);
            return -1;
        }
    }
    return sockfd;
}

static void print_header(const char *target, const char *dest_ip,
                         const struct s_options *opts) {
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
           target, dest_ip, opts->max_ttl, opts->packet_len);
}

/*
 * Pipelined probe loop: up to WINDOW_SIZE hops are probed concurrently.
 * Probes for every in-flight hop share one timeout window, so a burst of
 * silent hops costs roughly one timeout total rather than one per hop.
 * Hops are still printed strictly in TTL order.
 */
static void run_traceroute(int sockfd, struct sockaddr_in *dest,
                            uint16_t id, struct s_options *opts) {
    long timeout_ms = opts->timeout_ms;

    t_hop *hops = malloc((size_t)(opts->max_ttl + 1) * sizeof(t_hop));
    if (!hops) {
        fprintf(stderr, "ft_traceroute: malloc: %s\n", strerror(errno));
        return;
    }
    ft_memset(hops, 0, (size_t)(opts->max_ttl + 1) * sizeof(t_hop));

    int next_to_send  = opts->first_ttl;
    int next_to_print = opts->first_ttl;
    int dest_ttl      = opts->max_ttl;
    int in_flight     = 0;

    while (next_to_print <= dest_ttl) {
        /* Fill the send window. */
        while (in_flight < opts->window_size && next_to_send <= dest_ttl) {
            send_hop_probes(sockfd, dest, next_to_send, id,
                            opts->nqueries, timeout_ms, &hops[next_to_send],
                            opts->port, opts->packet_len);
            in_flight++;
            next_to_send++;
        }

        if (in_flight == 0)
            break;

        /* Wait until the next probe deadline. */
        struct timeval now;
        gettimeofday(&now, NULL);

        struct timeval wait;
        if (next_deadline(hops, next_to_print, next_to_send - 1,
                          opts->nqueries, &now, &wait)) {
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(sockfd, &fds);
            int ret = select(sockfd + 1, &fds, NULL, NULL, &wait);
            if (ret > 0)
                receive_response(sockfd, hops, id, opts->nqueries,
                                 next_to_print, next_to_send - 1,
                                 opts->port);
            else if (ret < 0 && errno != EINTR)
                break;
        }

        gettimeofday(&now, NULL);
        expire_probes(hops, next_to_print, next_to_send - 1,
                      opts->nqueries, &now);

        /* Mark hops whose all probes are done. */
        for (int ttl = next_to_print; ttl < next_to_send; ttl++) {
            if (hops[ttl].done)
                continue;
            if (!hop_is_complete(&hops[ttl], opts->nqueries))
                continue;
            hops[ttl].done = 1;
            in_flight--;
            if (hops[ttl].reached && ttl < dest_ttl) {
                dest_ttl = ttl;
                /* Cancel all probes already sent beyond the destination. */
                for (int t = dest_ttl + 1; t < next_to_send; t++) {
                    if (!hops[t].done) {
                        hops[t].done = 1;
                        in_flight--;
                        for (int p = 0; p < opts->nqueries; p++)
                            hops[t].probes[p].done = 1;
                    }
                }
            }
        }

        /* Print completed hops in TTL order. */
        while (next_to_print < next_to_send && hops[next_to_print].done) {
            print_hop_line(next_to_print, &hops[next_to_print], opts->nqueries, opts);
            if (hops[next_to_print].reached) {
                free(hops);
                return;
            }
            next_to_print++;
        }
    }

    free(hops);
}

int traceroute(char *target, struct s_options *opts) {
    struct sockaddr_in dest;
    if (resolve_target(target, &dest) < 0)
        return 1;

    char dest_ip[INET_ADDRSTRLEN];
    snprintf(dest_ip, sizeof(dest_ip), "%s", inet_ntoa(dest.sin_addr));

    int sockfd = create_icmp_socket(opts);
    if (sockfd < 0)
        return 1;

    uint16_t id = (uint16_t)(getpid() & 0xFFFF);

    print_header(target, dest_ip, opts);
    run_traceroute(sockfd, &dest, id, opts);
    close(sockfd);
    return 0;
}
