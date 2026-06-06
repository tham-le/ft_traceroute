#define _GNU_SOURCE
#include "ft_traceroute.h"

typedef struct {
    int send_ttl;
    int print_ttl;
    int last_ttl;
    int pending;
} t_loop;

static void send_packets(int send_sock, struct sockaddr_in *dest, uint16_t id,
                        t_hop *hops, t_loop *loop, const t_options *opts) {
    while (loop->send_ttl <= loop->last_ttl && loop->pending < opts->squeries) {
        int ttl = loop->send_ttl;
        send_hop_packets(send_sock, dest, ttl, id, &hops[ttl], opts);
        loop->send_ttl++;
        loop->pending++;
    }
}

static int handle_replies(int recv_sock, t_hop *hops, uint16_t id,
                         t_loop *loop, const t_options *opts) {
    struct timeval now, wait;
    gettimeofday(&now, NULL);
    if (next_deadline(hops, loop->print_ttl, loop->send_ttl - 1,
                      opts->nqueries, &now, &wait)) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(recv_sock, &fds);
        int ret = select(recv_sock + 1, &fds, NULL, NULL, &wait);
        if (ret > 0)
            receive_response(recv_sock, hops, id,
                             loop->print_ttl, loop->send_ttl - 1, opts);
        else if (ret < 0 && errno != EINTR)
            return -1;
    }
    gettimeofday(&now, NULL);
    expire_packets(hops, loop->print_ttl, loop->send_ttl - 1, opts->nqueries, &now);
    return 0;
}

static void close_complete_hops(t_hop *hops, t_loop *loop, int nqueries) {
    for (int ttl = loop->print_ttl; ttl < loop->send_ttl; ttl++) {
        if (hops[ttl].done || !hop_is_complete(&hops[ttl], nqueries))
            continue;
        hops[ttl].done = 1;
        loop->pending--;
        if (hops[ttl].reached && ttl < loop->last_ttl) {
            loop->last_ttl = ttl;
            for (int t = ttl + 1; t < loop->send_ttl; t++) {
                if (!hops[t].done) {
                    hops[t].done = 1;
                    loop->pending--;
                }
            }
        }
    }
}

static int print_ready_hops(t_hop *hops, t_loop *loop, int nqueries, int do_dns) {
    while (loop->print_ttl < loop->send_ttl && hops[loop->print_ttl].done) {
        print_hop_line(loop->print_ttl, &hops[loop->print_ttl], nqueries, do_dns);
        if (hops[loop->print_ttl].reached) return 1;
        loop->print_ttl++;
    }
    return 0;
}

static int print_results(t_hop *hops, t_loop *loop, const t_options *opts) {
    close_complete_hops(hops, loop, opts->nqueries);
    return print_ready_hops(hops, loop, opts->nqueries, opts->do_dns);
}

static int run_traceroute(int send_sock, int recv_sock, struct sockaddr_in *dest,
                          uint16_t id, t_options *opts) {
    t_hop *hops = malloc((size_t)(opts->max_ttl + 1) * sizeof(t_hop));
    if (!hops) {
        fprintf(stderr, "ft_traceroute: out of memory\n");
        return 1;
    }
    ft_memset(hops, 0, (size_t)(opts->max_ttl + 1) * sizeof(t_hop));
    t_loop loop = { opts->first_ttl, opts->first_ttl, opts->max_ttl, 0 };

    while (loop.print_ttl <= loop.last_ttl) {
        send_packets(send_sock, dest, id, hops, &loop, opts);
        if (loop.pending == 0)
            break;
        int socket_res = handle_replies(recv_sock, hops, id, &loop, opts);
        if (socket_res < 0)
            break;
        int trace_done = print_results(hops, &loop, opts);
        if (trace_done)
            break;
    }

    free(hops);
    return 0;
}

int traceroute(const char *target, t_options *opts) {
    struct sockaddr_in dest;
    if (resolve_target(target, &dest) < 0)
        return 1;
    char dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest.sin_addr, dest_ip, sizeof(dest_ip));

    int recv_sock = create_icmp_socket();
    if (recv_sock < 0)
        return 1;
    int send_sock = opts->icmp_mode ? recv_sock : create_udp_socket();
    if (send_sock < 0) {
        close(recv_sock);
        return 1;
    }

    uint16_t id = (uint16_t)(getpid() & 0xFFFF);
    print_header(target, dest_ip, opts);
    int ret = run_traceroute(send_sock, recv_sock, &dest, id, opts);
    if (send_sock != recv_sock) 
        close(send_sock);
    close(recv_sock);
    return ret;
}
