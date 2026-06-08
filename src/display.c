#define _GNU_SOURCE
#include "ft_traceroute.h"

void print_header(const char *target, const char *dest_ip,
                  const t_options *opts) {
    printf("traceroute to %s (%s), %d hops max\n",
           target, dest_ip, opts->max_ttl);
}

static void print_host(t_packet *pkt, int do_dns) {
    if (do_dns) {
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr *)&pkt->from_addr,
                        sizeof(pkt->from_addr),
                        host, sizeof(host), NULL, 0, 0) == 0) {
            printf("%s (%s)", host, pkt->from_ip);
        } else {
            printf("%s (%s)", pkt->from_ip, pkt->from_ip);
        }
    } else {
        printf("%s", pkt->from_ip);
    }
}

void print_hop_line(int ttl, t_hop *hop, int nqueries, int do_dns) {
    const char *last_ip = "";

    printf("%3d  ", ttl);
    for (int i = 0; i < nqueries; i++) {
        t_packet *pkt = &hop->packets[i];

        if (!pkt->got_reply) {
            printf(" *");
            continue;
        }

        if (ft_strcmp(pkt->from_ip, last_ip) != 0) {
            printf(" ");
            print_host(pkt, do_dns);
            last_ip = pkt->from_ip;
        }

        printf("  %.3fms", pkt->rtt);
    }
    printf("\n");
    fflush(stdout);
}
