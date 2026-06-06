#define _GNU_SOURCE
#include "ft_traceroute.h"

int main(int argc, char *argv[]) {
    t_options opts;
    ft_memset(&opts, 0, sizeof(opts));
    opts.max_ttl    = DEFAULT_MAX_TTL;
    opts.first_ttl  = DEFAULT_FIRST_TTL;
    opts.nqueries   = DEFAULT_NQUERIES;
    opts.squeries   = DEFAULT_SQUERIES;
    opts.packet_len = DEFAULT_PACKET_LEN;
    opts.do_dns     = 1;
    opts.port       = -1;

    const char *target = parse_arguments(argc, argv, &opts);
    return traceroute(target, &opts);
}
