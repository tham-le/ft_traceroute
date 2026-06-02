#include "ft_traceroute.h"

int main(int argc, char *argv[]) {
    struct s_options opts;
    ft_memset(&opts, 0, sizeof(opts));
    opts.max_ttl     = DEFAULT_MAX_TTL;
    opts.nqueries    = DEFAULT_NQUERIES;
    opts.timeout_ms  = DEFAULT_TIMEOUT_MS;
    opts.window_size = DEFAULT_WINDOW_SIZE;
    opts.do_dns      = 1;
    opts.first_ttl   = DEFAULT_FIRST_TTL;
    opts.tos         = DEFAULT_TOS;
    opts.port        = DEFAULT_PORT;
    opts.packet_len  = DEFAULT_PACKET_LEN;

    char *target = parse_arguments(argc, argv, &opts);
    return traceroute(target, &opts);
}
