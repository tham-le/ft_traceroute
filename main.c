#include "ft_traceroute.h"

int main(int argc, char *argv[]) {
    struct s_options opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_ttl     = DEFAULT_MAX_TTL;
    opts.nqueries    = DEFAULT_NQUERIES;
    opts.timeout_sec = DEFAULT_TIMEOUT_SEC;

    char *target = parse_arguments(argc, argv, &opts);
    return traceroute(target, &opts);
}
