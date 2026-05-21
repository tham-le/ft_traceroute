#include "ft_traceroute.h"

static void help(void) {
    printf("Usage: ft_traceroute [OPTION...] HOST\n"
           "Print the route packets trace to network host.\n\n"
           " Options:\n"
           "  -f <first_ttl> Start from this hop (default: 1)\n"
           "  -m <max_ttl>  Set the max number of hops (default: 30)\n"
           "  -q <nqueries> Probes per hop (default: 3, max: %d)\n"
           "  -w <timeout>  Seconds to wait per probe (default: 5)\n"
           "  -N <squeries> Simultaneous probes in flight (default: 16)\n"
           "  -n            Do not resolve IP addresses to hostnames\n"
           "  -t <tos>      Set IP TOS byte (default: 0)\n"
           "  -s <src_addr> Use this source address\n"
           "  -?, --help    Give this help list\n",
           MAX_NQUERIES);
    exit(0);
}

static int parse_int(const char *s, int min, int max, const char *flag) {
    char *end;
    long  val = strtol(s, &end, 10);
    if (*end != '\0' || val < min || val > max) {
        fprintf(stderr, "ft_traceroute: %s: invalid value '%s' (expected %d-%d)\n",
                flag, s, min, max);
        exit(1);
    }
    return (int)val;
}

static const char *need_arg(int argc, char *argv[], int *i, const char *flag) {
    (*i)++;
    if (*i >= argc) {
        fprintf(stderr, "ft_traceroute: %s requires an argument\n", flag);
        exit(1);
    }
    return argv[*i];
}

char *parse_arguments(int argc, char *argv[], struct s_options *opts) {
    char *target = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-?") == 0) {
            help();
        } else if (strcmp(argv[i], "-f") == 0) {
            opts->first_ttl = parse_int(need_arg(argc, argv, &i, "-f"), 1, 255, "-f");
        } else if (strcmp(argv[i], "-m") == 0) {
            opts->max_ttl = parse_int(need_arg(argc, argv, &i, "-m"), 1, 255, "-m");
        } else if (strcmp(argv[i], "-q") == 0) {
            opts->nqueries = parse_int(need_arg(argc, argv, &i, "-q"),
                                       1, MAX_NQUERIES, "-q");
        } else if (strcmp(argv[i], "-w") == 0) {
            opts->timeout_sec = parse_int(need_arg(argc, argv, &i, "-w"),
                                          1, 60, "-w");
        } else if (strcmp(argv[i], "-N") == 0) {
            opts->window_size = parse_int(need_arg(argc, argv, &i, "-N"),
                                          1, 128, "-N");
        } else if (strcmp(argv[i], "-n") == 0) {
            opts->do_dns = 0;
        } else if (strcmp(argv[i], "-t") == 0) {
            opts->tos = parse_int(need_arg(argc, argv, &i, "-t"), 0, 255, "-t");
        } else if (strcmp(argv[i], "-s") == 0) {
            opts->source = (char *)need_arg(argc, argv, &i, "-s");
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "ft_traceroute: invalid option '%s'\n", argv[i]);
            fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
            exit(1);
        } else {
            if (!target)
                target = argv[i];
        }
    }

    if (!target) {
        fprintf(stderr, "ft_traceroute: missing host operand\n");
        fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
        exit(1);
    }
    return target;
}
