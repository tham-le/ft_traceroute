#include "ft_traceroute.h"

static void help(void) {
    printf("Usage: ft_traceroute [OPTION...] HOST [PACKETLEN]\n"
           "Print the route packets trace to network host.\n\n"
           " Options:\n"
           "  -f <first_ttl> Start from this hop (default: 1)\n"
           "  -m <max_ttl>  Set the max number of hops (default: 30)\n"
           "  -q <nqueries> Probes per hop (default: 3, max: %d)\n"
           "  -w <timeout>  Seconds to wait per probe, may be fractional (default: 5)\n"
           "  -N <squeries> Simultaneous probes in flight (default: 16)\n"
           "  -n            Do not resolve IP addresses to hostnames\n"
           "  -t <tos>      Set IP TOS byte (default: 0)\n"
           "  -p <port>     Base ICMP sequence number (default: 0)\n"
           "  -l <len>      Total probe packet length in bytes (default: 48)\n"
           "  -s <src_addr> Use this source address\n"
           "  -i <iface>    Bind to this network interface\n"
           "  -?, --help    Give this help list\n",
           MAX_NQUERIES);
    exit(0);
}

static int parse_int(const char *s, int min, int max, const char *flag) {
    long val  = 0;
    int  i    = 0;
    int  sign = 1;
    int  ok   = 1;

    if (s[i] == '-') {
        sign = -1;
        i++;
    }
    if (s[i] == '\0')
        ok = 0;
    while (ok && s[i]) {
        if (s[i] < '0' || s[i] > '9' || val > 2147483647L) {
            ok = 0;
            break;
        }
        val = val * 10 + (s[i] - '0');
        i++;
    }
    val *= sign;
    if (!ok || val < min || val > max) {
        fprintf(stderr, "ft_traceroute: %s: invalid value '%s' (expected %d-%d)\n",
                flag, s, min, max);
        exit(1);
    }
    return (int)val;
}

/* Parse a possibly-fractional second value (e.g. "1", "0.5", "2.345") into
 * milliseconds.  Accepts up to millisecond precision; range 1ms .. 60s. */
static int parse_timeout_ms(const char *s, const char *flag) {
    long sec    = 0;
    long frac   = 0;
    long scale  = 100;
    int  i      = 0;
    int  ok     = 1;
    int  digits = 0;

    while (s[i] >= '0' && s[i] <= '9') {
        sec = sec * 10 + (s[i] - '0');
        if (sec > 60) {
            ok = 0;
            break;
        }
        i++;
        digits++;
    }
    if (ok && s[i] == '.') {
        i++;
        while (s[i] >= '0' && s[i] <= '9') {
            if (scale >= 1) {
                frac += (s[i] - '0') * scale;
                scale /= 10;
            }
            i++;
            digits++;
        }
    }
    long ms = sec * 1000 + frac;
    if (!ok || s[i] != '\0' || digits == 0 || ms < 1 || ms > 60000) {
        fprintf(stderr, "ft_traceroute: %s: invalid value '%s' (expected 0.001-60)\n",
                flag, s);
        exit(1);
    }
    return (int)ms;
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
    int   npos   = 0;

    for (int i = 1; i < argc; i++) {
        if (ft_strcmp(argv[i], "--help") == 0 || ft_strcmp(argv[i], "-?") == 0) {
            help();
        } else if (ft_strcmp(argv[i], "-f") == 0) {
            opts->first_ttl = parse_int(need_arg(argc, argv, &i, "-f"), 1, 255, "-f");
        } else if (ft_strcmp(argv[i], "-m") == 0) {
            opts->max_ttl = parse_int(need_arg(argc, argv, &i, "-m"), 1, 255, "-m");
        } else if (ft_strcmp(argv[i], "-q") == 0) {
            opts->nqueries = parse_int(need_arg(argc, argv, &i, "-q"),
                                       1, MAX_NQUERIES, "-q");
        } else if (ft_strcmp(argv[i], "-w") == 0) {
            opts->timeout_ms = parse_timeout_ms(need_arg(argc, argv, &i, "-w"), "-w");
        } else if (ft_strcmp(argv[i], "-N") == 0) {
            opts->window_size = parse_int(need_arg(argc, argv, &i, "-N"),
                                          1, 128, "-N");
        } else if (ft_strcmp(argv[i], "-n") == 0) {
            opts->do_dns = 0;
        } else if (ft_strcmp(argv[i], "-t") == 0) {
            opts->tos = parse_int(need_arg(argc, argv, &i, "-t"), 0, 255, "-t");
        } else if (ft_strcmp(argv[i], "-s") == 0) {
            opts->source = (char *)need_arg(argc, argv, &i, "-s");
        } else if (ft_strcmp(argv[i], "-i") == 0) {
            opts->iface = (char *)need_arg(argc, argv, &i, "-i");
        } else if (ft_strcmp(argv[i], "-p") == 0) {
            opts->port = parse_int(need_arg(argc, argv, &i, "-p"), 0, 65535, "-p");
        } else if (ft_strcmp(argv[i], "-l") == 0) {
            opts->packet_len = parse_int(need_arg(argc, argv, &i, "-l"),
                                         MIN_PACKET_LEN, MAX_PACKET_SIZE, "-l");
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "ft_traceroute: invalid option '%s'\n", argv[i]);
            fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
            exit(1);
        } else if (npos == 0) {
            target = argv[i];
            npos++;
        } else if (npos == 1) {
            /* Optional second operand sets the packet length, as in traceroute(8). */
            opts->packet_len = parse_int(argv[i], MIN_PACKET_LEN,
                                         MAX_PACKET_SIZE, "packetlen");
            npos++;
        } else {
            fprintf(stderr, "ft_traceroute: extra operand '%s'\n", argv[i]);
            fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
            exit(1);
        }
    }

    if (!target) {
        fprintf(stderr, "ft_traceroute: missing host operand\n");
        fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
        exit(1);
    }
    if (opts->first_ttl > opts->max_ttl) {
        fprintf(stderr, "ft_traceroute: first hop out of range\n");
        exit(1);
    }
    return target;
}
