#define _GNU_SOURCE
#include "ft_traceroute.h"

static void help(void) {
    printf("Usage: ft_traceroute [-InI] [-f first_ttl] [-m max_ttl] [-p port]\n"
           "                     [-q tries] [-w wait] host\n"
           "\n"
           "Options:\n"
           "  -f, --first=N        Start from hop N (default 1)\n"
           "  -I, --icmp           Use ICMP ECHO instead of UDP\n"
           "  -m, --max-hop=N      Max hops (default 64)\n"
           "  -n                   No DNS resolution\n"
           "  -p, --port=N         Destination port (default 33434)\n"
           "  -q, --tries=N        Probes per hop (default 3)\n"
           "  -w, --wait=N         Seconds to wait for response (default 3)\n"
           "  -h, --help           Show this help\n");
    exit(0);
}

typedef struct {
    const char *shortf;
    const char *longf;
    size_t      offset;
    int         min;
    int         max;
} t_flag;

static const t_flag g_flags[] = {
    { "-f", "--first",       offsetof(t_options, first_ttl),  1,  255          },
    { "-m", "--max-hop",     offsetof(t_options, max_ttl),    1,  255          },
    { "-N", "--sim-queries", offsetof(t_options, squeries),   1,  128          },
    { "-p", "--port",        offsetof(t_options, port),       0,  65535        },
    { "-q", "--tries",       offsetof(t_options, nqueries),   1,  MAX_NQUERIES },
    { "-l", NULL,            offsetof(t_options, packet_len), MIN_PACKET_LEN, MAX_PACKET_SIZE },
};

static int parse_int(const char *s, int min, int max, const char *flag) {
    const char *p = s;
    if (*p == '-')
        p++;
    if (!*p) {
        fprintf(stderr, "ft_traceroute: %s: invalid value '%s'\n", flag, s);
        exit(1);
    }
    while (*p) {
        if (*p < '0' || *p > '9') {
            fprintf(stderr, "ft_traceroute: %s: invalid value '%s'\n", flag, s);
            exit(1);
        }
        p++;
    }
    if (p - s > 11) {
        fprintf(stderr, "ft_traceroute: %s: invalid value '%s' (expected %d-%d)\n",
                flag, s, min, max);
        exit(1);
    }
    int val = ft_atoi(s);
    if (val < min || val > max) {
        fprintf(stderr, "ft_traceroute: %s: invalid value '%s' (expected %d-%d)\n",
                flag, s, min, max);
        exit(1);
    }
    return val;
}

static int match(const char *arg, const char *shortf, const char *longf,
                 int argc, char **argv, int *i, const char **val) {
    if (ft_strcmp(arg, shortf) == 0) {
        if (++(*i) >= argc) {
            fprintf(stderr, "ft_traceroute: %s requires an argument\n", shortf);
            exit(1);
        }
        *val = argv[*i];
        return 1;
    }
    if (longf) {
        size_t len = ft_strlen(longf);
        if (ft_strncmp(arg, longf, len) == 0 && arg[len] == '=') {
            *val = arg + len + 1;
            return 1;
        }
    }
    return 0;
}

static int try_flags(const char *arg, int argc, char **argv, int *i, t_options *opts) {
    const char *val;
    int nflags = (int)(sizeof(g_flags) / sizeof(g_flags[0]));
    for (int f = 0; f < nflags; f++) {
        if (match(arg, g_flags[f].shortf, g_flags[f].longf, argc, argv, i, &val)) {
            int *field = (int *)((char *)opts + g_flags[f].offset);
            *field = parse_int(val, g_flags[f].min, g_flags[f].max, g_flags[f].shortf);
            return 1;
        }
    }
    return 0;
}

static void handle_positional(const char *arg, const char **target, int *npos,
                               t_options *opts) {
    if (*npos == 0) {
        *target = arg;
        (*npos)++;
    } else if (*npos == 1) {
        opts->packet_len = parse_int(arg, MIN_PACKET_LEN, MAX_PACKET_SIZE, "packetlen");
        (*npos)++;
    } else {
        fprintf(stderr, "ft_traceroute: extra operand '%s'\n", arg);
        fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
        exit(1);
    }
}

static void validate_opts(const char *target, const t_options *opts) {
    if (!target) {
        fprintf(stderr, "ft_traceroute: missing host operand\n");
        fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
        exit(1);
    }
    if (opts->first_ttl > opts->max_ttl) {
        fprintf(stderr, "ft_traceroute: first hop out of range\n");
        exit(1);
    }
}

const char *parse_arguments(int argc, char *argv[], t_options *opts) {
    const char *target = NULL;
    int         npos   = 0;
    int         i      = 1;

    for (; i < argc; i++) {
        if (ft_strcmp(argv[i], "--help") == 0 || ft_strcmp(argv[i], "-h") == 0
            || ft_strcmp(argv[i], "-?") == 0 || ft_strcmp(argv[i], "--usage") == 0)
            help();
        else if (ft_strcmp(argv[i], "-n") == 0)
            opts->do_dns = 0;
        else if (ft_strcmp(argv[i], "-w") == 0 || ft_strncmp(argv[i], "--wait=", 7) == 0) {
            const char *val = (argv[i][1] == 'w' && argv[i][2] == '\0')
                ? (++i < argc ? argv[i] : NULL) : argv[i] + 7;
            if (!val) { fprintf(stderr, "ft_traceroute: -w requires an argument\n"); exit(1); }
            opts->timeout_ms = parse_int(val, 1, 3600, "-w") * 1000;
        }
        else if (ft_strcmp(argv[i], "-I") == 0 || ft_strcmp(argv[i], "--icmp") == 0)
            opts->icmp_mode = 1;
        else if (!try_flags(argv[i], argc, argv, &i, opts)) {
            if (argv[i][0] == '-') {
                fprintf(stderr, "ft_traceroute: invalid option '%s'\n", argv[i]);
                fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
                exit(1);
            }
            handle_positional(argv[i], &target, &npos, opts);
        }
    }

    if (opts->port == -1)
        opts->port = opts->icmp_mode ? 1 : DEFAULT_UDP_PORT;

    validate_opts(target, opts);
    return target;
}
