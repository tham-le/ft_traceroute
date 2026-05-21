#include "ft_traceroute.h"

static void help(void) {
    printf("Usage: ft_traceroute [OPTION...] HOST\n"
           "Print the route packets trace to network host.\n\n"
           " Options:\n"
           "  -m <max_ttl>  Set the max number of hops (default: 30)\n"
           "  -?, --help    Give this help list\n");
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
        } else if (strcmp(argv[i], "-m") == 0) {
            opts->max_ttl = parse_int(need_arg(argc, argv, &i, "-m"), 1, 255, "-m");
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
