#include "ft_traceroute.h"

static void help(void) {
    printf("Usage: ft_traceroute [OPTION...] HOST\n"
           "Print the route packets trace to network host.\n\n"
           " Options:\n\n"
           "  -?, --help    give this help list\n");
    exit(0);
}

char *parse_arguments(int argc, char *argv[], struct s_options *opts) {
    (void)opts;
    char *target = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-?") == 0) {
            help();
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "ft_traceroute: invalid option -- '%s'\n", argv[i] + 1);
            fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
            exit(1);
        } else {
            if (target == NULL)
                target = argv[i];
        }
    }

    if (target == NULL) {
        fprintf(stderr, "ft_traceroute: missing host operand\n");
        fprintf(stderr, "Try 'ft_traceroute --help' for more information.\n");
        exit(1);
    }

    return target;
}
