#include "ft_traceroute.h"

static int create_icmp_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("ft_traceroute: socket");
        return -1;
    }
    return sockfd;
}

int traceroute(char *target, struct s_options *opts) {
    (void)target;
    (void)opts;

    int sockfd = create_icmp_socket();
    if (sockfd < 0)
        return 1;
    close(sockfd);
    return 0;
}
