#include "ft_traceroute.h"

static int create_icmp_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("ft_traceroute: socket");
        return -1;
    }
    return sockfd;
}

static int resolve_target(const char *target, struct sockaddr_in *dest) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int ret = getaddrinfo(target, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "ft_traceroute: %s: %s\n", target, gai_strerror(ret));
        return -1;
    }
    *dest = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return 0;
}

int traceroute(char *target, struct s_options *opts) {
    (void)opts;

    struct sockaddr_in dest;
    if (resolve_target(target, &dest) < 0)
        return 1;

    int sockfd = create_icmp_socket();
    if (sockfd < 0)
        return 1;
    close(sockfd);
    return 0;
}
