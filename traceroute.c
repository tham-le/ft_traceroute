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

static unsigned short checksum(void *data, int len) {
    unsigned short *buf = data;
    unsigned long   sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

static void send_probe(int sockfd, struct sockaddr_in *dest,
                       int ttl, int seq, uint16_t id) {
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt IP_TTL");
        return;
    }

    char packet[sizeof(struct icmphdr) + PROBE_DATA_SIZE];
    memset(packet, 0, sizeof(packet));

    struct icmphdr *icmp   = (struct icmphdr *)packet;
    icmp->type             = ICMP_ECHO;
    icmp->code             = 0;
    icmp->un.echo.id       = htons(id);
    icmp->un.echo.sequence = htons((uint16_t)seq);
    icmp->checksum         = 0;
    icmp->checksum         = checksum(packet, sizeof(packet));

    if (sendto(sockfd, packet, sizeof(packet), 0,
               (struct sockaddr *)dest, sizeof(*dest)) < 0) {
        perror("sendto");
    }
}

int traceroute(char *target, struct s_options *opts) {
    (void)opts;

    struct sockaddr_in dest;
    if (resolve_target(target, &dest) < 0)
        return 1;

    int sockfd = create_icmp_socket();
    if (sockfd < 0)
        return 1;

    uint16_t id = (uint16_t)(getpid() & 0xFFFF);
    send_probe(sockfd, &dest, 64, 0, id);

    close(sockfd);
    return 0;
}
