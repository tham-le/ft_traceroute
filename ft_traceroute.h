#ifndef FT_TRACEROUTE_H
#define FT_TRACEROUTE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include "libft.h"

#define DEFAULT_MAX_TTL     30
#define DEFAULT_FIRST_TTL    1
#define DEFAULT_NQUERIES     3
#define DEFAULT_SQUERIES    16
#define DEFAULT_UDP_PORT     33434
#define DEFAULT_PACKET_LEN   60
#define IP_HEADER_LEN        20
#define UDP_HEADER_LEN       8
#define MIN_PACKET_LEN       28
#define MAX_PACKET_SIZE    4096
#define MAX_NQUERIES         10
#define TIMEOUT_MS         5000

typedef struct s_options {
    int max_ttl;
    int first_ttl;
    int nqueries;
    int squeries;
    int port;
    int packet_len;
    int do_dns;
    int icmp_mode;
} t_options;

typedef struct {
    struct timeval     send_time;
    struct timeval     deadline;
    int                done;
    int                got_reply;
    double             rtt;
    struct sockaddr_in from_addr;
    char               from_ip[INET_ADDRSTRLEN];
} t_packet;

typedef struct {
    t_packet packets[MAX_NQUERIES];
    int      done;
    int      reached;
} t_hop;

/* args.c */
const char     *parse_arguments(int argc, char *argv[], t_options *opts);

/* net.c */
unsigned short  checksum(void *data, int len);
int             resolve_target(const char *target, struct sockaddr_in *dest);
int             create_udp_socket(void);
int             create_icmp_socket(void);
double          time_diff_ms(struct timeval *start, struct timeval *end);
void            timeval_add_ms(struct timeval *tv, long ms);

/* packet.c */
void    send_hop_packets(int send_sock, struct sockaddr_in *dest,
                         int ttl, uint16_t id, t_hop *hop,
                         const t_options *opts);
int     hop_is_complete(t_hop *hop, int nqueries);
void    expire_packets(t_hop *hops, int from_ttl, int to_ttl,
                       int nqueries, struct timeval *now);
int     next_deadline(t_hop *hops, int from_ttl, int to_ttl,
                      int nqueries, struct timeval *now, struct timeval *out);
void    receive_response(int recv_sock, t_hop *hops, uint16_t id,
                         int from_ttl, int to_ttl, const t_options *opts);

/* display.c */
void    print_header(const char *target, const char *dest_ip, const t_options *opts);
void    print_hop_line(int ttl, t_hop *hop, int nqueries, int do_dns);

/* traceroute.c */
int     traceroute(const char *target, t_options *opts);

#endif
