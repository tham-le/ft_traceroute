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

#define DEFAULT_MAX_TTL      30
#define DEFAULT_FIRST_TTL     1
#define DEFAULT_NQUERIES      3
#define DEFAULT_TIMEOUT_SEC   5
#define PROBE_DATA_SIZE      40
#define MAX_PACKET_SIZE    4096
#define MAX_NQUERIES         10
#define DEFAULT_WINDOW_SIZE  16
#define DEFAULT_TOS           0
#define NEAR_MS             400

struct s_options {
    int max_ttl;
    int nqueries;
    int timeout_sec;
    int window_size;
    int do_dns;
    int first_ttl;
    int tos;
};

int   traceroute(char *target, struct s_options *opts);
char *parse_arguments(int argc, char *argv[], struct s_options *opts);

#endif
