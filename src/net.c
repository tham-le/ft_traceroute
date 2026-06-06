// Project Kyber: net.c
// Copyright © 2022-2026 Kyber SAS
// SPDX-License-Identifier: LicenseRef-Kyber-Commercial OR AGPL-3.0-or-later
//
// This file is both under dual license: AGPLv3 and a Commercial one.
//
// ----
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#define _GNU_SOURCE
#include "ft_traceroute.h"

unsigned short checksum(void *data, int len) {
    unsigned char *buf = (unsigned char *)data;
    unsigned long  sum = 0;
    unsigned short word;

    while (len > 1) {
        ft_memcpy(&word, buf, sizeof(word));
        sum += word;
        buf += 2;
        len -= 2;
    }
    if (len == 1) {
        word = 0;
        ft_memcpy(&word, buf, 1);
        sum += word;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int resolve_target(const char *target, struct sockaddr_in *dest) {
    struct addrinfo hints, *res;
    ft_memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = 0;
    int ret = getaddrinfo(target, NULL, &hints, &res);
    if (ret != 0) {
        fprintf(stderr, "ft_traceroute: %s: %s\n", target, gai_strerror(ret));
        return -1;
    }
    *dest = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return 0;
}

int create_udp_socket(void) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0)
        fprintf(stderr, "ft_traceroute: udp socket: %s\n", strerror(errno));
    return sockfd;
}

int create_icmp_socket(void) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        if (errno == EPERM || errno == EACCES)
            fprintf(stderr, "ft_traceroute: raw socket requires root privileges\n");
        else
            fprintf(stderr, "ft_traceroute: icmp socket: %s\n", strerror(errno));
        return -1;
    }
    return sockfd;
}

double time_diff_ms(struct timeval *start, struct timeval *end) {
    return (double)(end->tv_sec  - start->tv_sec)  * 1000.0
         + (double)(end->tv_usec - start->tv_usec) / 1000.0;
}

void timeval_add_ms(struct timeval *tv, long ms) {
    tv->tv_usec += ms * 1000L;
    tv->tv_sec  += tv->tv_usec / 1000000;
    tv->tv_usec %= 1000000;
}
