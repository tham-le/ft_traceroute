// Project Kyber: display.c
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

void print_header(const char *target, const char *dest_ip,
                  const t_options *opts) {
    printf("traceroute to %s (%s), %d hops max, %d byte packets\n",
           target, dest_ip, opts->max_ttl, opts->packet_len);
}

static void print_host(t_packet *pkt, int do_dns) {
    if (do_dns) {
        char host[NI_MAXHOST];
        if (getnameinfo((struct sockaddr *)&pkt->from_addr,
                        sizeof(pkt->from_addr),
                        host, sizeof(host), NULL, 0, 0) == 0) {
            printf("%s (%s)", host, pkt->from_ip);
        } else {
            printf("%s (%s)", pkt->from_ip, pkt->from_ip);
        }
    } else {
        printf("%s", pkt->from_ip);
    }
}

void print_hop_line(int ttl, t_hop *hop, int nqueries, int do_dns) {
    const char *last_ip = "";

    printf("%2d ", ttl);
    for (int i = 0; i < nqueries; i++) {
        t_packet *pkt = &hop->packets[i];

        if (!pkt->got_reply) {
            printf(" *");
            continue;
        }

        if (ft_strcmp(pkt->from_ip, last_ip) != 0) {
            printf(" ");
            print_host(pkt, do_dns);
            last_ip = pkt->from_ip;
        }

        printf("  %.3f ms", pkt->rtt);
    }
    printf("\n");
    fflush(stdout);
}
