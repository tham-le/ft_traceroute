// Project Kyber: main.c
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

int main(int argc, char *argv[]) {
    t_options opts;
    ft_memset(&opts, 0, sizeof(opts));
    opts.max_ttl    = DEFAULT_MAX_TTL;
    opts.first_ttl  = DEFAULT_FIRST_TTL;
    opts.nqueries   = DEFAULT_NQUERIES;
    opts.squeries   = DEFAULT_SQUERIES;
    opts.packet_len = DEFAULT_PACKET_LEN;
    opts.do_dns     = 1;
    opts.port       = -1;

    const char *target = parse_arguments(argc, argv, &opts);
    return traceroute(target, &opts);
}
