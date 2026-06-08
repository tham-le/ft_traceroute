#!/bin/sh
docker run --rm --cap-add=NET_RAW ft_traceroute "$@"
