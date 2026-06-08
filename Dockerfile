FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    make \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN make re

ENTRYPOINT ["./ft_traceroute"]
