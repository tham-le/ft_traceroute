FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    make \
    bash-completion \
    iputils-ping \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

RUN echo '. /etc/bash_completion' >> /root/.bashrc

WORKDIR /app
COPY . .

RUN make re

ENTRYPOINT ["./ft_traceroute"]
