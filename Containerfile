FROM docker.io/library/debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential nginx nginx-dev liblzma-dev libmaxminddb-dev libssl-dev libpcre2-dev zlib1g-dev \
      curl ca-certificates python3 openssl procps iproute2 tcpdump tshark xz-utils mmdb-bin \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
