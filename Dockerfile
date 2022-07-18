FROM python:3.10-slim-buster AS python

ARG WIREGUARD_RELEASE

ENV FLASK_APP="dashboard"

WORKDIR /app

RUN apt update && apt install -y --no-install-recommends \
    bc \
    build-essential \
    curl \
    dkms \
    git \
    gnupg \ 
    ifupdown \
    iproute2 \
    iptables \
    iputils-ping \
    jq \
    libc6 \
    libelf-dev \
    net-tools \
    openresolv \
    perl \
    pkg-config \
    qrencode

# The following is taken from https://github.com/linuxserver/docker-baseimage-ubuntu/blob/bionic/Dockerfile
RUN \
    WIREGUARD_RELEASE=$(curl -sX GET "https://api.github.com/repos/WireGuard/wireguard-tools/tags" \
    | jq -r .[0].name); \
    git clone https://git.zx2c4.com/wireguard-linux-compat && \
    git clone https://git.zx2c4.com/wireguard-tools && \
    cd wireguard-tools && \
    git checkout "${WIREGUARD_RELEASE}" && \
    make -C src -j$(nproc) && \
    make -C src install && \
    echo "**** install CoreDNS ****" && \
    COREDNS_VERSION=$(curl -sX GET "https://api.github.com/repos/coredns/coredns/releases/latest" \
    | awk '/tag_name/{print $4;exit}' FS='[""]' | awk '{print substr($1,2); }') && \
    curl -o /tmp/coredns.tar.gz -L \
    "https://github.com/coredns/coredns/releases/download/v${COREDNS_VERSION}/coredns_${COREDNS_VERSION}_linux_amd64.tgz" && \
    tar xf /tmp/coredns.tar.gz -C /app && \
    echo "**** clean up ****" && \
    rm -rf /tmp/* /var/lib/apt/lists/* /var/tmp/*


COPY src/requirements.txt ./

COPY src/ ./
RUN pip install -r requirements.txt 


EXPOSE 51820/udp
EXPOSE 80
VOLUME /config/
VOLUME /log/

CMD [ "flask", "run", "--host=0.0.0.0", "--port=80" ]
