FROM golang:1.20-bullseye AS builder

RUN apt-get update  \
    && apt-get -qq -y --no-install-recommends install build-essential automake libtool make gcc pkg-config libssl-dev git protoc-gen-go \
    libjansson-dev libmagic-dev \
    && cd /root  \
    && wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz \
    && tar -zxf v4.3.2.tar.gz \
    && cd yara-4.3.2 \
    && ./bootstrap.sh \
    && ./configure --prefix=/usr/local/yara --disable-dotnet --enable-magic --enable-cuckoo \
    && make \
    && make install \
    && cd /usr/local/ \
    && tar -czf yara.tar.gz yara

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.30.0 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0

WORKDIR /home/deepfence/src/YaraHunter
COPY . .
RUN make clean \
    && make all \
    && cd /home/deepfence \
    && git clone https://github.com/deepfence/yara-rules


FROM debian:bullseye
LABEL MAINTAINER="Deepfence"
LABEL deepfence.role=system

ENV LD_LIBRARY_PATH=/usr/local/yara/lib \
    DOCKERVERSION=23.0.3
RUN apt-get update && apt-get -qq -y --no-install-recommends install libjansson4 libssl1.1 libmagic1 libstdc++6 jq bash skopeo curl \
    && nerdctl_version=1.4.0 \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v${nerdctl_version}/nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && rm nerdctl-${nerdctl_version}-linux-amd64.tar.gz \
    && curl -fsSLO https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKERVERSION}.tgz \
    && tar xzvf docker-${DOCKERVERSION}.tgz --strip 1 -C /usr/local/bin docker/docker \
    && rm docker-${DOCKERVERSION}.tgz
WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/yara-rules .
COPY --from=builder /usr/local/yara.tar.gz /usr/local/yara.tar.gz
COPY --from=builder /home/deepfence/src/YaraHunter/YaraHunter .
COPY --from=builder /home/deepfence/src/YaraHunter/config.yaml .

RUN cd /usr/local/ \
    && tar -xzf yara.tar.gz
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/YaraHunter", "-config-path", "/home/deepfence/usr", "-rules-path", "/home/deepfence/usr"]
CMD ["-h"]
