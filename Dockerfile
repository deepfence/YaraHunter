FROM golang:1.18.3-bullseye AS builder
MAINTAINER DeepFence

RUN apt-get update  \
    && apt-get -qq -y --no-install-recommends install build-essential automake libtool make gcc pkg-config libssl-dev \
    libjansson-dev libmagic-dev \
    && cd /root  \
    && wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.2.1.tar.gz \
    && tar -zxf v4.2.1.tar.gz \
    && cd yara-4.2.1 \
    && ./bootstrap.sh \
    && ./configure --prefix=/usr/local/yara --disable-dotnet --enable-magic --enable-cuckoo \
    && make \
    && make install \
    && cd /usr/local/ \
    && tar -czf yara.tar.gz yara

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0

WORKDIR /home/deepfence/src/IOCScanner
COPY . .
RUN make clean \
    && make all

FROM debian:bullseye
MAINTAINER DeepFence
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-internal-router \
    MGMT_CONSOLE_PORT=443 \
    LD_LIBRARY_PATH=/usr/local/yara/lib
RUN apt-get update && apt-get -qq -y --no-install-recommends install libjansson4 libssl1.1 libmagic1 bash curl python3-pip \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v0.18.0/nerdctl-0.18.0-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-0.18.0-linux-amd64.tar.gz \
    && rm nerdctl-0.18.0-linux-amd64.tar.gz
WORKDIR /home/deepfence/usr
COPY --from=builder /usr/local/yara.tar.gz /usr/local/yara.tar.gz
COPY --from=builder /home/deepfence/src/IOCScanner/IOCScanner .
COPY --from=builder /home/deepfence/src/IOCScanner/config.yaml .
COPY registry_image_save/* ./
RUN pip3 install -r requirements.txt \
    && cd /usr/local/ \
    && tar -xzf yara.tar.gz
WORKDIR /home/deepfence/mnt

ENTRYPOINT ["/home/deepfence/usr/IOCScanner", "-config-path", "/home/deepfence/usr", "-quiet"]
CMD ["-h"]