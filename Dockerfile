FROM golang:1.18.3-bullseye AS builder
MAINTAINER DeepFence

RUN apt-get update  \
    && apt-get -qq -y --no-install-recommends install  musl-dev git protobuf-compiler \
    autoconf \
    automake \
    libtool \
    libtool \
    pkg-config \
    ca-certificates \
    wget \
    patch \
    sed \
    git-core \
    moreutils \
    zip \
    git \
    yara 



RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.27.1 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2.0


WORKDIR /home/deepfence/src/IOCScanner
COPY . .
RUN make clean
RUN make 3rdparty-all 

FROM debian:bullseye
MAINTAINER DeepFence
LABEL deepfence.role=system

ENV MGMT_CONSOLE_URL=deepfence-internal-router \
    MGMT_CONSOLE_PORT=443
RUN apt-get update && apt-get -qq -y --no-install-recommends install libgcc-s1 docker skopeo python3 python3-pip curl \
    gcc-multilib \
    gcc-mingw-w64 \
    autoconf \
    automake \
    libtool \
    pkg-config \
    ca-certificates \
    wget \
    patch \
    sed \
    git-core \
    moreutils \
    zip \
    git \
    yara \
    && curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v0.18.0/nerdctl-0.18.0-linux-amd64.tar.gz \
    && tar Cxzvvf /usr/local/bin nerdctl-0.18.0-linux-amd64.tar.gz \
    && rm nerdctl-0.18.0-linux-amd64.tar.gz \
    && apt-get remove curl 
WORKDIR /home/deepfence/usr
COPY --from=builder /home/deepfence/src/IOCScanner/IOCScanner .
COPY --from=builder /home/deepfence/src/IOCScanner/config.yaml .
COPY registry_image_save/* ./
RUN pip3 install -r requirements.txt
WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/IOCScanner", "-config-path", "/home/deepfence/usr", "-quiet"]
CMD ["-h"]

