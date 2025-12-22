FROM golang:1.25-bookworm AS skopeo-builder

# Ubuntu (`libbtrfs-dev` requires Ubuntu 18.10 and above):
RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y libgpgme-dev libassuan-dev libbtrfs-dev libdevmapper-dev pkg-config

RUN git clone https://github.com/containers/skopeo $GOPATH/src/github.com/containers/skopeo
RUN cd $GOPATH/src/github.com/containers/skopeo && DISABLE_DOCS=1 make bin/skopeo
RUN cd $GOPATH/src/github.com/containers/skopeo && DISABLE_DOCS=1 make
RUN cd $GOPATH/src/github.com/containers/skopeo && cp ./bin/skopeo /usr/bin/skopeo

FROM golang:1.25-alpine3.23 AS builder

RUN apk add --no-cache \
	git \
	make  \
	build-base \
	pkgconfig \
	libpcap-dev \
	libcap-dev \
	openssl-dev \
	file \
	jansson-dev \
	jansson-static \
	bison \
	tini \
	su-exec \
	curl

RUN apk add --no-cache -t .build-deps py-setuptools \
	openssl-libs-static \
	jansson-dev \
	build-base \
	libc-dev \
	file-dev \
	automake \
	autoconf \
	libtool \
	libcrypto3 \
	flex \
	git \
	libmagic-static \
	linux-headers

RUN cd /root && wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.5.5.tar.gz \
	&& tar -zxf v4.5.5.tar.gz \
	&& cd yara-4.5.5 \
	&& ./bootstrap.sh \
	&& ./configure --prefix=/usr/local/yara --disable-dotnet --enable-magic --enable-cuckoo --disable-shared --enable-static\
	&& make \
	&& make install \
	&& cd /usr/local/ \
	&& tar -czf yara.tar.gz yara

WORKDIR /home/deepfence/src/YaraHunter
COPY . .
RUN make clean && make all

# Download rules and convert to yar format
RUN mkdir -p /home/deepfence/rules \
	&& curl -fsSL https://threat-intel.threatmapper.org/threat-intel/malware/malware_v2.5.8.tar.gz \
	-o /tmp/malware_rules.tar.gz \
	&& tar -xzf /tmp/malware_rules.tar.gz -C /home/deepfence/rules --strip-components=1 \
	&& rm /tmp/malware_rules.tar.gz

# Build and run the converter using the project's own code
RUN cd /home/deepfence/src/YaraHunter && \
	go run ./cmd/convert-rules/main.go /home/deepfence/rules/df-malware.json /home/deepfence/rules/malware.yar


FROM debian:bookworm
LABEL MAINTAINER="Deepfence"
LABEL deepfence.role=system

COPY --from=skopeo-builder /usr/bin/skopeo /usr/bin/skopeo

ENV LD_LIBRARY_PATH=/usr/local/yara/lib \
	DOCKERVERSION=29.1.3

RUN apt-get update && apt-get -qq -y --no-install-recommends install libjansson4 libssl3 libmagic1 libstdc++6 jq bash curl ca-certificates

ARG TARGETARCH

RUN <<EOF
set -eux
nerdctl_version=2.2.0
curl -fsSLOk https://github.com/containerd/nerdctl/releases/download/v${nerdctl_version}/nerdctl-${nerdctl_version}-linux-${TARGETARCH}.tar.gz
tar Cxzvvf /usr/local/bin nerdctl-${nerdctl_version}-linux-${TARGETARCH}.tar.gz
rm nerdctl-${nerdctl_version}-linux-${TARGETARCH}.tar.gz

if [ "$TARGETARCH" = "arm64" ]; then
    ARCHITECTURE="aarch64"
elif [ "$TARGETARCH" = "amd64" ]; then
    ARCHITECTURE="x86_64"
else
    echo "Unsupported architecture $TARGETARCH" && exit 1;
fi

curl -fsSLO https://download.docker.com/linux/static/stable/${ARCHITECTURE}/docker-${DOCKERVERSION}.tgz
tar xzvf docker-${DOCKERVERSION}.tgz --strip 1 -C /usr/local/bin docker/docker
rm docker-${DOCKERVERSION}.tgz

EOF

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y libgpgme-dev libdevmapper-dev

WORKDIR /home/deepfence/usr
COPY --from=builder /usr/local/yara.tar.gz /usr/local/yara.tar.gz
COPY --from=builder /home/deepfence/src/YaraHunter/YaraHunter .
COPY --from=builder /home/deepfence/src/YaraHunter/config.yaml .
COPY --from=builder /home/deepfence/rules/malware.yar .

RUN cd /usr/local/ \
	&& tar -xzf yara.tar.gz

WORKDIR /home/deepfence/output

ENTRYPOINT ["/home/deepfence/usr/YaraHunter", "-config-path", "/home/deepfence/usr/config.yaml", "-rules-path", "/home/deepfence/usr"]
CMD ["-h"]
