export IMAGE_REPOSITORY?=quay.io/deepfenceio
export DF_IMG_TAG?=2.5.0

all: yarahunter

bootstrap:
	$(PWD)/bootstrap.sh

clean:
	-rm ./YaraHunter

vendor: go.mod
	go mod tidy -v
	go mod vendor

yarahunter: vendor $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/**/*.go
	CGO_LDFLAGS="-ljansson -lcrypto -lmagic" PKG_CONFIG_PATH=/usr/local/yara/lib/pkgconfig:$(PKG_CONFIG_PATH) go build -buildmode=pie -ldflags="-s -w -extldflags=-static -X 'main.version=$(DF_IMG_TAG)'" -buildvcs=false -v .

.PHONY: clean bootstrap

.PHONY: docker
docker:
	DOCKER_BUILDKIT=1 docker build -t $(IMAGE_REPOSITORY)/deepfence_malware_scanner_ce:$(DF_IMG_TAG) .
