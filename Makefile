all: yarahunter

bootstrap:
	$(PWD)/bootstrap.sh

clean:
	-rm ./YaraHunter

vendor: go.mod
	go mod tidy -v
	go mod vendor

yarahunter: vendor $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/**/*.go
	CGO_LDFLAGS="-ljansson -lcrypto -lmagic" PKG_CONFIG_PATH=/usr/local/yara/lib/pkgconfig:$(PKG_CONFIG_PATH) go build -buildmode=pie -ldflags="-s -w -extldflags=-static" -buildvcs=false -v .

.PHONY: clean bootstrap

.PHONY: docker
docker:
	docker build -t deepfenceio/deepfence_malware_scanner:latest .
