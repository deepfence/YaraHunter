all: yarahunter

bootstrap:
	$(PWD)/bootstrap.sh

clean:
	-rm ./YaraHunter

yarahunter: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/**/*.go
	go mod tidy -v
	go mod vendor
	env PKG_CONFIG_PATH=/usr/local/yara/lib/pkgconfig:$(PKG_CONFIG_PATH) go build -ldflags="-extldflags=-static" -buildvcs=false -v .

.PHONY: clean bootstrap
