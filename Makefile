all: yarahunter

clean:
	-rm ./YaraHunter

yarahunter: $(PWD)/**/*.go $(PWD)/agent-plugins-grpc/**/*.go
	$(PWD)/bootstrap.sh
	go mod tidy -v
	go mod vendor
	env PKG_CONFIG_PATH=/usr/local/yara/lib/pkgconfig:$(PKG_CONFIG_PATH) go build -buildvcs=false -v .

.PHONY: clean
