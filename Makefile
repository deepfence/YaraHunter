

$(if $(filter 4.%,$(MAKE_VERSION)),,\
	$(error GNU make 4.0 or above is required.))

SED := $(firstword $(shell which gsed sed))
TAR := $(firstword $(shell which gtar tar))

GOROOT ?= $(firstword \
	$(patsubst %,/usr/lib/go-%,\
		$(shell echo $(patsubst /usr/lib/go-%,%,$(wildcard /usr/lib/go-*)) \
			     | tr ' ' '\n' \
			     | sort -rV))\
	$(shell go env GOROOT))
VERSION = '1.0'
VERSIONSUFFIX :=
NAMESPACE := $(shell awk '/^module / {print $$2}' go.mod)
ARCHS ?= $(3rdparty_ARCHS)

all:
include 3rdparty.mk
-include local.mk


$(foreach arch,$(ARCHS),\
	$(if $(findstring $(3rdparty_NATIVE_ARCH),$(arch)),,\
		$(eval _build/$(arch)/%: private export CC=$(arch)-gcc))\
	$(eval _build/$(arch)/%: private export PKG_CONFIG_PATH=$(PWD)/_3rdparty/tgt/$(arch)/lib/pkgconfig)\
	$(eval _build/$(arch)/%: private export GOOS=\
		$(or $(if $(findstring linux,$(arch)),linux),\
		     $(if $(findstring mingw,$(arch)),windows),\
		     $(if $(findstring darwin,$(arch)),darwin),\
		     $(if $(findstring freebsd,$(arch)),freebsd),\
		     $(error Could not derive GOOS from $(arch))))\
	$(eval _build/$(arch)/%: private export GOARCH=\
		$(or $(if $(findstring x86_64,$(arch)),amd64),\
		     $(if $(or $(findstring i386,$(arch)),$(findstring i686,$(arch))),386),\
		     $(error Could not derive GOARCH from $(arch)))))


$(EXE): private extldflags = $(if $(findstring darwin,$(GOOS)),,-static)

$(PWD)/agent-plugins-grpc/proto/*.proto:
	$(PWD)/bootstrap.sh

$(PWD)/agent-plugins-grpc/proto/*.go: $(PWD)/agent-plugins-grpc/proto/*.proto
	(cd agent-plugins-grpc && make go)

clean:
	-(cd agent-plugins-grpc && make clean)
	-rm ./IOCScanner

all: IOCScanner
IOCScanner: 
	$(info [+] Building IOCScanner...)
	$(info [+] GOROOT=$(GOROOT) GOOS=$(GOOS) GOARCH=$(GOARCH) CC=$(CC))
	$(info [+] PKG_CONFIG_PATH=$(PKG_CONFIG_PATH))
	mkdir -p $(@D)
	$(GOROOT)/bin/go build \
		-ldflags '$(VERSIONDEF) -w -s -linkmode=external -extldflags "$(extldflags)"' \
		-tags yara_static \
	    -buildvcs=false -v .

.PHONY: clean
