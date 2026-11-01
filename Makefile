.PHONY: all build test clean deb deb-all

VERSION ?= 0.1.0-1
ARCH ?= $(shell dpkg --print-architecture 2>/dev/null || uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/' -e 's/armv7l/armhf/')
OUTPUT_DIR ?= dist

all: build

build:
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=$(shell echo $(VERSION) | sed -e 's/^v//' -e 's/-.*//')" -o dnsupdate ./cmd/dnsupdate

test:
	go test -v ./...

deb:
	ARCH=$(ARCH) VERSION=$(VERSION) OUTPUT_DIR=$(OUTPUT_DIR) ./scripts/build-deb.sh

deb-all:
	ARCH=amd64 VERSION=$(VERSION) OUTPUT_DIR=$(OUTPUT_DIR) ./scripts/build-deb.sh
	ARCH=arm64 VERSION=$(VERSION) OUTPUT_DIR=$(OUTPUT_DIR) ./scripts/build-deb.sh
	ARCH=armhf VERSION=$(VERSION) OUTPUT_DIR=$(OUTPUT_DIR) ./scripts/build-deb.sh

clean:
	rm -f dnsupdate
	rm -rf dist _build
