NAME ?= auger
PKG ?= github.com/jpbetz/$(NAME)
GO_VERSION ?= 1.16.5
GOOS ?= linux
GOARCH ?= amd64
TEMP_DIR := $(shell mktemp -d)

# Local development build
build:
	@mkdir -p build
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o build/$(NAME)
	@echo build/$(NAME) built!

# Local development test
# `go test` automatically manages the build, so no need to depend on the build target here in make
test:
	@echo Vetting
	go vet ./...
	@echo Testing
	go test ./...

# Dockerized build
release:
	@cp -r $(CURDIR) $(TEMP_DIR)
	@echo Building release in temp directory $(TEMP_DIR)
	docker run \
		-v $(TEMP_DIR)/$(NAME):/go/src/$(PKG) \
		-w /go/src/$(PKG) \
		golang:$(GO_VERSION) \
		/bin/bash -c "make -f /go/src/$(PKG)/Makefile release-docker-build GOARCH=$(GOARCH) GOOS=$(GOOS)"
	@mkdir -p build
	@cp $(TEMP_DIR)/$(NAME)/$(NAME) build/$(NAME)
	@echo build/$(NAME) built!

# Build used inside docker by 'release'
release-docker-build:
	export GOPATH=/go
	GOOS=$(GOOS) GOARCH=$(GOARCH) GO111MODULE=on go build

clean:
	rm -rf build

.PHONY: build test release release-docker-build clean
