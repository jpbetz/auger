NAME?=auger
PKG?=github.com/jpbetz/$(NAME)
GO_VERSION?=1.8.3
GOOS?=linux
GOARCH?=amd64
TEMP_DIR:=$(shell mktemp -d)

# Local development glide install
vendor:
	glide install --strip-vendor

# Local development build
build: vendor
	@mkdir -p build
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o build/$(NAME)
	@echo build/$(NAME) built!

# Local development test
# `go test` automatically manages the build, so no need to depend on the build target here in make
test: vendor
	@echo Vetting
	go vet $$(go list ./... | grep -v /vendor/)
	@echo Testing
	go test $$(go list ./... | grep -v /vendor/)

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
	curl https://glide.sh/get | sh
	glide install --strip-vendor
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build

clean:
	rm -rf vendor
	rm -rf build

.PHONY: build test release release-docker-build clean
