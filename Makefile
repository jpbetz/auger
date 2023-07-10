
# Copyright 2022 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

NAME ?= auger
PKG ?= github.com/jpbetz/$(NAME)
GO_VERSION ?= 1.20.5
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
