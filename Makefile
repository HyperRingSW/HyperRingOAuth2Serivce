#.DEFAULT_GOAL := up
#VERSION := $(shell git describe --tags --always --long |sed -e "s/^v//")
#GO_LINT_VERSION := v1.53.3


#PLAYER_OPENAPI_PATH = openapi/upl-openapi/frontend/cap/player/v1/openapi.yaml
#PLAYER_GENERATED_CODE_PATH = openapi/api/player

.PHONY: generate proto

init: clean submodules proto generate-player-client generate

generate:
	go generate ./...


build:
	mkdir -p bin
	go build $(GO_EXTRA_BUILD_ARGS) -ldflags "-s -w -X main.version=$(VERSION)" -o bin/server ./cmd/server/*.go

run: build
	./bin/server --config .env.local
