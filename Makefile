init: generate

generate:
	go generate ./...


build:
	mkdir -p bin
	go build $(GO_EXTRA_BUILD_ARGS) -ldflags "-s -w -X main.version=$(VERSION)" -o bin/server ./cmd/server/*.go

clean:
	rm -f bin/server

run: clean build
	./bin/server --config .env.local
