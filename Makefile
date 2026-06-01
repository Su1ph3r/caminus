BINARY := caminus
PKG    := ./cmd/caminus
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet fmt clean install

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

clean:
	rm -rf bin dist $(BINARY) $(BINARY).exe
