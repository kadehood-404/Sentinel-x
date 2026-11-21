.PHONY: build test test-race vet lint clean

GO ?= $(shell command -v go || echo $(HOME)/.local/bin/go)

build:
	$(GO) build -o bin/ ./cmd/...

test:
	$(GO) test -count=1 ./...

test-race:
	$(GO) test -race -count=1 ./internal/policy ./internal/ledger ./internal/sigil ./internal/hammer ./internal/bridge

vet:
	gofmt -l cmd internal
	$(GO) vet ./...

lint: build
	bin/sentinel-x lint rules

clean:
	rm -rf bin
