.PHONY: build test vet lint clean

build:
	go build -o bin/ ./cmd/...

test:
	go test -race -count=1 ./...

vet:
	gofmt -l .
	go vet ./...

lint: build
	bin/sentinel-core lint rules/bridge

clean:
	rm -rf bin
