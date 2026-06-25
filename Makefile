.PHONY: build clean test

build:
	@mkdir -p bin
	go build -o bin/ping ./cmd/ping

clean:
	rm -f bin/ping

test:
	go test -v -race ./...
