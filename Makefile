.PHONY: build clean test lint

BINARY := ping
CMD_DIR := ./cmd/ping

build:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY) $(CMD_DIR)

clean:
	rm -f $(BINARY)

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...
