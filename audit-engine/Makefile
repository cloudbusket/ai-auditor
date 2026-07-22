APP_NAME=auditor

build:
	go build -o bin/$(APP_NAME) ./cmd/auditor

run:
	go run ./cmd/auditor

test:
	go test ./...

clean:
	rm -rf bin

fmt:
	go fmt ./...

lint:
	go vet ./...
