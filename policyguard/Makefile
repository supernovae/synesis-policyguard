APP_NAME := policyguard
GO        ?= go
MODULE    := github.com/synesis/policyguard

.PHONY: all build test vet lint fmt clean docker-build run

all: fmt vet lint build test

build:
	$(GO) build -o bin/$(APP_NAME) ./cmd/$(APP_NAME)

test:
	$(GO) test -race -count=1 -v ./...

test-coverage:
	$(GO) test -race -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf bin/ coverage.out coverage.html

docker-build:
	docker build -t $(APP_NAME):latest .

run: build
	./bin/$(APP_NAME)
