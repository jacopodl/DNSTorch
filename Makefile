GOCMD=go
GOBUILD=$(GOCMD) build

# Binary
BIN_FOLDER=$(shell pwd)/bin
BIN_NAME=$(shell basename "$(PWD)")

export GO111MODULE=off
export GOPATH=$(shell pwd)

dnstorch:
	@echo "Building $(BIN_NAME)..."
	@$(GOBUILD) -o $(BIN_FOLDER)/$(BIN_NAME) src/main.go
	@echo "Done"
clean:
	@$(GOCMD) clean

.PHONY: dnstorch clean

