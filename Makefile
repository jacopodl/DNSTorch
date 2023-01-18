GOCMD=go
GOBUILD=$(GOCMD) build

# Binary
BIN_FOLDER=$(shell pwd)/bin
BIN_NAME=$(shell basename "$(PWD)")

dnstorch:
	@echo "Building $(BIN_NAME)..."
	@$(GOBUILD) -o $(BIN_FOLDER)/$(BIN_NAME) src/main.go
	@echo "Done"
clean:
	@$(GOCMD) clean

.PHONY: dnstorch clean

