.PHONY: all build test clean install lint fmt vet bench coverage examples

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOCLEAN=$(GOCMD) clean
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
GOVET=$(GOCMD) vet
GOLINT=golangci-lint

# Build parameters
BINARY_NAME=wsclient
BINARY_DIR=bin
COVERAGE_FILE=coverage.out

all: test build

build:
	@echo "Building SDK..."
	$(GOBUILD) -v ./...

test:
	@echo "Running tests..."
	$(GOTEST) -v -race ./...

test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -v -race -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report generated: coverage.html"

bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BINARY_DIR)
	rm -f $(COVERAGE_FILE) coverage.html

install:
	@echo "Installing dependencies..."
	$(GOGET) -v ./...
	$(GOMOD) download
	$(GOMOD) tidy

fmt:
	@echo "Formatting code..."
	$(GOFMT) -s -w .

vet:
	@echo "Running go vet..."
	$(GOVET) ./...

lint:
	@echo "Running linter..."
	@which $(GOLINT) > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	$(GOLINT) run ./...

# Build examples
examples: example-simple example-advanced

example-simple:
	@echo "Building simple example..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(BINARY_DIR)/simple-client ./examples/simple

example-advanced:
	@echo "Building advanced example..."
	@mkdir -p $(BINARY_DIR)
	$(GOBUILD) -o $(BINARY_DIR)/advanced-client ./examples/advanced

# Run examples
run-simple: example-simple
	@echo "Running simple client..."
	./$(BINARY_DIR)/simple-client

run-advanced: example-advanced
	@echo "Running advanced client..."
	./$(BINARY_DIR)/advanced-client

# Development helpers
dev-test:
	@echo "Running tests in watch mode..."
	@which reflex > /dev/null || go install github.com/cespare/reflex@latest
	reflex -r '\.go$$' -- $(GOTEST) -v ./...

check: fmt vet lint test
	@echo "All checks passed!"

# Documentation
docs:
	@echo "Generating documentation..."
	@which godoc > /dev/null || go install golang.org/x/tools/cmd/godoc@latest
	@echo "Documentation server starting at http://localhost:6060"
	godoc -http=:6060

# Docker support
docker-build:
	@echo "Building Docker image..."
	docker build -t wsclient-sdk:latest .

# Help
help:
	@echo "Available targets:"
	@echo "  make build          - Build the SDK"
	@echo "  make test           - Run tests"
	@echo "  make test-coverage  - Run tests with coverage report"
	@echo "  make bench          - Run benchmarks"
	@echo "  make clean          - Clean build artifacts"
	@echo "  make install        - Install dependencies"
	@echo "  make fmt            - Format code"
	@echo "  make vet            - Run go vet"
	@echo "  make lint           - Run linter"
	@echo "  make examples       - Build example applications"
	@echo "  make run-simple     - Run simple example"
	@echo "  make run-advanced   - Run advanced example"
	@echo "  make check          - Run all checks (fmt, vet, lint, test)"
	@echo "  make docs           - Start documentation server"
	@echo "  make help           - Show this help message"