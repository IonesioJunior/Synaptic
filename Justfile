#!/usr/bin/env just --justfile

# Default recipe to display help
default:
    @just --list

# Variables
server_dir := "websocket_server"
client_dir := "client-sdk"
server_binary := "websocket-server"
client_binary := "ws-client"
coverage_file := "coverage.out"

# Colors for output
red := "\\033[0;31m"
green := "\\033[0;32m"
yellow := "\\033[0;33m"
blue := "\\033[0;34m"
reset := "\\033[0m"

# ====================
# Build Commands
# ====================

# Build everything
build: build-server build-client
    @echo "{{green}}✓ All projects built successfully{{reset}}"

# Build the WebSocket server
build-server:
    @echo "{{blue}}Building WebSocket server...{{reset}}"
    cd {{server_dir}} && go build -o ../bin/{{server_binary}} .
    @echo "{{green}}✓ Server built: bin/{{server_binary}}{{reset}}"

# Build the client SDK
build-client:
    @echo "{{blue}}Building client SDK...{{reset}}"
    cd {{client_dir}} && go build -v ./...
    @echo "{{green}}✓ Client SDK built{{reset}}"

# Build client examples
build-examples:
    @echo "{{blue}}Building client examples...{{reset}}"
    cd {{client_dir}} && mkdir -p bin
    cd {{client_dir}} && go build -o bin/simple-client ./examples/simple
    cd {{client_dir}} && go build -o bin/simple-env-client ./examples/simple-env
    cd {{client_dir}} && go build -o bin/advanced-client ./examples/advanced
    @echo "{{green}}✓ Examples built in {{client_dir}}/bin/{{reset}}"

# ====================
# Test Commands
# ====================

# Run all tests
test: test-server test-client
    @echo "{{green}}✓ All tests passed{{reset}}"

# Test the WebSocket server
test-server:
    @echo "{{blue}}Testing WebSocket server...{{reset}}"
    cd {{server_dir}} && go test -v -race ./...

# Test the client SDK
test-client:
    @echo "{{blue}}Testing client SDK...{{reset}}"
    cd {{client_dir}} && go test -v -race ./...

# Run tests with coverage
test-coverage:
    @echo "{{blue}}Running tests with coverage...{{reset}}"
    cd {{server_dir}} && go test -v -race -coverprofile={{coverage_file}} -covermode=atomic ./...
    cd {{server_dir}} && go tool cover -html={{coverage_file}} -o coverage-server.html
    cd {{client_dir}} && go test -v -race -coverprofile={{coverage_file}} -covermode=atomic ./...
    cd {{client_dir}} && go tool cover -html={{coverage_file}} -o coverage-client.html
    @echo "{{green}}✓ Coverage reports generated{{reset}}"

# Run integration tests (requires running server)
test-integration:
    @echo "{{yellow}}⚠ Make sure the WebSocket server is running{{reset}}"
    cd {{client_dir}} && go test -tags=integration -v -timeout=30s

# Run benchmarks
bench:
    @echo "{{blue}}Running benchmarks...{{reset}}"
    cd {{server_dir}} && go test -bench=. -benchmem ./...
    cd {{client_dir}} && go test -bench=. -benchmem ./...

# ====================
# Run Commands
# ====================

# Run the WebSocket server
run-server: build-server
    @echo "{{blue}}Starting WebSocket server...{{reset}}"
    ./bin/{{server_binary}}

# Run the server with custom settings
run-server-dev:
    @echo "{{blue}}Starting WebSocket server in dev mode...{{reset}}"
    cd {{server_dir}} && SERVER_ADDR=":8443" MESSAGE_RATE_LIMIT="10.0" MESSAGE_BURST_LIMIT="20" go run .

# Run simple client example
run-client-simple: build-examples
    @echo "{{blue}}Running simple client...{{reset}}"
    cd {{client_dir}} && ./bin/simple-client

# Run advanced client example
run-client-advanced: build-examples
    @echo "{{blue}}Running advanced client...{{reset}}"
    cd {{client_dir}} && ./bin/advanced-client

# Run both server and client in separate terminals (requires tmux)
run-demo:
    @echo "{{blue}}Starting demo in tmux...{{reset}}"
    @tmux new-session -d -s demo -n server 'just run-server'
    @tmux new-window -t demo -n client 'sleep 2 && just run-client-simple'
    @tmux attach -t demo
    @echo "{{green}}✓ Demo started in tmux{{reset}}"

# ====================
# Development Commands
# ====================

# Format all Go code
fmt:
    @echo "{{blue}}Formatting code...{{reset}}"
    cd {{server_dir}} && go fmt ./...
    cd {{client_dir}} && go fmt ./...
    @echo "{{green}}✓ Code formatted{{reset}}"

# Run go vet on all code
vet:
    @echo "{{blue}}Running go vet...{{reset}}"
    cd {{server_dir}} && go vet ./...
    cd {{client_dir}} && go vet ./...
    @echo "{{green}}✓ Vet passed{{reset}}"

# Run linter (requires golangci-lint)
lint:
    @echo "{{blue}}Running linter...{{reset}}"
    @which golangci-lint > /dev/null || (echo "{{yellow}}Installing golangci-lint...{{reset}}" && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
    cd {{server_dir}} && golangci-lint run ./...
    cd {{client_dir}} && golangci-lint run ./...
    @echo "{{green}}✓ Linting complete{{reset}}"

# Run all checks (fmt, vet, lint, test)
check: fmt vet lint test
    @echo "{{green}}✓ All checks passed{{reset}}"

# Update dependencies
deps:
    @echo "{{blue}}Updating dependencies...{{reset}}"
    cd {{server_dir}} && go get -u ./... && go mod tidy
    cd {{client_dir}} && go get -u ./... && go mod tidy
    @echo "{{green}}✓ Dependencies updated{{reset}}"

# Download dependencies
deps-download:
    @echo "{{blue}}Downloading dependencies...{{reset}}"
    cd {{server_dir}} && go mod download
    cd {{client_dir}} && go mod download
    @echo "{{green}}✓ Dependencies downloaded{{reset}}"

# ====================
# Database Commands
# ====================

# Reset the server database
db-reset:
    @echo "{{yellow}}⚠ Resetting database...{{reset}}"
    rm -f {{server_dir}}/app.db {{server_dir}}/app.db-shm {{server_dir}}/app.db-wal
    @echo "{{green}}✓ Database reset{{reset}}"

# Backup the server database
db-backup:
    @echo "{{blue}}Backing up database...{{reset}}"
    @mkdir -p backups
    @cp {{server_dir}}/app.db backups/app-$(date +%Y%m%d-%H%M%S).db 2>/dev/null || echo "{{yellow}}No database to backup{{reset}}"
    @echo "{{green}}✓ Database backed up{{reset}}"

# ====================
# Docker Commands
# ====================

# Build Docker images
docker-build:
    @echo "{{blue}}Building Docker images...{{reset}}"
    docker build -t websocket-server:latest -f {{server_dir}}/Dockerfile {{server_dir}}
    docker build -t websocket-client:latest -f {{client_dir}}/Dockerfile {{client_dir}}
    @echo "{{green}}✓ Docker images built{{reset}}"

# Build with docker-compose
docker-compose-build:
    @echo "{{blue}}Building with docker-compose...{{reset}}"
    @which docker-compose > /dev/null || docker compose build || (echo "{{red}}docker-compose not found. Please install it or use 'docker compose' command{{reset}}" && exit 1)
    @echo "{{green}}✓ Docker compose build complete{{reset}}"

# Run with docker-compose
docker-compose-up:
    @echo "{{blue}}Starting services with docker-compose...{{reset}}"
    docker compose up -d
    @echo "{{green}}✓ Services started{{reset}}"
    @echo "{{yellow}}Server: https://localhost:443{{reset}}"
    @echo "{{yellow}}Clients: Alice, Bob, Charlie, and Bot{{reset}}"
    @echo "{{yellow}}View logs: docker compose logs -f{{reset}}"

# Run docker-compose with only server and specific clients
docker-compose-up-selective clients="alice bob":
    @echo "{{blue}}Starting server and selected clients: {{clients}}...{{reset}}"
    docker compose up -d websocket-server $(echo {{clients}} | sed 's/\b\w/client-&/g')
    @echo "{{green}}✓ Services started{{reset}}"

# Stop docker-compose services
docker-compose-down:
    @echo "{{blue}}Stopping docker-compose services...{{reset}}"
    docker compose down
    @echo "{{green}}✓ Services stopped{{reset}}"

# View logs for all clients
docker-compose-logs-clients:
    @echo "{{blue}}Showing client logs...{{reset}}"
    docker compose logs -f client-alice client-bob client-charlie message-bot

# Attach to a specific client
docker-attach-client name="alice":
    @echo "{{blue}}Attaching to client-{{name}}...{{reset}}"
    @echo "{{yellow}}Press Ctrl+P, Ctrl+Q to detach{{reset}}"
    docker attach ws-client-{{name}}

# Send message from one client to another
docker-send-message from="alice" to="bob" message="Hello Bob!":
    @echo "{{blue}}Sending message from {{from}} to {{to}}...{{reset}}"
    echo "@{{to}} {{message}}" | docker exec -i ws-client-{{from}} sh -c 'cat >> /proc/1/fd/0'

# Show active users from server perspective
docker-active-users:
    @echo "{{blue}}Fetching active users...{{reset}}"
    docker exec ws-server wget -qO- http://localhost/active-users | jq '.' || echo "{{red}}Server not ready or jq not installed{{reset}}"

# Run server in Docker
docker-run-server:
    @echo "{{blue}}Running server in Docker...{{reset}}"
    docker run -d --name ws-server -p 443:443 -p 80:80 -e JWT_SECRET=your-secret-key websocket-server:latest
    @echo "{{green}}✓ Server running on https://localhost:443{{reset}}"

# Run client in Docker
docker-run-client:
    @echo "{{blue}}Running client in Docker...{{reset}}"
    docker run -it --rm --name ws-client --network host -e INSECURE_TLS=true -e WS_SERVER_URL=https://localhost:443 websocket-client:latest

# Generate Ed25519 keys for all clients and save to .env
generate-keys:
    @echo "{{blue}}Generating Ed25519 keys for clients...{{reset}}"
    @./scripts/generate-keys.sh
    @echo "{{green}}✓ Keys generated and saved to .env{{reset}}"

# Run client with environment variables
docker-run-client-env user="test" username="Test User":
    @echo "{{blue}}Running client with environment configuration...{{reset}}"
    docker run -it --rm --name ws-client-{{user}} \
        --network host \
        -e WS_USER_ID={{user}} \
        -e WS_USERNAME="{{username}}" \
        -e INSECURE_TLS=true \
        -e WS_SERVER_URL=https://localhost:443 \
        -e AUTO_ANNOUNCE=true \
        websocket-client:latest ./simple-env-client

# Stop Docker containers
docker-stop:
    @echo "{{blue}}Stopping Docker containers...{{reset}}"
    docker stop ws-server ws-client 2>/dev/null || true
    docker rm ws-server ws-client 2>/dev/null || true
    @echo "{{green}}✓ Containers stopped{{reset}}"

# View Docker logs
docker-logs:
    @echo "{{blue}}Showing Docker logs...{{reset}}"
    docker-compose logs -f --tail=50

# ====================
# Cleanup Commands
# ====================

# Clean build artifacts
clean:
    @echo "{{blue}}Cleaning build artifacts...{{reset}}"
    rm -rf bin/
    rm -f {{server_dir}}/{{server_binary}}
    rm -f {{client_dir}}/bin/*
    rm -f {{server_dir}}/{{coverage_file}} {{server_dir}}/coverage*.html
    rm -f {{client_dir}}/{{coverage_file}} {{client_dir}}/coverage*.html
    find . -name "*.test" -delete
    @echo "{{green}}✓ Cleaned{{reset}}"

# Deep clean (includes database and logs)
clean-all: clean db-reset
    @echo "{{blue}}Deep cleaning...{{reset}}"
    rm -rf {{server_dir}}/*.log
    rm -rf {{client_dir}}/*.log
    rm -rf backups/
    @echo "{{green}}✓ Deep clean complete{{reset}}"

# Nuclear clean - removes EVERYTHING including Docker images, volumes, containers
clean-nuclear: clean-all
    @echo "{{red}}⚠ NUCLEAR CLEAN - This will remove everything!{{reset}}"
    @echo "{{blue}}Stopping all containers...{{reset}}"
    -docker compose down -v
    -docker rm -f $(docker ps -aq) 2>/dev/null || true
    @echo "{{blue}}Removing Docker images...{{reset}}"
    -docker rmi websocket-server:latest websocket-client:latest 2>/dev/null || true
    @echo "{{blue}}Removing directories and files...{{reset}}"
    rm -rf data/ certs/ backups/ releases/ .env .env.* test-client.sh security-report.json
    rm -rf /tmp/test.db /tmp/*_key.txt 2>/dev/null || true
    @echo "{{blue}}Pruning Docker volumes and networks...{{reset}}"
    -docker volume prune -f
    -docker network prune -f
    @echo "{{green}}✓ Nuclear clean complete - everything removed!{{reset}}"

# ====================
# Documentation Commands
# ====================

# Generate documentation
docs:
    @echo "{{blue}}Generating documentation...{{reset}}"
    @which godoc > /dev/null || go install golang.org/x/tools/cmd/godoc@latest
    @echo "{{green}}Documentation server starting at http://localhost:6060{{reset}}"
    @echo "{{yellow}}Press Ctrl+C to stop{{reset}}"
    godoc -http=:6060

# View README
readme:
    @cat {{client_dir}}/README.md | less

# View architecture docs
architecture:
    @cat {{client_dir}}/ARCHITECTURE.md | less

# ====================
# Security Commands
# ====================

# Run security scan
security:
    @echo "{{blue}}Running security scan...{{reset}}"
    @which gosec > /dev/null || (echo "{{yellow}}Installing gosec...{{reset}}" && go install github.com/securego/gosec/v2/cmd/gosec@latest)
    gosec -fmt=json -out=security-report.json ./...
    @echo "{{green}}✓ Security scan complete (see security-report.json){{reset}}"

# Check for vulnerabilities
vuln-check:
    @echo "{{blue}}Checking for vulnerabilities...{{reset}}"
    cd {{server_dir}} && go list -json -deps ./... | nancy sleuth
    cd {{client_dir}} && go list -json -deps ./... | nancy sleuth
    @echo "{{green}}✓ Vulnerability check complete{{reset}}"

# ====================
# Monitoring Commands
# ====================

# Show server logs
logs-server:
    @echo "{{blue}}Showing server logs...{{reset}}"
    tail -f {{server_dir}}/*.log 2>/dev/null || echo "{{yellow}}No log files found{{reset}}"

# Monitor server database
monitor-db:
    @echo "{{blue}}Monitoring database...{{reset}}"
    watch -n 1 'sqlite3 {{server_dir}}/app.db "SELECT COUNT(*) as users FROM users; SELECT COUNT(*) as messages FROM messages; SELECT COUNT(*) as sessions FROM sessions;"'

# ====================
# Release Commands
# ====================

# Create release binaries
release:
    @echo "{{blue}}Building release binaries...{{reset}}"
    @mkdir -p releases
    # Build server for multiple platforms
    cd {{server_dir}} && GOOS=linux GOARCH=amd64 go build -o ../releases/{{server_binary}}-linux-amd64 .
    cd {{server_dir}} && GOOS=darwin GOARCH=amd64 go build -o ../releases/{{server_binary}}-darwin-amd64 .
    cd {{server_dir}} && GOOS=windows GOARCH=amd64 go build -o ../releases/{{server_binary}}-windows-amd64.exe .
    # Build client examples
    cd {{client_dir}} && GOOS=linux GOARCH=amd64 go build -o ../releases/simple-client-linux-amd64 ./examples/simple
    cd {{client_dir}} && GOOS=darwin GOARCH=amd64 go build -o ../releases/simple-client-darwin-amd64 ./examples/simple
    cd {{client_dir}} && GOOS=windows GOARCH=amd64 go build -o ../releases/simple-client-windows-amd64.exe ./examples/simple
    @echo "{{green}}✓ Release binaries created in releases/{{reset}}"

# Package release
package version:
    @echo "{{blue}}Packaging release {{version}}...{{reset}}"
    just release
    tar -czf websocket-suite-{{version}}.tar.gz releases/
    @echo "{{green}}✓ Package created: websocket-suite-{{version}}.tar.gz{{reset}}"

# ====================
# Utility Commands
# ====================

# Show project statistics
stats:
    @echo "{{blue}}Project Statistics:{{reset}}"
    @echo "Server lines of code:"
    @find {{server_dir}} -name "*.go" | xargs wc -l | tail -1
    @echo "Client SDK lines of code:"
    @find {{client_dir}} -name "*.go" | xargs wc -l | tail -1
    @echo "Test coverage:"
    @cd {{server_dir}} && go test -cover ./... 2>/dev/null | grep -E "coverage:" || echo "Run 'just test-coverage' for detailed coverage"

# Initialize development environment
init:
    @echo "{{blue}}Initializing development environment...{{reset}}"
    just deps-download
    just build
    @echo "{{green}}✓ Development environment ready{{reset}}"

# Run development watcher (requires entr)
watch:
    @echo "{{blue}}Watching for changes...{{reset}}"
    @which entr > /dev/null || (echo "{{red}}Please install entr: https://github.com/eradman/entr{{reset}}" && exit 1)
    find . -name "*.go" | entr -c just test

# Generate self-signed certificates for testing
gen-certs:
    @echo "{{blue}}Generating self-signed certificates...{{reset}}"
    cd {{server_dir}} && openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
    @echo "{{green}}✓ Certificates generated{{reset}}"

# Help command with categories
help:
    @echo "{{blue}}WebSocket Suite - Available Commands{{reset}}"
    @echo ""
    @echo "{{yellow}}Build & Run:{{reset}}"
    @echo "  build           - Build all projects"
    @echo "  run-server      - Run the WebSocket server"
    @echo "  run-client-*    - Run client examples"
    @echo "  run-demo        - Run demo in tmux"
    @echo ""
    @echo "{{yellow}}Testing:{{reset}}"
    @echo "  test            - Run all tests"
    @echo "  test-coverage   - Generate coverage reports"
    @echo "  bench           - Run benchmarks"
    @echo ""
    @echo "{{yellow}}Development:{{reset}}"
    @echo "  check           - Run all checks"
    @echo "  watch           - Watch for changes"
    @echo "  fmt/vet/lint    - Code quality tools"
    @echo ""
    @echo "{{yellow}}Maintenance:{{reset}}"
    @echo "  clean           - Clean build artifacts"
    @echo "  deps            - Update dependencies"
    @echo "  db-reset        - Reset database"
    @echo ""
    @echo "Run 'just --list' for all commands"