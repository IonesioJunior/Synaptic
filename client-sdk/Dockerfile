# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the examples
RUN go build -o simple-client ./examples/simple
RUN go build -o simple-env-client ./examples/simple-env
RUN go build -o advanced-client ./examples/advanced

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1000 -S wsclient && \
    adduser -u 1000 -S wsclient -G wsclient

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/simple-client .
COPY --from=builder /build/simple-env-client .
COPY --from=builder /build/advanced-client .

# Switch to non-root user
USER wsclient

# Environment variables
ENV WS_SERVER_URL="https://localhost:443" \
    WS_USER_ID="" \
    WS_USERNAME="" \
    WS_PRIVATE_KEY="" \
    INSECURE_TLS="false" \
    AUTO_MODE="false" \
    AUTO_ANNOUNCE="false" \
    DEBUG="false"

# Default command (can be overridden)
CMD ["./simple-env-client"]