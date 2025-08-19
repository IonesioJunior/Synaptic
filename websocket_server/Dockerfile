# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git gcc musl-dev sqlite-dev

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o websocket-server .

# Generate self-signed certificates for testing (production should use real certs)
RUN apk add --no-cache openssl && \
    openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
    -days 365 -nodes -subj "/CN=localhost" \
    -addext "subjectAltName = DNS:localhost,DNS:ws-server,DNS:websocket-server,IP:127.0.0.1,IP:::1"

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates sqlite

# Create non-root user
RUN addgroup -g 1000 -S wsserver && \
    adduser -u 1000 -S wsserver -G wsserver

# Set working directory
WORKDIR /app

# Copy binary and certificates from builder
COPY --from=builder /build/websocket-server .
COPY --from=builder /build/server.crt .
COPY --from=builder /build/server.key .

# Copy static files if they exist
COPY --from=builder /build/static ./static

# Create directory for database
RUN mkdir -p /app/data && \
    chown -R wsserver:wsserver /app

# Switch to non-root user
USER wsserver

# Environment variables with defaults
ENV SERVER_ADDR=":443" \
    MESSAGE_RATE_LIMIT="5.0" \
    MESSAGE_BURST_LIMIT="10" \
    JWT_SECRET=""

# Expose ports
EXPOSE 80 443

# Health check (using --no-check-certificate for self-signed cert)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider --no-check-certificate https://localhost/health || exit 1

# Volume for persistent data
VOLUME ["/app/data"]

# Run the server
CMD ["./websocket-server"]