# Build stage
FROM golang:1.20-alpine AS builder

# Install necessary build tools
RUN apk add --no-cache git

# Set the working directory
WORKDIR /app

# Copy go.mod and go.sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o zoom-caliper ./cmd/zoom-caliper

# Runtime stage
FROM alpine:3.17

# Install CA certificates for HTTPS connections
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create directories for the application
RUN mkdir -p /app/certs /app/tokens
WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/zoom-caliper /app/

# Create a directory for storing tokens and certificates
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose the HTTP and HTTPS ports
EXPOSE 8080 8443

# Set environment variables
ENV USE_TEST_CLIENT=false

# Volume for certificates and tokens
VOLUME ["/app/certs", "/app/tokens"]

# Run the application
ENTRYPOINT ["/app/zoom-caliper"] 