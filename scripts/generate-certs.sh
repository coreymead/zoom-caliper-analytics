#!/bin/bash

# Script to generate local development certificates using mkcert
# This allows the app to serve content over HTTPS locally

set -e

echo "Generating TLS certificates for local development..."

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "mkcert is not installed. Please install it first:"
    echo "On macOS: brew install mkcert"
    echo "On Linux: See https://github.com/FiloSottile/mkcert#linux"
    echo "On Windows: See https://github.com/FiloSottile/mkcert#windows"
    exit 1
fi

# Create certs directory if it doesn't exist
mkdir -p certs

# Change to certs directory
cd certs

# Generate certificates
echo "Installing local CA..."
mkcert -install

echo "Generating certificates for localhost..."
mkcert localhost 127.0.0.1 ::1

# Rename files to match expected names
mv localhost+2.pem localhost.pem
mv localhost+2-key.pem localhost-key.pem

echo "Certificates generated successfully!"
echo "TLS certificate: $(pwd)/localhost.pem"
echo "TLS key: $(pwd)/localhost-key.pem"
echo ""
echo "Update your .env file to uncomment and use these paths:"
echo "TLS_CERT_FILE=./certs/localhost.pem"
echo "TLS_KEY_FILE=./certs/localhost-key.pem"

# Print final instructions
echo ""
echo "To use HTTPS, update your .env file and restart the application." 