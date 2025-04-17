#!/bin/bash

# Script to run the Zoom Caliper application with ngrok
# This sets up a tunnel for receiving webhooks from Zoom

set -e

# Check if ngrok is installed
if ! command -v ngrok &> /dev/null; then
    echo "ngrok is not installed. Please install it first:"
    echo "On macOS: brew install ngrok"
    echo "Or download from: https://ngrok.com/download"
    exit 1
fi

# Check if environment variables are set
if [ ! -f .env ]; then
    echo "No .env file found. Please create one with your Zoom credentials."
    exit 1
fi

# Build the application
echo "Building application..."
go build -o bin/zoom-caliper cmd/zoom-caliper/main.go

# Start ngrok in the background
echo "Starting ngrok tunnel on port 8080..."
ngrok http 8080 > /dev/null &
NGROK_PID=$!

# Wait for ngrok to start
sleep 2

# Get the ngrok URL
NGROK_URL=$(curl -s http://localhost:4040/api/tunnels | grep -o '"public_url":"https://[^"]*' | grep -o 'https://[^"]*')

if [ -z "$NGROK_URL" ]; then
    echo "Failed to get ngrok URL. Is ngrok running correctly?"
    kill $NGROK_PID
    exit 1
fi

echo "ngrok tunnel established at: $NGROK_URL"
echo "Updating .env file with ngrok URL..."

# Create a temporary file with the updated REDIRECT_URL
sed -i.bak "s|REDIRECT_URL=.*|REDIRECT_URL=${NGROK_URL}/oauth/callback|" .env
rm .env.bak

echo ""
echo "====================================="
echo "Zoom Caliper is ready!"
echo "====================================="
echo ""
echo "1. Update your Zoom app configuration with these URLs:"
echo "   - Redirect URL for OAuth: ${NGROK_URL}/oauth/callback"
echo "   - Event notification endpoint URL: ${NGROK_URL}/webhook/zoom"
echo ""
echo "2. Start the OAuth flow by visiting:"
echo "   ${NGROK_URL}/oauth/authorize"
echo ""
echo "Press Ctrl+C to stop the application and ngrok"
echo ""

# Start the application
./bin/zoom-caliper

# Clean up ngrok when the application exits
kill $NGROK_PID 