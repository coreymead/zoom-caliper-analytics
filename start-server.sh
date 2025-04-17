#!/bin/bash

# Kill any running instances
pkill -f "zoom-caliper" || true

# Start the server with log redirection
go run cmd/zoom-caliper/main.go 2>&1 | tee server.log 