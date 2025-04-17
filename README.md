# Zoom Caliper

A service that consumes Zoom webhook events and publishes them to a Caliper data feed.

## Features

- Processes Zoom webhook events (meeting started, ended, participant joined, left)
- Maps Zoom events to Caliper format
- Supports OAuth authentication with Zoom
- Provides HTTPS endpoints for secure webhook reception
- Configurable through environment variables

## Setup and Installation

### Prerequisites

- Go 1.19 or higher
- mkcert for local HTTPS development

### Environment Variables

Create a `.env` file in the root directory with the following variables:

```
ZOOM_CLIENT_ID=your_zoom_client_id
ZOOM_CLIENT_SECRET=your_zoom_client_secret
ZOOM_WEBHOOK_SECRET=your_zoom_webhook_secret
USE_TEST_CLIENT=true  # Set to false for production
```

### SSL Certificates

For HTTPS support, generate certificates using mkcert:

```bash
# Install mkcert
brew install mkcert  # on macOS

# Create a directory for certificates
mkdir -p certs

# Install local CA
mkcert -install

# Generate certificates
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost
```

## Running the Application

### Directly with Go

```bash
# Install dependencies
go mod tidy

# Run the application
go run cmd/zoom-caliper/main.go
```

### Using Docker

The application can be run using Docker:

```bash
# Build the Docker image
docker build -t zoom-caliper .

# Run the container
docker run -p 8080:8080 -p 8443:8443 \
  -e ZOOM_CLIENT_ID=your_zoom_client_id \
  -e ZOOM_CLIENT_SECRET=your_zoom_client_secret \
  -e ZOOM_WEBHOOK_SECRET=your_zoom_webhook_secret \
  -v $(pwd)/certs:/app/certs \
  -v $(pwd)/tokens:/app/tokens \
  zoom-caliper
```

### Using Docker Compose

For a more convenient setup, use Docker Compose:

```bash
# Create and populate .env file with your credentials
echo "ZOOM_CLIENT_ID=your_zoom_client_id" > .env
echo "ZOOM_CLIENT_SECRET=your_zoom_client_secret" >> .env
echo "ZOOM_WEBHOOK_SECRET=your_zoom_webhook_secret" >> .env
echo "USE_TEST_CLIENT=true" >> .env  # Set to false for production

# Start the service
docker-compose up -d

# View logs
docker-compose logs -f
```

## OAuth Setup

1. Visit `http://localhost:8080/oauth/authorize` to initiate OAuth flow
2. Login to Zoom when prompted
3. Authorize the application
4. You will be redirected back to the callback URL

## Webhook Setup

1. In the Zoom Marketplace, set up a webhook endpoint pointing to `https://your-domain:8443/webhook/zoom`
2. Configure the webhook to listen for the following events:
   - meeting.started
   - meeting.ended
   - meeting.participant_joined
   - meeting.participant_left

## Testing

Run the tests with:

```bash
go test ./...

## License

MIT 