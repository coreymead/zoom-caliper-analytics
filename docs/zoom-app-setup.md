# Setting Up a Zoom App for Caliper Integration

This guide walks through the process of creating and configuring a Zoom App in the Zoom Marketplace to work with the Zoom Caliper integration.

## 1. Create a Zoom Developer Account

1. Navigate to the [Zoom App Marketplace](https://marketplace.zoom.us/)
2. Click "Develop" in the top-right corner
3. Sign in with your Zoom account or create a new one

## 2. Create a New OAuth App

1. In the Zoom App Marketplace Developer dashboard, click "Build App"
2. Select "OAuth" from the app types
3. Give your app a name (e.g., "Caliper Integration")
4. Click "Create"

## 3. Configure App Information

In the "App Credentials" section:

1. Note your **Client ID** and **Client Secret** (you'll need these for the `.env` file)
2. Configure "Redirect URL for OAuth" to your callback URL:
   - For local development: `https://localhost:8080/oauth/callback`
   - For production: `https://your-domain.com/oauth/callback`

In the "Information" section:

1. Fill in the required fields:
   - App name
   - Short description
   - Long description
   - Developer name and contact information
2. Upload app icons

## 4. Add Features and Scopes

1. Navigate to the "Scopes" section
2. Add the following scopes:
   - `meeting:read:admin` - Required to access meeting information
   - `user:read:admin` - Required to access user information
   - `webinar:read:admin` - Required if you need to handle webinar events

## 5. Configure Event Subscriptions

1. Navigate to the "Feature" section
2. Click "Add" on the "Event Subscriptions" feature
3. Enable the feature
4. Configure "Event notification endpoint URL":
   - For local development: `https://localhost:8080/webhook/zoom`
   - For production: `https://your-domain.com/webhook/zoom`
5. Note your **Verification Token** (this is your webhook secret for the `.env` file)
6. Select the events you want to subscribe to:
   - `meeting.started`
   - `meeting.ended`
   - `webinar.started`
   - `webinar.ended`
   - `participant.joined`
   - `participant.left`
   - `recording.started`
   - `recording.stopped`
   - `recording.completed`
7. Click "Save"

## 6. Activate the App

1. Navigate to the "Activation" tab
2. Review all settings
3. Click "Activate your app"

## 7. Configure Your Local Environment

1. Update your `.env` file with the values from your Zoom app:

```
ZOOM_CLIENT_ID=your_client_id
ZOOM_CLIENT_SECRET=your_client_secret
ZOOM_WEBHOOK_SECRET=your_verification_token
```

## 8. Public Access for Development

For local development, you need a way to receive webhooks from Zoom. Options include:

### Using ngrok

1. Install [ngrok](https://ngrok.com/)
2. Run: `ngrok http 8080`
3. Copy the https URL (e.g., `https://abc123.ngrok.io`)
4. Update your Zoom app's Redirect URL and Event notification endpoint URL with the ngrok URL
5. Update your `.env` file with:
   ```
   REDIRECT_URL=https://abc123.ngrok.io/oauth/callback
   ```

### Alternative: Use a Production Server

If you have a production server with HTTPS support:

1. Deploy your application
2. Configure your production server with your Zoom app credentials
3. Update your Zoom app's Redirect URL and Event notification endpoint URL with your production URLs

## 9. Test the Integration

1. Start the Zoom Caliper application:
   ```
   go run cmd/zoom-caliper/main.go
   ```
2. Navigate to your OAuth authorization URL:
   - Local: `https://localhost:8080/oauth/authorize`
   - With ngrok: `https://abc123.ngrok.io/oauth/authorize`
3. Complete the OAuth flow
4. Start a Zoom meeting to trigger webhook events
5. Check your application logs to verify that events are being received and processed

## Troubleshooting

### Common Issues

1. **Webhook events not being received**
   - Verify your webhook URL is publicly accessible
   - Check that your webhook secret matches
   - Ensure your app is activated in the Zoom Marketplace

2. **OAuth authorization fails**
   - Verify your redirect URL is correctly configured
   - Check that your client ID and secret match
   - Ensure the proper scopes are enabled

3. **Invalid signature on webhook**
   - Double-check your webhook secret
   - For development, you can set `SKIP_WEBHOOK_VERIFICATION=true`

### Webhook Testing

Zoom provides a way to test webhook delivery:

1. In your app's Event Subscriptions page
2. Click "Test" next to any event you've subscribed to
3. This will send a test event to your webhook endpoint 