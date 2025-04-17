# Fix Webhook Request Body Handling

## Description
This PR fixes an issue with the webhook handling logic where the request body was being read twice, which was causing validation failures. The solution was to separate the body reading from the signature validation, allowing the verification to happen without consuming the request body.

## Changes
- Added a new `ValidateSignature` function to handle signature verification without reading the request body
- Updated the webhook handler to avoid reading the body twice
- Added comprehensive tests for webhook signature validation
- Added tests for the webhook handler with signature verification

## Testing
The changes were tested using unit tests that verify:
- Valid signatures are accepted
- Invalid signatures are rejected
- Missing headers are properly handled
- Proper error messages are returned

## References
- [Zoom Webhook Documentation](https://marketplace.zoom.us/docs/api-reference/webhook-reference/#verify-webhook-events) 