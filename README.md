# r2-presign-url Cloudflare Worker

A Cloudflare Worker for generating presigned R2 PUT URLs with JWT authentication, file-type validation, per-file cache control, and robust error handling.

## Table of Contents
- [Features](#features)  
- [Installation](#installation)  
- [Usage](#usage)  
- [Wrangler Configuration](#wrangler-configuration)  
- [Wrangler Secrets](#wrangler-secrets)  
- [Dependencies](#dependencies)  
- [License](#license)

## Features
- **JWT Authentication**: Validate and verify bearer tokens using `jose`.
- **Typed Uploads**: Enforce allowed extensions and upload types.
- **Per-file Cache-Control**: Customize `Cache-Control` per file (max‑age, immutable).
- **Concurrency Limiting**: Generate up to 200 presigned URLs with controlled concurrency.
- **Timeout Handling**: Abort slow presign operations.
- **Multi-status Responses**: RFC 7807 compliant 200, 207, 422, and error responses.
- **Observability**: Built‑in worker metrics and logging via Wrangler.

## Installation

```bash
git clone <your-repo-url>
cd r2-presign-url
npm install
```

## Usage

Publish to Cloudflare Workers:

```bash
npx wrangler publish --env dev
npx wrangler publish --env prod
```

Request presigned URLs:

```bash
curl -X POST https://<your-domain>/generate-presigned-urls   -H "Authorization: Bearer <JWT_TOKEN>"   -H "Content-Type: application/json"   -d '{
    "files": [
      { "filename": "example.jpg", "type": "item_image" },
      { "filename": "recording.mp3", "type": "item_recording" }
    ],
    "presign_options": { "expires_in_seconds": 600 }
  }'
```

## Configuration

All of your Cloudflare Worker settings live in **wrangler.jsonc** at the repo root. Before you publish, make sure to update the following fields under each environment (`dev` and `prod`):

```jsonc
{
  "env": {
    "dev": {
      "vars": {
        "R2_PUBLIC_URL_PREFIX": "https://pub-<YOUR_DEV_HASH>.r2.dev",
        "EXPECTED_AUDIENCE": "<your-jwt-expected-audience>",
        "EXPECTED_ISSUER": "<your-jwt-expected-issuer>",
        "MAX_FILES": "200",
        "PRESIGNED_URL_EXPIRATION_SECONDS": "300",
        "DEPLOY_ENV": "dev",
        "R2_BUCKET_NAME": "<your-dev-bucket-name>",
        "DEFAULT_MAX_FILES": "200",
        "DEFAULT_PRESIGNED_URL_EXPIRY_SECONDS": "300",
        "MIN_PRESIGNED_URL_EXPIRATION_SECONDS": "60",
        "MAX_PRESIGNED_URL_EXPIRATION_SECONDS": "3600",
        "MAX_PAYLOAD_SIZE_BYTES": "524288",
        "PRESIGN_OPERATION_TIMEOUT_MS": "5000",
        "PRESIGN_REQUEST_CONCURRENCY_LIMIT": "10",
        "DEBUG_LOGGING": "true"
      },
      "r2_buckets": [
        {
          "binding": "<YOUR_R2_BUCKET_BINDING>",
          "bucket_name": "<your-dev-bucket-name>",
          "preview_bucket_name": "<your-dev-preview-bucket>"
        }
      ]
    },
    "prod": {
      "vars": {
        "R2_PUBLIC_URL_PREFIX": "https://cdn.example.com",
        "EXPECTED_AUDIENCE": "<your-jwt-expected-audience>",
        "EXPECTED_ISSUER": "<your-jwt-expected-issuer>",
        "MAX_FILES": "200",
        "PRESIGNED_URL_EXPIRATION_SECONDS": "300",
        "DEPLOY_ENV": "prod",
        "R2_BUCKET_NAME": "<your-prod-bucket-name>",
        "DEFAULT_MAX_FILES": "200",
        "DEFAULT_PRESIGNED_URL_EXPIRY_SECONDS": "300",
        "MIN_PRESIGNED_URL_EXPIRATION_SECONDS": "60",
        "MAX_PRESIGNED_URL_EXPIRATION_SECONDS": "3600",
        "MAX_PAYLOAD_SIZE_BYTES": "524288",
        "PRESIGN_OPERATION_TIMEOUT_MS": "5000",
        "PRESIGN_REQUEST_CONCURRENCY_LIMIT": "10",
        "DEBUG_LOGGING": "false"
      },
      "r2_buckets": [
        {
          "binding": "<YOUR_R2_BUCKET_BINDING>",
          "bucket_name": "<your-prod-bucket-name>",
          "preview_bucket_name": "<your-prod-preview-bucket>"
        }
      ]
    }
  }
}
```

## Wrangler Secrets

Run to list required secrets in each environment:

```bash
npx wrangler secret list --env dev
# [
#   { "name": "CLOUDFLARE_ACCOUNT_ID", "type": "secret_text" },
#   { "name": "JWT_SECRET",             "type": "secret_text" },
#   { "name": "R2_ACCESS_KEY_ID",       "type": "secret_text" },
#   { "name": "R2_SECRET_ACCESS_KEY",   "type": "secret_text" }
# ]
```

## Dependencies

- **Hono** `^4.7.10`  
- **jose** `^6.0.11`  
- **aws4fetch** `^1.0.17`  
- **hono/body-limit**  
- **hono/http-exception**  

## License

This project is licensed under the [MIT License](LICENSE).
