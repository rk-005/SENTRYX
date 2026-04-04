---
title: SENTRYX Security API
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
---

# SENTRYX Security API

Minimal Hugging Face Docker Space bundle for prompt security classification.

Environment variables:

- `API_BASE_URL`
- `MODEL_NAME`
- `HF_TOKEN`

Endpoints:

- `GET /`
- `POST /predict`

## Deploy

1. Create a new Hugging Face Space with `Docker` SDK.
2. Copy the contents of this folder into the Space repository root.
3. Add these Space secrets or variables:
   - `API_BASE_URL`
   - `MODEL_NAME`
   - `HF_TOKEN`
4. Push to the Space repository.

## Local run

```bash
docker build -t sentryx-hf-space .
docker run --rm -p 7860:7860 \
  -e API_BASE_URL="$API_BASE_URL" \
  -e MODEL_NAME="$MODEL_NAME" \
  -e HF_TOKEN="$HF_TOKEN" \
  sentryx-hf-space
```
