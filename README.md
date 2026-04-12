# hanzoai/spa

Zero-config SPA server. Drop your build output and run.

```dockerfile
FROM ghcr.io/hanzoai/spa
COPY dist /public
```

That's it. No flags, no config files, no Node.js.

## What it does

- **SPA mode always on** — `index.html` served for all routes
- **Smart caching** — hashed assets (Vite `index-DByAis3x.js`) get 1 year immutable, `index.html` gets no-cache
- **Pre-compressed** — serves `.br` and `.gz` files automatically
- **Security headers** — HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Health check** — `GET /health` → `{"status":"ok"}`
- **Scratch-based** — ~5MB image, zero attack surface

## Environment

| Var | Default | Description |
|-----|---------|-------------|
| `PORT` | `3000` | Listen port |
| `ROOT` | `/public` | Static files directory |

## Usage

```bash
# Local
go run .

# Docker
docker build -t spa .
docker run -v ./dist:/public -p 3000:3000 spa

# Production (multi-stage)
FROM node:22-alpine AS build
WORKDIR /app
COPY . .
RUN pnpm install && pnpm build

FROM ghcr.io/hanzoai/spa
COPY --from=build /app/dist /public
```
