# SPA Runtime Recipe

This is the canonical pattern for shipping a static site (SPA, Next.js
static export, plain HTML) on the `ghcr.io/hanzoai/spa` runtime. Every
new static site in our stack follows this recipe verbatim — no bikeshedding.

The runtime contract lives in `README.md` + `main.go`. This file is the
copy-paste recipe.

## When to use

Use `hanzoai/spa` for any of:

- Vite / SvelteKit / SolidStart SPAs (`dist/`)
- Next.js static export with `output: 'export'` (`out/`)
- Plain HTML/CSS sites (`public/`)
- Multi-app monorepos that ship N SPAs from one binary (`MULTI_APP=true`)

Do NOT use it for:

- Server-rendered Next.js (use the Next.js standalone runtime)
- Anything with a backend that needs to run inside the same container

## Single-app Dockerfile

Drop this verbatim into the site repo as `Dockerfile`:

```dockerfile
# Static SPA runtime — see https://github.com/hanzoai/spa
FROM ghcr.io/hanzoai/spa:1.2.0
COPY out/ /public/
```

Vite/SvelteKit projects use `dist/`; Next.js static export uses `out/`;
plain HTML sites use `public/`. Pick one and stick with it. Pin a semver
tag — never `:latest` in a Dockerfile that ships to production.

If your build needs a build stage in the same image (no separate CI build
job), use the multi-stage form:

```dockerfile
FROM node:22-alpine AS build
WORKDIR /app
COPY . .
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build

FROM ghcr.io/hanzoai/spa:1.2.0
COPY --from=build /app/out /public
```

## Multi-app Dockerfile (monorepo)

For a monorepo that ships multiple SPAs under one image (one per
hostname prefix), use `MULTI_APP=true`:

```dockerfile
FROM ghcr.io/hanzoai/spa:1.2.0
COPY --from=build /app/apps/superadmin/dist  /public/superadmin
COPY --from=build /app/apps/ats/dist         /public/ats
COPY --from=build /app/apps/bd/dist          /public/bd
COPY --from=build /app/apps/ta/dist          /public/ta
ENV MULTI_APP=true
ENV DEFAULT_APP=superadmin
```

Hostname prefix routing:

| Hostname            | Served from              |
|---------------------|--------------------------|
| `ats.example.com`   | `/public/ats/`           |
| `bd.example.com`    | `/public/bd/`            |
| `ta.example.com`    | `/public/ta/`            |
| anything else       | `/public/$DEFAULT_APP/`  |

## Caller workflow (`.github/workflows/docker.yml`)

This is the canonical filename — never `docker-v2.yml`, never
`build-and-push.yml`. The reusable mirrors are identical content; pick
the one matching your org:

| Org repo prefix     | Reusable workflow                                |
|---------------------|--------------------------------------------------|
| `hanzoai/*`         | `hanzoai/.github/.github/workflows/docker-build.yml@main` |
| `zooai/*`           | `zooai/.github/.github/workflows/docker-build.yml@main`   |
| `luxfi/*`           | `luxfi/.github/.github/workflows/docker-build.yml@main`   |

If your build needs a JS build step before the docker stage (the
common case for Next.js / Vite), you have two options.

**Option A — let the Dockerfile build it (simpler, more cache-friendly).**
Use the multi-stage Dockerfile shown above and a minimal caller:

```yaml
# .github/workflows/docker.yml
name: Docker
on:
  workflow_dispatch:
  push:
    branches: [main]
    tags: ['v*']
jobs:
  docker:
    uses: zooai/.github/.github/workflows/docker-build.yml@main
    with:
      image: ghcr.io/zooai/<your-site>
      runner-amd64: zoo-build-linux-amd64
      runner-deploy: zoo-build-linux-amd64
      platforms: "linux/amd64"
    secrets: inherit
```

**Option B — pre-build outside Docker, then COPY artifacts.**
Use the simple Dockerfile (`FROM ghcr.io/hanzoai/spa:1.2.0` + `COPY out/`)
and add a `pre-build-command:`:

```yaml
jobs:
  docker:
    uses: zooai/.github/.github/workflows/docker-build.yml@main
    with:
      image: ghcr.io/zooai/<your-site>
      runner-amd64: zoo-build-linux-amd64
      runner-deploy: zoo-build-linux-amd64
      platforms: "linux/amd64"
      pre-build-command: |
        corepack enable
        pnpm install --frozen-lockfile
        pnpm build
    secrets: inherit
```

### Hard rules

- **No top-level `permissions:` block** in the caller. `secrets: inherit`
  silently drops if the caller declares its own permissions. Hard-learned.
- Caller filename is `docker.yml` (single canonical name per repo). No
  parallel `-v2`, `-new`, `-old` files.
- `:latest` is never written into a Kubernetes manifest. Tag a semver,
  reference that semver in the manifest. Always.
- Match runner labels to the GitHub org of the caller repo:
  | Repo org    | Runner label                   |
  |-------------|--------------------------------|
  | `hanzoai/*` | `hanzo-build-linux-amd64`      |
  | `zooai/*`   | `zoo-build-linux-amd64`        |
  | `luxfi/*`   | `lux-build-linux-amd64`        |
  GitHub-hosted runners (`ubuntu-latest`) are not a permitted fallback.
- `linux/amd64` only until DOKS ships arm64 droplets. The reusable
  defaults to multi-arch; static sites override to amd64-only.

## Tagging

Tag a `v0.1.0` to publish the first image. Bump per
[semver](https://semver.org/) on subsequent changes. CI tags the image
`X.Y.Z` (no `v` prefix), `X.Y`, `X`, plus `latest` on the default branch.
Manifest references the exact `X.Y.Z` tag.

```bash
git tag -a v0.1.0 -m "Initial release"
git push origin v0.1.0
```

## Kubernetes manifest

Drop this into `~/work/lux/universe/k8s/<namespace>/<site>.yaml` and
`kubectl apply -f`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: <site>
  namespace: <namespace>
  labels:
    app: <site>
spec:
  replicas: 1
  selector:
    matchLabels:
      app: <site>
  template:
    metadata:
      labels:
        app: <site>
    spec:
      imagePullSecrets:
        - name: ghcr-luxfi
      containers:
        - name: spa
          image: ghcr.io/<org>/<site>:0.1.0   # NEVER :latest
          ports:
            - containerPort: 3000
          readinessProbe:
            httpGet: { path: /health, port: 3000 }
            initialDelaySeconds: 2
            periodSeconds: 10
          livenessProbe:
            httpGet: { path: /health, port: 3000 }
            initialDelaySeconds: 10
            periodSeconds: 30
          resources:
            requests: { cpu: 50m,  memory: 32Mi }
            limits:   { cpu: 200m, memory: 128Mi }
---
apiVersion: v1
kind: Service
metadata:
  name: <site>
  namespace: <namespace>
spec:
  type: ClusterIP
  ports:
    - port: 3000
      targetPort: 3000
  selector:
    app: <site>
---
apiVersion: hanzo.ai/v1alpha1
kind: IngressRoute
metadata:
  name: <site>
  namespace: <namespace>
spec:
  entryPoints: [websecure]
  routes:
    - match: Host(`<site>.example`) || Host(`www.<site>.example`)
      kind: Rule
      services:
        - name: <site>
          port: 3000
  tls:
    certResolver: letsencrypt
```

The image pull secret `ghcr-luxfi` is the canonical name across
namespaces in `do-sfo3-lux-k8s` and `do-sfo3-hanzo-k8s`. Copy it into
new namespaces with `kubectl get secret ghcr-luxfi -n <src> -o yaml |
sed 's/namespace: <src>/namespace: <dst>/' | kubectl apply -f -`.

## DNS

Point apex + www at the cluster's ingress LB. Either:

1. **Origin TLS via Let's Encrypt** — A record (proxied=false), Traefik
   `certResolver: letsencrypt` issues at the origin. Use this when the
   namespace's cert volume isn't rate-limited.
2. **CF edge TLS** — A record (proxied=true), Cloudflare terminates TLS at
   the edge and the origin sees plain HTTP. Use this if LE is in 429-ban
   territory or you want CF's WAF / caching for free.

`do-sfo3-lux-k8s` ingress LB is `134.199.138.27` (`hanzo-ingress` in
`lux-system`).

## Verify

```bash
curl -sI https://<site>           # 200 + brand-correct title in body
curl -sI https://www.<site>       # 200 (matched by IngressRoute)
curl -s   https://<site>/health   # {"status":"ok"}
kubectl get cert -n <namespace>   # all True (origin LE) or empty (CF edge)
```

## Done

Ship. Move on.
