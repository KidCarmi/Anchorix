# Compose Overlays

This directory holds optional Docker Compose overlays for deploying Anchorix
in environments other than local development.

> The base `docker-compose.yml` at the repository root is **for development
> and demos only**. It does not terminate TLS, does not assume an external
> reverse proxy, and uses example credentials.

## Planned overlays (not yet implemented)

- `compose.proxy.yml` — adds a TLS-terminating reverse proxy (Caddy or Nginx)
  in front of the API and the static UI.
- `compose.prod.yml` — production-leaning overrides: pinned image tags,
  resource limits, read-only filesystems where possible, secret references
  via Docker secrets.
- `compose.observability.yml` — optional metrics scraping setup
  (out of scope for v0.1; placeholder so the path is reserved).

## Operator Responsibilities

Anchorix deliberately does **not** ship an opinionated TLS / ingress story.
Operators are expected to:

1. Front Anchorix with a reverse proxy they already operate.
2. Provide the proxy with a valid certificate (Let's Encrypt, internal CA,
   etc.).
3. Configure `ANCHORIX_PUBLIC_BASE_URL` to match the public URL.
4. Restrict access to `/healthz` and `/readyz` to internal networks.

See [`CLAUDE.md`](../../CLAUDE.md) §11 for the trust model assumptions that
apply to deployment.
