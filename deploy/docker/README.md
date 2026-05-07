# Dockerfiles

Service Dockerfiles live next to their source code:

- Backend control plane → [`backend/Dockerfile`](../../backend/Dockerfile)
- Frontend UI → [`frontend/Dockerfile`](../../frontend/Dockerfile)

This directory is reserved for shared Docker assets that are not specific
to a single service (helper scripts, CI build images, base-image pinning).

For now it is intentionally empty.
