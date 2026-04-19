<p align="center"><img src="https://raw.githubusercontent.com/ccvass/swarmex/main/docs/assets/logo.svg" alt="Swarmex" width="400"></p>

[![Test, Build & Deploy](https://github.com/ccvass/swarmex-rbac/actions/workflows/publish.yml/badge.svg)](https://github.com/ccvass/swarmex-rbac/actions/workflows/publish.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

# Swarmex RBAC

Docker socket proxy with role-based access control and JWT authentication via Authentik.

Part of [Swarmex](https://github.com/ccvass/swarmex) — enterprise-grade orchestration for Docker Swarm.

## What It Does

Acts as a secure proxy in front of the Docker socket, enforcing role-based access control. Authenticates requests via JWT tokens issued by Authentik and maps users to roles (admin, operator, viewer) with granular API permissions.

## Labels

This is an infrastructure controller — no service labels required. Access is controlled via JWT claims and role configuration.

## How It Works

1. Intercepts all requests to the Docker socket.
2. Validates the JWT token from the `Authorization` header against Authentik.
3. Extracts the user identity and maps it to a configured role.
4. Checks if the role has permission for the requested Docker API endpoint.
5. Proxies allowed requests to the Docker socket; denies unauthorized ones.

## Quick Start

```bash
docker service create \
  --name swarmex-rbac \
  --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
  -e AUTHENTIK_URL=https://auth.example.com \
  -p 2375:2375 \
  ghcr.io/ccvass/swarmex-rbac:latest
```

## Verified

JWT token for `akadmin` → admin role → access granted. Anonymous request → access denied.

## License

Apache-2.0
