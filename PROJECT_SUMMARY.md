# Anchorix Project Summary

**Machine Identity & Certificate Operations Platform.**

## Core Philosophy
> **Visibility before automation.**

Anchorix is a control plane that gives organizations visibility into their certificates and machine identities **without replacing their PKI**. It discovers, inventories, and risk-scores certificates across an estate, and integrates with existing trust infrastructure.

## Project Goals (v0.1)
- Give operators **visibility** into certificates across their estate.
- Provide a **stable, extensible foundation** for future automation.
- Avoid **vendor lock-in** to any specific PKI.
- Be **operationally simple** to deploy, observe, and reason about.
- Be **secure by default** even before any automation features land.

## Non-Goals (v0.1)
- Acting as a Certificate Authority.
- Storing or transmitting private keys.
- Automating renewal, revocation, or rotation.
- Linux / macOS / Kubernetes agent support.
- Multi-tenancy beyond a single organization row.
- HA / multi-region clustering.

## High-Level Architecture
- **Control Plane**: A Go modular monolith exposing a REST API. Stateless, with all durable state in PostgreSQL.
- **Windows Agent**: A Go binary run as a Windows service that enumerates certificates and sends inventory to the control plane.
- **Frontend**: A React + Tailwind SPA.
- **Storage**: PostgreSQL.

## Engineering Rules (CLAUDE.md)
The `CLAUDE.md` document serves as the binding engineering, security, and architecture rulebook. Key rules include:
- No plaintext secrets anywhere.
- No private key exfiltration.
- Least privilege everywhere.
- TLS for all agent ↔ control-plane traffic.
- Authenticated agent enrollment.
- Audit everything that changes state.
- Provider-based design for integrations.
- Strict decoupling rules (e.g., `domain → httpapi` is forbidden).
- Append-only database migrations.
