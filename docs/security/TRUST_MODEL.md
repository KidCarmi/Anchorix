# Trust Model — Anchorix v0.1

This document records the trust boundaries and assumptions Anchorix makes.
Operators MUST review these before deploying.

## Trust Boundaries

```
+---------------------------+        +----------------------------+
| Operator workstation      |  TLS   | Control plane (Linux host) |
| - Browser, UI session     | <----> | - API + UI server          |
+---------------------------+        | - PostgreSQL (same host or |
                                     |   trusted network)         |
+---------------------------+  TLS   +-------------+--------------+
| Windows endpoints         |  +----------------- |
| - anchorix-agent service  |  pinned             |
+---------------------------+  fingerprint        v
                                            +-----+--------+
                                            | PostgreSQL   |
                                            +--------------+
```

## Assumptions

| Assumption                                                              | Why we make it                                | If violated                                |
| ----------------------------------------------------------------------- | ---------------------------------------------- | ------------------------------------------ |
| The control plane host is trusted by the operator.                      | We do not isolate against a hostile host.      | Full compromise of the platform.           |
| The PostgreSQL database is on a trusted network.                        | v0.1 does not encrypt application-level rows.  | Data exposure for an attacker on the wire. |
| Operators access the UI from authenticated sessions over TLS.           | Sessions and CSRF protections rely on it.      | Session hijacking, CSRF.                   |
| Agents are installed by the operator on Windows endpoints they own.     | Enrollment requires an operator-issued token.  | Rogue agents or noisy inventory.           |
| Agents trust the control plane's TLS identity (pinned at enrollment).   | Defends against MITM after enrollment.         | MITM on agent traffic.                     |
| The control plane does NOT trust agents to assert their own identity    | Defense-in-depth.                              | Spoofed agents.                            |
| beyond the cryptographic material established at enrollment.            |                                                |                                            |
| The deployer fronts the stack with a TLS-terminating reverse proxy.     | v0.1 does not ship an opinionated TLS story.   | Plain-text traffic in production.          |

## What we explicitly do **not** trust

- The agent host's runtime environment (it may be malware-affected).
  We bound blast radius via least privilege and the no-private-key rule.
- The user-supplied content of certificates (subject, SANs, friendly
  name). All such content is treated as untrusted and escaped on render.
- The network path between agent and control plane. Pinned trust is
  required after enrollment.

## Out of v0.1 trust scope

- Multi-tenant isolation between organizations.
- Hostile DBA scenarios.
- Hostile control-plane host scenarios.
- Detached audit log integrity (off-host signing / shipping).

These are tracked in `THREAT_MODEL.md` §4 and will be addressed in later
phases. Until then, operators are responsible for the corresponding
operational controls.
