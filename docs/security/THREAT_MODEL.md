# Threat Model — Anchorix v0.1

Status: **draft** (will be revisited at the end of each roadmap phase).

## 1. Assets

| Asset                              | Sensitivity | Notes                                   |
| ---------------------------------- | ----------- | --------------------------------------- |
| Operator credentials               | High        | bcrypt hashed; never logged             |
| Agent enrollment tokens            | High        | single-use; only sha256 stored          |
| Agent identity material            | High        | private key never leaves the agent host |
| Certificate inventory metadata     | Medium      | not secret, but reveals attack surface  |
| Public certificate PEMs            | Low         | by definition public                    |
| Audit log                          | High        | integrity is critical                   |
| PostgreSQL data at rest            | High        | depends on operator's DB hardening      |
| Session cookies / tokens           | High        | HttpOnly, Secure, SameSite              |

**Out-of-scope (by design):** private keys. Anchorix never holds them.

## 2. Attacker Model

We design against the following adversaries in v0.1:

- **A1 — Network attacker (passive/active) on the agent ↔ control plane
  link.** Mitigated by HTTPS + pinned control-plane fingerprint and (in
  Phase 6) mTLS.
- **A2 — Compromised endpoint hosting an agent.** Bounded blast radius:
  cannot escalate beyond what one agent can do. Cannot read private keys
  belonging to other endpoints.
- **A3 — Compromised operator workstation.** Limited by session cookie
  scope and CSRF protections. Stolen cookies grant access until session
  expiry; we mitigate with short session lifetimes and re-auth on
  sensitive actions (Phase 6).
- **A4 — Internal attacker with read-only DB access.** Can observe
  metadata; cannot recover passwords (bcrypt) or enrollment tokens
  (sha256 only).
- **A5 — Supply-chain attacker.** Mitigations: pinned dependencies,
  SBOM in CI, container scanning, signed releases (target by v1.0).
- **Out of scope for v0.1:** nation-state physical attack on the
  control plane host; compromise of the underlying hypervisor.

## 3. Threats and Mitigations

### T1 — Private key exfiltration via the agent

- **Vector:** malicious or buggy agent build reads private key material
  from a Windows certificate store and uploads it.
- **Mitigation:** Agent code has no path that reads private keys
  (CLAUDE.md §6.2). The control plane validates inbound payloads and
  rejects anything containing a `BEGIN ... PRIVATE KEY` block
  (`internal/inventory.rejectPrivateKeyMaterial`). Schema has no column
  for private key material.

### T2 — Agent enrollment token replay

- **Vector:** attacker captures a token in transit or from the operator's
  clipboard and re-uses it to enroll a rogue agent.
- **Mitigation:** Tokens are single-use, short-lived (default 15m), and
  stored only as `sha256(token)`. Successful consumption marks
  `consumed_at`. Rejected attempts are audited.

### T3 — TLS downgrade / MITM between agent and control plane

- **Vector:** attacker terminates TLS at a proxy and inspects/modifies
  traffic.
- **Mitigation:** Agent pins the control-plane certificate fingerprint at
  enrollment. Phase 6 introduces mTLS with short-lived agent certs.

### T4 — SQL injection

- **Vector:** crafted query parameters reach SQL via string concatenation.
- **Mitigation:** All queries use parameter binding (CLAUDE.md §6.7).
  Code review and lint rules forbid string-built SQL.

### T5 — Audit log tampering

- **Vector:** attacker with DB access edits or deletes audit rows.
- **Mitigation:** Triggers reject `UPDATE` and `DELETE` on `audit_events`.
  v0.1 still trusts a DBA with sufficient privilege; future phases add
  off-host audit replication.

### T6 — Secret leakage in logs

- **Vector:** developer accidentally logs a session key, token, or PEM.
- **Mitigation:** Centralized logger with a redaction allow-list
  (`internal/logger/redact.go`). Heuristic redaction of any field name
  ending in `_token`, `_secret`, `_password`, `_key`. Code review on
  every PR that touches logging.

### T7 — Cross-site request forgery (CSRF)

- **Vector:** logged-in operator's browser is tricked into POSTing to the
  control plane.
- **Mitigation:** SameSite=Lax cookies plus per-form CSRF tokens for
  state-changing endpoints. Phase 1 implements both.

### T8 — Cross-site scripting (XSS)

- **Vector:** attacker-controlled certificate metadata renders as HTML
  in the UI.
- **Mitigation:** React's default escaping; no `dangerouslySetInnerHTML`
  in operator-facing components. CSP set on the static SPA host.

### T9 — Privilege escalation in operator UI

- **Vector:** operator role bypasses admin-only actions.
- **Mitigation:** Role checks happen in the API layer, not the UI. Audit
  events record actor + action + target for every state change.

### T10 — Provider configuration leaks credentials

- **Vector:** operator pastes a provider API key in a configuration field
  that ends up in logs or backups in plaintext.
- **Mitigation:** Provider credentials are stored via the `secrets`
  provider abstraction; v0.1 reads them from environment variables.
  The `providers.config` JSONB stores references, not raw secrets.

## 4. Open Questions / Future Work

- Off-host audit replication (write-ahead-log shipping or signed batches).
- mTLS rotation policy for agents.
- Hardware-backed key storage on the agent (Windows TPM / KSP) for the
  enrollment private key.
- Multi-tenancy isolation review when org boundaries get enforced.
