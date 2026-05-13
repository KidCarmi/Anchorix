# Hardening Backlog

This file tracks **real** follow-up engineering items surfaced during
the post-PR-002 hardening pass (PR-005). Each entry is small enough
to land in a focused PR but was deferred from PR-005 to keep that PR
documentation-only.

**This is not a TODO list.** Per CLAUDE.md §19, TODO-driven
architecture is forbidden. Each entry below has a clear scope, a
recommended PR title, and a rationale for why it wasn't fixed in
PR-005. New items get added only when the work is real, scoped, and
justifiable.

**Source of truth for rules:** [`CLAUDE.md`](../../CLAUDE.md). If
this file and CLAUDE.md disagree, CLAUDE.md wins.

## Open Items

### H-006 — Reinstall / rebind / credential rotation design

- **Title:** `design(enrollment): reinstall flow + credential rotation`
- **Risk:** medium (UX + ops; not a v0.1 security risk because we
  fail closed). PR-013 documents `install_id` as a single-use
  identity binding. A second enrollment with the same
  `install_id` is rejected with `enrollment_rejected` and an
  `install_id_already_enrolled` audit reason. That is the safe
  default but it forces operators to revoke the existing agent
  row + redeploy with a fresh `install_id` for every legitimate
  reinstall. An explicit reinstall flow (probably an admin-issued
  reinstall token + credential rotation that issues a new
  `agent_credential` and revokes the old one) is a real
  operational need before Phase 3 fleets get large.
- **Scope:** **design first**. This is the largest of the four
  items; the implementation PR depends on agreed semantics.
  Specifically: who authorizes the rebind, how the agent
  authenticates the reinstall (the original installer is gone),
  what the rotation envelope looks like, and how rotation
  composes with the future agent-credential auth middleware
  (H-007). Land a design doc under `docs/engineering/` before
  cutting an implementation PR.
- **Recommended PR:** First a design doc (`docs/engineering/
  AGENT_REINSTALL.md`); then an implementation PR.
- **Reason not fixed now:** the v0.1 fail-closed posture is
  documented and tested; rebind is operational sugar that must
  not paper over the trust model. Needs a written contract.
- **References:** CLAUDE.md §6, §19; `docs/engineering/
  AGENT_ENROLLMENT.md` "Reinstall behavior in v0.1".

### H-007 — Agent-credential authentication middleware

- **Title:** `feat(backend): agent-bearer authentication middleware`
- **Risk:** high (security). PR-013 issues
  `agent_credential` at enrollment and stores it as SHA-256.
  Nothing **uses** the credential yet — the heartbeat and
  inventory endpoints are still 501 stubs. Phase 3 wires them up,
  and the first thing they need is an `Authorization: Bearer
  <agent_credential>` middleware that:
    - reads the header,
    - hashes the supplied value,
    - looks up the agent by `credential_hash`,
    - validates the agent's `status`,
    - attaches `*enrollment.Agent` to ctx for the handlers.
  Without this middleware, no real agent-side endpoint can ship,
  and the bearer credential issued today is unused.
- **Scope:** small-medium. New file
  `internal/httpapi/middleware/agent_auth.go` consuming an
  `AgentAuthenticator` interface from `internal/enrollment` (the
  service looks up the credential hash via a new repo method).
  Constant-time-equal not strictly required for SHA-256 of
  32-byte random tokens (negligible timing surface) but cheap to
  add. Routes for `POST /agents/{id}/heartbeat` and
  `POST /agents/{id}/inventory` move behind it in the same PR or
  the next one (Phase 3 work).
- **Recommended PR:** `feat(backend): agent-credential auth middleware (H-007)`
- **Reason not fixed now:** PR-013's scope was issuing the
  credential. Consuming it requires at least one real agent
  endpoint, which begins Phase 3.
- **References:** CLAUDE.md §6 (auth), §8.6 (decoupling — the
  middleware sits at httpapi, depends on a domain interface
  owned by enrollment).

### H-008 — Future mTLS / device crypto identity hardening

- **Title:** `design(security): Phase 6 mTLS migration for agent identity`
- **Risk:** high (security; Phase 6, not v0.1). The v0.1
  identity is a bearer credential. CLAUDE.md §6.4 commits to
  mTLS in Phase 6: each agent presents a client certificate, the
  control plane pins it at enrollment, and the agent's identity
  becomes its key pair rather than a long-lived shared secret.
  Migration 0002 already relaxed
  `agents.public_key_fingerprint` to NULL specifically so a
  future mTLS migration can populate it for every agent without a
  schema reshape. The design + migration are deferred but should
  be tracked formally.
- **Scope:** **design first**. Enrollment flow needs a key-pair
  generation step on the agent, a CSR to the control plane, an
  issuance flow (a built-in CA? a delegated PKI provider?), and
  a pinning model. The `internal/providers/pki/` package already
  exists for the provider abstraction. The agent side requires
  Windows-native key storage (CNG / DPAPI). The transition story
  matters: a fleet enrolled on bearer must be able to upgrade
  in-place without re-deploying installers.
- **Recommended PR:** First a design doc
  (`docs/security/AGENT_MTLS.md`); then a migration that
  populates `public_key_fingerprint`; then the issuance flow.
- **Reason not fixed now:** Phase 6 boundary; the bearer
  credential is the documented v0.1 primitive and the migration
  preserves the schema for the upgrade.
- **References:** CLAUDE.md §6.4 (mTLS by Phase 6); §10 (provider
  abstraction); `docs/engineering/AGENT_ENROLLMENT.md` Schema
  notes section.

## How items get added or removed

- **Added** when a deferred follow-up has clear scope, a real risk,
  and a recommended PR shape. "We might want to look at X someday"
  is not an entry; design speculation lives in
  `docs/architecture/EVOLUTION.md`.
- **Removed** when the recommended PR has merged. Crossing the entry
  out is not enough — delete it. The merge commit + this file's git
  history are the audit trail.
- **Promoted** to a CLAUDE.md amendment if the item turns out to
  encode a binding rule. CLAUDE.md is the constitution; this file is
  the punch list.
