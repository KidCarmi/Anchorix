# GitHub Actions Workflows

Each file here is a binding CI gate for Anchorix. **Every job is blocking** —
a red gate prevents merge to `main`. The full policy is in
[`CLAUDE.md`](../../CLAUDE.md) §11 and [`docs/BRANCHING.md`](../../docs/BRANCHING.md) §2.

| File                        | Trigger                       | Concurrency group     | Purpose                                                |
| --------------------------- | ----------------------------- | --------------------- | ------------------------------------------------------ |
| `ci.yml`                    | `pull_request`, push to main  | `ci-${{ github.ref }}`         | Code quality + Docker build + runtime smoke    |
| `codeql.yml`                | `pull_request`, push to main  | `codeql-${{ github.ref }}`     | SAST (Go + JavaScript/TypeScript)              |
| `security.yml`              | `pull_request`, push to main  | `security-${{ github.ref }}`   | govulncheck, npm audit, Trivy, Gitleaks        |
| `dependency-obituary.yml`   | `pull_request`, push to main  | `obituary-${{ github.ref }}`   | Direct-dep health gate (frontend/package.json) |

## Job names (use these exact strings as required status checks)

- `backend (go)`
- `agent/windows (go)`
- `frontend`
- `docker (config + build + smoke)`
- `codeql (go)`
- `codeql (javascript-typescript)`
- `govulncheck (backend)`
- `govulncheck (agent/windows)`
- `npm audit (frontend)`
- `trivy (filesystem)`
- `gitleaks`
- `dependency obituary`

## Dependency Obituary scope

`dependency obituary` runs against **`frontend/package.json`** — direct
dependencies only. This is a deliberate policy decision, documented in
[`CLAUDE.md`](../../CLAUDE.md) §11 and
[`docs/BRANCHING.md`](../../docs/BRANCHING.md) §2:

- Gating direct-dep abandonment / deprecation: this job (threshold 60).
- Gating transitive CVEs: `npm audit (frontend)` and `trivy (filesystem)`.
- Gating transitive dep *health* (abandonment, deprecation): **not gated
  for v0.1.** The npm long tail of tiny stable utilities produces too
  much noise without commensurate signal. We may extend later, but only
  by amending CLAUDE.md §11.

The threshold is fixed at 60. Lowering it, switching the gate to
`continue-on-error`, or adding a per-package allowlist are all
forbidden by CLAUDE.md.

## Adding a new check

1. Decide whether the check is **deterministic, reliable, and reproducible**
   on every run. If not, it does **not** join the blocking set
   (CLAUDE.md §11).
2. Add the job to the most appropriate workflow file (don't create a
   one-job workflow without reason).
3. Update this table and the required-checks list above.
4. Update `docs/BRANCHING.md` §9 with the new required check name.
5. Update `CLAUDE.md` §11 with the new gate.

## Removing a check

A blocking check can be removed only by amending CLAUDE.md §11 and
documenting the rationale in the PR description.
