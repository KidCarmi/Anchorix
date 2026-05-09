# Branching & Pull Request Policy

This document is binding for every contributor — human or AI. It covers
how branches are created, named, merged into Anchorix, and which CI gates
must pass before a merge.

> If this policy conflicts with [`CLAUDE.md`](../CLAUDE.md), CLAUDE.md
> wins. Where they overlap, both apply.

## 1. Default Branch

- The default branch is **`main`**.
- `main` is **protected** and the long-term source of truth.
- A Claude-generated feature branch is **never** the default branch and
  is **never** the source of truth, even temporarily.
- Required protections on `main`:
  - direct pushes are forbidden (humans and Claude)
  - force pushes are forbidden
  - branch deletion is forbidden
  - merges to `main` only happen via pull request
  - merges to `main` require:
    - all required CI checks green (see §2)
    - at least one approving review (no self-approval)
    - a linked issue or rationale in the PR body
  - the merge strategy is squash-merge (one commit per PR on `main`)
  - `main` is read-only outside of PR merges; even maintainers go
    through a PR

Releases are cut from `main` only.

### One-time bootstrap exception

Anchorix was incubated on the Claude session branch
`claude/anchorix-foundation-hN43r`. The very first push of `main` —
seeded from that branch's tip — is the **single** authorized direct
push to `main` in the project's history. Every subsequent change to
`main` must go through a pull request. The session branch becomes a
normal feature branch from that point forward and may be deleted once
GitHub default-branch and protection settings are in place (§9).

## 2. CI Is Mandatory Before Merge

Every PR — human-authored or Claude-authored — runs the same CI suite.
**Failed quality, build, or security checks block the merge.** The full
authoritative list lives in [`CLAUDE.md`](../CLAUDE.md) §11 and the
workflow files under [`.github/workflows/`](../.github/workflows/).

Mandatory blocking gates:

- `gofmt`, `go vet`, `go test`, `go build` (backend and `agent/windows`,
  including a `GOOS=windows` cross-compile for the agent)
- `npm ci`, `npm run lint`, `npm run typecheck`, `npm test`,
  `npm run build` (frontend)
- CodeQL (Go and JavaScript/TypeScript)
- `govulncheck` for both Go modules
- `npm audit --audit-level=high`
- Trivy filesystem scan (HIGH/CRITICAL fail)
- Gitleaks secret scan
- Dependency Obituary — direct deps only, threshold 60
  (scans `frontend/package.json`, not the lockfile; transitive
  health is not gated, transitive CVEs are covered by `npm audit`
  and Trivy)
- `docker compose config` validation
- Backend and frontend Docker image builds
- Runtime smoke (`/healthz` + `/readyz`)

Branch protection on `main` is configured to require every check above.
None of these checks are advisory.

A failing security check (CodeQL, govulncheck, npm audit, Trivy,
Gitleaks, Dependency Obituary) must **not** be worked around by lowering
the threshold or skipping the job. The fix is to address the underlying
finding, or — if it is genuinely a false positive — to suppress it via
the tool's documented suppression mechanism with rationale in the PR
body.

Blocking checks must remain **deterministic, reliable, and
reproducible**. If a blocking check becomes flaky, fix the check.

## 3. Feature Branches

All work happens on a feature branch off the latest `main`.

### Naming

| Branch type        | Pattern                                | Example                                  |
| ------------------ | -------------------------------------- | ---------------------------------------- |
| Human contributor  | `<author>/<short-topic>`               | `alice/agent-enrollment`                 |
| Claude session     | `claude/<short-topic>-<random-suffix>` | `claude/anchorix-foundation-hN43r`       |
| Hotfix (post-tag)  | `hotfix/<short-topic>`                 | `hotfix/cve-2026-12345`                  |
| Release branch     | `release/vX.Y`                         | `release/v0.1`                           |

Rules:

- Lower-case, kebab-case slugs. No spaces.
- Keep slugs short and descriptive.
- One topic per branch. If scope grows, open a follow-up branch.

### Lifetime

- Branches are short-lived. Open a PR within a few days of starting work.
- A branch that has been merged via PR is **deleted** (server-side and
  local). Do not reuse a merged branch name.
- A branch that has been abandoned for more than 30 days without an open
  PR may be deleted by maintainers.

## 4. Claude Branches Are PR-Only

Claude (the AI assistant) is constrained to the same rules as any other
contributor, with two additional requirements:

1. **Claude never pushes to `main`.** Every Claude session works on a
   `claude/<topic>-<suffix>` branch and opens a pull request.
2. **Claude does not reuse a feature branch as if it were `main`.**
   Treat the feature branch as a single-purpose work area. When the PR
   merges, the branch is gone; new work needs a new branch off `main`.

Claude branches are subject to **every** CI gate listed in §2. A red
gate blocks merge regardless of who authored the PR. Claude does not
bypass branch protection or self-approve a review.

A session prompt that tells Claude to "develop on `claude/<branch>`" is
authorization to commit and push to **that branch only**. It is **not**
authorization to:

- push to `main`
- delete or force-push someone else's branch
- merge a PR
- self-approve a review
- weaken or disable any CI gate to make a PR pass

## 5. Pull Requests

A pull request must include:

- A short, imperative title (under 70 chars).
- A summary that explains **why** the change is needed.
- A link to the related issue or roadmap phase, if applicable.
- A test plan checklist.
- Any threat-model entry required by [`CLAUDE.md`](../CLAUDE.md) §6.10.

PR-time review checklist (binding):

- Does the PR follow `CLAUDE.md`? (If not, the PR loses.)
- Are tests added or updated for behavior changes?
- Are docs updated (`ARCHITECTURE.md`, `docs/api/REST_API.md`,
  `docs/security/...`) when the public surface or trust boundary moves?
- Is anything in the diff a "convenience" violation of a CLAUDE.md rule?
- Did all CI gates pass on the latest commit?

## 6. Releases

Releases are tagged `vX.Y.Z` from `main`. Tags are immutable. Release
notes live under `docs/releases/` (path reserved; created with first
release).

## 7. Hotfixes

If a fix is needed against an already-tagged release:

1. Branch `hotfix/<topic>` from the release tag.
2. Open a PR targeting the relevant `release/vX.Y` branch (or `main` if
   the affected version is still the latest).
3. After merge, cherry-pick into `main` if it has diverged.

## 8. What This Means in Practice

- Don't `git push origin main`. Open a PR.
- Don't keep working on a branch that has already merged. Start a new one.
- Don't ask Claude to bypass these rules; the rules apply to Claude.
- Don't approve your own PR.
- Don't merge a PR with red CI.
- Don't disable a CI gate to land a PR.

## 9. Repository Setup Status (manual GitHub steps)

The Git side of branch normalization is automated by this PR / commit:

- [x] `main` branch exists at the foundation tip.
- [x] `main` contains the v0.1 foundation, naming cleanup, envelope
      consolidation, and CI workflows.
- [x] `docs/BRANCHING.md` and `CLAUDE.md` §11 document the policy.
- [x] CI workflows under `.github/workflows/` enforce every required
      gate on PRs targeting `main`.

The following items can only be set from the GitHub UI / API and are
therefore the **repository owner's responsibility** to apply once `main`
exists on the remote:

1. **Set default branch to `main`.**
   `Settings → General → Default branch → switch to main`.
2. **Add a branch protection rule for `main`** (`Settings → Branches →
   Add rule → Branch name pattern: main`):
   - [x] Require a pull request before merging
     - [x] Require approvals: **1**
     - [x] Dismiss stale approvals on new commits
     - [x] Require review from Code Owners (when CODEOWNERS lands)
   - [x] Require status checks to pass before merging
     - [x] Require branches to be up to date before merging
     - [x] Required status checks (paste the exact job names CI emits):
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
   - [x] Require conversation resolution before merging
   - [x] Require linear history
   - [x] Do not allow bypassing the above settings (apply to admins)
   - [x] Restrict who can push to matching branches: nobody (PR-only)
   - [ ] Require signed commits (recommended; enable when contributors
         have signing keys configured)
3. **Disable force pushes and branch deletion** for `main`
   (covered by the protection rule above; double-check the toggles).
4. **Delete the bootstrap feature branch** (`claude/anchorix-foundation-hN43r`)
   once `main` is the default and contains the same content. This is
   not strictly required, but keeping a stale Claude branch around
   invites confusion about the source of truth.
5. **(Optional) Configure auto-merge** on PRs that pass CI and have an
   approving review.

If any of the items above are not applied, the policy in this document
is documentation-only and not enforced. The combination of `main`
existing + branch protection rules being applied is what makes the
policy real.
