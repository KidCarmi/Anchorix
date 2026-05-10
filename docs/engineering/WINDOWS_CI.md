# Windows CI Plan — Real Agent Validation

**Status:** planned for Phase 6 (per `ROADMAP.md`); not added to the
required-checks set yet.
**Source of truth for binding rules:**
[`CLAUDE.md`](../../CLAUDE.md) §11 (Windows CI subsection), §18
(Robustness), §8.11 (Outbound Client Rules).
**Owner at activation:** assigned in the PR that introduces the job.

## Goal

The current `agent/windows (go)` job cross-compiles with `GOOS=windows
GOARCH=amd64` from a Linux runner. That catches build-tag mistakes
but **does not** validate Windows-only behavior:

- the Service Control Manager wiring,
- certificate-store enumeration via `crypt32.dll`,
- TLS verification under SChannel,
- file ACLs on `%ProgramData%\Anchorix\agent\identity.json`,
- service start/stop signal handling.

Windows CI exists to validate those at every PR, end-to-end against
a containerized control plane, with **no fakery on critical security
flows** (CLAUDE.md §11).

## Job Design

**Workflow file:** new top-level `agent (windows-latest)` job inside
`.github/workflows/ci.yml` (sibling to the existing `agent/windows
(go)` job; the cross-compile job stays — both are useful).

**Runner:** `windows-latest`.

**Triggers:** same as the rest of `ci.yml` — `pull_request`, push to
`main`. Subject to the same concurrency group.

**Required status check name (when activated):**
`agent (windows e2e)`. Exact spelling matters because branch
protection references it; it is added to
`.github/workflows/README.md` and `CLAUDE.md` §11 in the same PR
that activates the job.

## What the Job Validates

### 1. Native build

```powershell
cd agent\windows
go build .\...
```

The native build complements the Linux cross-compile. Together they
catch:
- syscall-only API usage that compiles cross-host but breaks at
  runtime,
- missing build-tag guards on Windows-only files,
- `cgo`-dependent paths if any are added in the future.

### 2. Service install / uninstall smoke

```powershell
.\anchorix-agent.exe install   # planned in Phase 6
sc.exe query Anchorix          # status: STOPPED expected
sc.exe start Anchorix
# wait up to 30s for status: RUNNING
sc.exe stop  Anchorix
.\anchorix-agent.exe uninstall
```

Pass criteria: each command exits 0; SCM reports the expected state
transitions. Any `Start-Process` semantics relied upon are exercised.

### 3. End-to-end agent ↔ control plane (real network)

This is the meat of the job and the reason it exists.

The agent runs on the Windows runner; the control plane and its
PostgreSQL must be reachable to it over real network sockets. The
exact topology that delivers that is **not chosen here** — running
Linux service containers on `windows-latest` is not a reliably
supported pattern across GitHub-hosted runner images, so the
implementing PR must pick and prove a topology before this job
becomes blocking.

#### Topology decision (deferred to the implementing PR)

The Windows E2E job must choose **one** validated topology:

1. **Run the control plane directly on the Windows runner** with a
   reachable PostgreSQL service (PostgreSQL launched as a Windows
   service or as a `windows`-image container; the API binary built
   for `GOOS=windows` and started as a background process).
2. **Use a separate Linux job (or containerized backend) and expose
   it to the Windows test job** through a supported GitHub Actions
   topology — for example a job-to-job artifact handoff combined
   with a tunnelled service exposed via a documented GitHub-hosted
   network path, or a self-hosted runner pair joined by an
   internal network.
3. **Build a dedicated test harness** that starts the backend
   binary on Windows for CI only — packaged minimally (no Docker
   on the Windows runner), exercising exactly the agent ↔ control
   plane surface this job needs. The harness lives under
   `agent/windows/test/harness/` and is reviewed independently.

The chosen topology must be **proven in the implementation PR**
(stable runs across at least the documented green-streak window in
[`CI_PLAN.md`](./CI_PLAN.md)) **before** the job becomes blocking.
A topology that flakes is not a topology — see CLAUDE.md §11
(deterministic / reliable / reproducible).

Whichever topology is chosen, the rest of this document
(assertions, fixtures, fail-closed behavior) applies unchanged —
the agent's view of the wire is the same.

Smoke assertions:

| Step                                  | Assertion                                                                            |
| ------------------------------------- | ------------------------------------------------------------------------------------ |
| Issue enrollment token via API        | `POST /api/v1/agents/enrollment-tokens` returns 201 with a single-use token          |
| Configure agent and start service     | `ANCHORIX_AGENT_CONTROL_PLANE_URL` set; service reaches RUNNING                      |
| Agent enrolls                         | One `agents` row appears with status `active` within 30s                             |
| Agent heartbeats                      | `last_seen_at` updates at least twice within 90s                                     |
| Agent uploads inventory               | One `certificates` row + at least one `certificate_observations` row, all metadata-only — no PEM that contains private-key markers |
| Audit                                 | `audit_events` rows exist for `agent_enrolled` and the operator-issued enrollment token |
| TLS pinning                           | After enrollment, agent rejects a control plane reachable on the same DNS but with a different cert (test by swapping cert and asserting agent stays in `pending_enrollment` / refuses) |

### 4. Retry / offline behavior (limited scope at v0.1)

For v0.1 Windows CI we validate the **happy path** + one targeted
offline scenario:

- Stop the api container while the agent is running. Heartbeat fails;
  agent backs off (does not crash, does not spin). Restart the api;
  agent recovers within one heartbeat interval.

We do not exhaustively fuzz the retry policy in v0.1 — that's the
unit-test surface in `agent/windows/internal/transport`. Windows CI
just confirms the loops actually run on Windows.

## What Is Real vs. What Is Mocked

| Real (no mocks allowed)                              | Mocked / fixtured (acceptable)                       |
| ----------------------------------------------------- | ----------------------------------------------------- |
| Enrollment over HTTPS on real sockets                 | The set of certificates discovered (we ship a fixed  |
| TLS handshake + control-plane fingerprint pinning     | fixture cert into `LocalMachine\My` at job start so   |
| `agents.UpsertAgent` SQL path                         | discovery has stable input)                           |
| Heartbeat loop and timing behavior on Windows         | The control plane's risk evaluation rules            |
| Inventory upload payload shape on the wire            | (out of scope for PR-002–PR-004; not exercised here)  |
| Audit event writes                                    |                                                       |
| Service install/uninstall via SCM                     |                                                       |

CLAUDE.md §11 forbids faking critical security flows. Enrollment,
TLS, and identity binding are critical and are exercised end-to-end.

## Minimum Acceptable v0.1 Coverage

When the Windows CI job is activated as a required check, it must at
minimum cover:

1. Native Windows build of `agent/windows` and its tests.
2. Service install/start/stop/uninstall round-trip.
3. Enrollment + first heartbeat + first inventory upload, all
   end-to-end.
4. TLS-pinning negative test (different cert, agent refuses).
5. One reconnect-after-outage check.

Anything beyond this is welcome but not required for the gate to
become blocking.

## Determinism / Reliability

- The fixture certs used by discovery are committed under
  `agent/windows/test/fixtures/` (planned). Their existence is
  byte-stable, so the discovered-set is deterministic.
- The control-plane container is pinned to a specific image hash,
  not `latest`.
- All timeouts are bounded and explicit. The job has a workflow-level
  `timeout-minutes: 15` cap.
- No reliance on external network beyond the GitHub-hosted runner
  reaching the GitHub Actions infrastructure itself. No public DNS
  lookups in test code.

If the job becomes flaky, the answer is to fix the underlying race or
fixture, never to wrap with retries (CLAUDE.md §11 / `CI_PLAN.md`).

## What This Plan Does NOT Cover

- MSI installer signing — comes with Phase 6 release plumbing.
- Windows kernel-mode anything — out of v0.1 scope.
- Group Policy installation patterns — operator-side concern.
- `.NET` — the agent is pure Go; no .NET runtime dependency.
- Code signing of the agent binary — tracked in
  [`AGENT_HARDENING.md`](./AGENT_HARDENING.md).
