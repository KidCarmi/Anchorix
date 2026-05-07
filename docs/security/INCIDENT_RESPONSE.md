# Incident Response Runbook (Initial Draft)

This runbook is a starting point. Operators are expected to adapt it to
their organization's incident process.

## Severity

| Level    | Meaning                                                            |
| -------- | ------------------------------------------------------------------ |
| SEV-1    | Confirmed compromise of control plane, DB, or admin credentials.   |
| SEV-2    | Suspected compromise; rogue agent; secret leakage.                 |
| SEV-3    | Failed authentication spike; suspicious findings overrides.        |
| SEV-4    | Anomaly worth recording (e.g. unusual inventory diff).             |

## SEV-1 Playbook (control plane compromise suspected)

1. **Contain.** Block ingress to the control plane at the proxy.
2. **Rotate.** Rotate `ANCHORIX_SESSION_KEY`, all operator passwords, all
   agent enrollment tokens, and any provider credentials.
3. **Re-enroll.** Mark all agents `revoked` in DB; require re-enrollment.
4. **Snapshot.** Take a forensic snapshot of the host filesystem and DB.
5. **Audit.** Export the `audit_events` table to a write-once store.
6. **Investigate.** Look for unexpected admin actions, new users, new
   providers, finding suppressions during the incident window.
7. **Report.** Per organizational policy and regulatory obligations.
8. **Lessons learned.** File a CLAUDE.md amendment if the incident
   reveals a structural gap.

## SEV-2 Playbook (rogue agent suspected)

1. Disable the suspected agent (`agents.status = 'disabled'`).
2. Compare its recent inventory diff to peers.
3. Inspect its enrollment chain: token issuer, time, source IP.
4. If confirmed, mark `revoked` (terminal) and require re-enrollment of
   the underlying host with a new identity.

## SEV-3 Playbook (auth anomaly)

1. Inspect `audit_events` filtered to `action LIKE 'auth.%'` over the
   anomaly window.
2. Lock affected accounts; require password reset.
3. Review session table for active sessions; revoke as needed.

## Communications

- Internal: incident channel and ticket ID.
- External: only with explicit authorization. Do not post indicators of
  compromise to public services unless explicitly cleared.

## Post-incident

- Update this runbook with what worked and what didn't.
- File security improvements as roadmap items.
- If a CLAUDE.md rule was insufficient, propose an amendment.
