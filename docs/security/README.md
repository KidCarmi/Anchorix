# Security Documentation

This directory holds security-relevant documentation for Anchorix v0.1.

| File                          | Purpose                                                  |
| ----------------------------- | -------------------------------------------------------- |
| `THREAT_MODEL.md`             | Threats, assets, attacker model, mitigations             |
| `TRUST_MODEL.md`              | Trust boundaries and assumptions                         |
| `SECURITY_CONTROLS.md`        | Concrete controls implemented in v0.1                    |
| `INCIDENT_RESPONSE.md`        | Runbook for suspected security incidents                 |
| `REPORTING.md`                | How to responsibly report a vulnerability                |
| `providers/`                  | Per-provider threat analyses (added as providers land)   |

CLAUDE.md §6.10 requires a threat model entry **before** any major feature
that touches keys, identity, network trust, or provider integration is
merged. This directory is the authoritative location for those documents.
