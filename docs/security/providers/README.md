# Per-Provider Threat Analyses

CLAUDE.md §6.10 requires a threat-model entry before any feature that
touches keys, identity, network trust, or provider integration is merged.
This directory holds those analyses.

Each provider (ADCS, Vault PKI, Smallstep, EJBCA, future) gets a single
markdown file when its implementation lands. Suggested template:

```
# Provider — <Name>

## Trust assumptions
## Network surface
## Authentication and authorization
## Secret handling
## Failure modes
## Blast radius if compromised
## Mitigations
## Open questions
```

The `none` provider has no threat surface (introspection only) and does
not require its own document.
