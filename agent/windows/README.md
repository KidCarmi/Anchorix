# Anchorix Windows Agent

The Windows agent (`anchorix-agent`) is a small Go program packaged as a
Windows service. It enumerates certificates from Windows certificate stores
and uploads non-secret metadata to the Anchorix control plane.

## Hard Constraints

- **No private key material ever leaves the host.** The agent does not read
  private keys from the certificate stores (CLAUDE.md §6.2).
- **Least privilege.** The service should run with the minimum permissions
  required to read the configured certificate stores.
- **No outbound calls beyond the configured control plane.**
- **Pinned trust.** After enrollment, the agent pins the control plane's
  TLS certificate fingerprint and refuses to talk to a different one.

## Layout

```
agent/windows/
├── cmd/anchorix-agent/   # main()
├── internal/
│   ├── config/           # config loader (registry, file, env)
│   ├── logger/           # structured logging (Windows event log + file)
│   ├── service/          # Windows service wrapper (golang.org/x/sys/windows/svc)
│   ├── transport/        # HTTPS client to the control plane
│   └── discovery/        # Windows certificate store enumeration
└── go.mod
```

## Behavior

1. On first start, generate a key pair and request enrollment using a
   one-time token.
2. Persist agent identity material in a permission-restricted file under
   `%ProgramData%\Anchorix\agent\identity.json`.
3. Run two recurring loops:
   - **heartbeat** every `heartbeat_interval` (default 60s)
   - **inventory** every `inventory_interval` (default 15m)
4. Honor service stop signals — drain in-flight uploads, then exit.

## Build

```bash
cd agent/windows
GOOS=windows GOARCH=amd64 go build -o ../../dist/anchorix-agent.exe ./cmd/anchorix-agent
```

A development build can run on Linux with `ANCHORIX_AGENT_DISCOVERY=stub`,
which uses a deterministic in-memory list of fake certificates instead of
the Windows store enumerator. This is for local iteration only and is not
shipped.

## Roadmap

The agent skeleton lives here today. Real Windows certstore enumeration
(via `crypt32.dll`) lands in Phase 3. Service installation packaging (MSI)
lands in Phase 6.
