// Package enrollment owns the deployment-package + agent-enrollment
// domain.
//
// Ownership boundaries (CLAUDE.md §19):
//
//   - Owns: DeploymentPackage and Agent domain types, the
//     bootstrap-secret/credential vocabulary, and the EnrollmentService
//     that translates "admin creates a package" / "agent enrolls" into
//     repository writes + audit events.
//   - Does NOT own: SQL (lives in internal/storage/postgres), HTTP
//     wire shape (lives in internal/httpapi/handlers), or PKI / agent
//     transport details (those live behind interfaces this package
//     consumes).
//
// Forbidden dependencies:
//
//   - Must not import internal/httpapi or internal/httpapi/handlers.
//   - Must not import any storage/* implementation; the
//     DeploymentPackageRepository and AgentRepository interfaces are
//     owned by this package and implemented in
//     internal/storage/postgres (CLAUDE.md §8.8 interfaces-belong-to-the-consumer).
//
// Architectural role: domain layer. Plain Go types and pure
// business logic; concurrency and transactional safety are delegated
// to the Transactor interface (the storage layer's *DB binds the
// active tx to ctx so repository calls inside WithTx participate
// automatically).
//
// Security promises (CLAUDE.md §6, §9, AUTH_FOUNDATION.md):
//
//   - Plaintext bootstrap secrets and agent credentials never reach
//     persistent storage. Repository APIs accept only the SHA-256
//     hash. Plaintext is returned to the caller exactly once, in
//     the API response of the creating/enrolling call.
//   - Every state change (package create, agent enroll) is written
//     in the same transaction as its audit event; an audit-write
//     failure rolls the whole operation back so a control plane can
//     never reach a state where a deployment package or agent
//     exists without a matching audit row.
//   - Enrollment rejections return a single sentinel error to the
//     caller (ErrEnrollmentRejected). The internal reason
//     (expired / revoked / exhausted / unknown bootstrap secret) is
//     recorded in an audit event with severity:"security" but never
//     surfaced to the agent side of the wire.
package enrollment
