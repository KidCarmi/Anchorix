// Package auth — see auth.go for the package contract.
//
// This doc.go exists per CLAUDE.md §19 so future contributors can
// grep for the ownership boundaries without scrolling auth.go.
//
//   - Responsibility: operator authentication + session lifecycle.
//   - Owns:           User, Session, Role types; password hashing
//     policy; cookie sign/verify; login/logout/auth.
//   - Forbidden imports: net/http, github.com/jackc/pgx/* (this
//     package is HTTP- and SQL-free).
//   - Architectural role: domain layer. Consumed by httpapi via
//     interfaces; implemented by storage/postgres.
package auth
