// Package httpapi exposes the Anchorix REST API.
//
// Layering rules (binding):
//
//   - httpapi may import internal/{auth,agents,inventory,risks,audit,
//     providers,...} via their public interfaces.
//   - Domain packages MUST NOT import httpapi.
//   - Handlers contain no business logic. They translate HTTP requests
//     into domain calls and shape responses.
//
// The full REST contract is documented in docs/api/REST_API.md.
package httpapi
