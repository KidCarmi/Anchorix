package postgres

import (
	"reflect"
	"testing"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
)

// TestListOverridesExpiringByIsRemovedFromRepository is a regression
// guard for the H-029 PR-1 removal of the unpaged
// `ListOverridesExpiringBy` method. The paged primitive
// (`ListExpiringOverridesPaged`) is now the only entry point; the
// unpaged variant must never reappear on either the consumer-owned
// `governance.OwnershipRepository` interface or the
// `*postgres.OwnershipRepository` concrete type, because reintroducing
// it would resurrect the unbounded read the H-029 design closed.
//
// This is a unit-level reflection check — no PostgreSQL needed — so it
// runs in CI's `go test ./...` phase and catches a regression long
// before any integration test would.
func TestListOverridesExpiringByIsRemovedFromRepository(t *testing.T) {
	const removed = "ListOverridesExpiringBy"

	concreteType := reflect.TypeOf((*OwnershipRepository)(nil))
	if _, ok := concreteType.MethodByName(removed); ok {
		t.Fatalf("%s is back on *postgres.OwnershipRepository — H-029 PR-1 removed it; the unbounded read must not reappear", removed)
	}

	interfaceType := reflect.TypeOf((*governance.OwnershipRepository)(nil)).Elem()
	for i := 0; i < interfaceType.NumMethod(); i++ {
		if interfaceType.Method(i).Name == removed {
			t.Fatalf("%s is back on governance.OwnershipRepository — H-029 PR-1 removed it; the unbounded read must not reappear", removed)
		}
	}
}
