//go:build integration

package integration

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/governance"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// sameSet reports whether a and b contain the same elements,
// ignoring order. Used for the order-independent signal-set
// assertions; ordering is asserted separately where it matters.
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]string(nil), a...)
	cb := append([]string(nil), b...)
	sort.Strings(ca)
	sort.Strings(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

// ----- H-026B1 signal-read seed helpers -----

func seedCertMeta(t *testing.T, db *postgres.DB, ctx context.Context, orgID, id, subject, issuer string, sans []string) {
	t.Helper()
	sansJSON := "["
	for i, s := range sans {
		if i > 0 {
			sansJSON += ","
		}
		sansJSON += `"` + s + `"`
	}
	sansJSON += "]"
	const q = `
		INSERT INTO certificates (
			id, organization_id, fingerprint_sha256, subject, issuer,
			serial_number_hex, signature_algorithm, public_key_algorithm,
			public_key_bits, not_before, not_after, sans, pem
		) VALUES (
			$1, $2, $1, $3, $4,
			'01', 'SHA256-RSA', 'RSA',
			2048, now() - interval '30 days', now() + interval '365 days', $5::jsonb,
			'-----BEGIN CERTIFICATE-----' || E'\n' || 'MIIBxxx' || E'\n' || '-----END CERTIFICATE-----'
		)`
	if err := execRawSQL(ctx, db, rawStmt{q, []any{id, orgID, subject, issuer, sansJSON}}); err != nil {
		t.Fatalf("seed cert meta %s: %v", id, err)
	}
}

func seedObservationRow(t *testing.T, db *postgres.DB, ctx context.Context, orgID, obsID, certID, agentID, store string, removed bool) {
	t.Helper()
	var removedAt *time.Time
	if removed {
		ts := time.Now().UTC().Add(-time.Hour)
		removedAt = &ts
	}
	const q = `
		INSERT INTO certificate_observations (
			id, organization_id, certificate_id, agent_id, store_location,
			last_seen_at, removed_at
		) VALUES ($1, $2, $3, $4, $5, now(), $6)`
	if err := execRawSQL(ctx, db, rawStmt{q, []any{obsID, orgID, certID, agentID, store, removedAt}}); err != nil {
		t.Fatalf("seed observation %s: %v", obsID, err)
	}
}

func seedTagAssign(t *testing.T, db *postgres.DB, ctx context.Context, orgID, tagID, key, value, targetType, targetID string) {
	t.Helper()
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO tags (id, organization_id, key, value) VALUES ($1, $2, $3, $4)
		   ON CONFLICT (organization_id, key, value) DO NOTHING`,
		[]any{tagID, orgID, key, value},
	}); err != nil {
		t.Fatalf("seed tag %s: %v", tagID, err)
	}
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO tag_assignments (id, organization_id, tag_id, target_type, target_id, assigned_by)
		   VALUES ($1, $2, $3, $4, $5, 'tester')`,
		[]any{"asg-" + tagID + "-" + targetID, orgID, tagID, targetType, targetID},
	}); err != nil {
		t.Fatalf("seed tag assignment %s->%s: %v", tagID, targetID, err)
	}
}

func seedAgentGroupMembership(t *testing.T, db *postgres.DB, ctx context.Context, orgID, groupID, agentID string) {
	t.Helper()
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO agent_groups (id, organization_id, slug, display_name)
		   VALUES ($1, $2, $1, 'grp') ON CONFLICT (organization_id, id) DO NOTHING`,
		[]any{groupID, orgID},
	}); err != nil {
		t.Fatalf("seed agent group %s: %v", groupID, err)
	}
	if err := execRawSQL(ctx, db, rawStmt{
		`INSERT INTO agent_group_memberships (organization_id, agent_id, agent_group_id, assigned_by)
		   VALUES ($1, $2, $3, 'tester')`,
		[]any{orgID, agentID, groupID},
	}); err != nil {
		t.Fatalf("seed agent group membership %s/%s: %v", groupID, agentID, err)
	}
}

func findSignals(sigs []governance.CertificateSignals, certID string) *governance.CertificateSignals {
	for i := range sigs {
		if sigs[i].CertificateID == certID {
			return &sigs[i]
		}
	}
	return nil
}

// TestListCertificateSignalsCorrectness pins the full signal bundle
// for one cert: intrinsic metadata, active-observation-derived store
// locations / agents / agent groups, and cert + agent tags.
func TestListCertificateSignalsCorrectness(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	seedCertMeta(t, db, ctx, "anchorix", "cert-sig-1",
		"CN=billing-prod-01.corp.example", "CN=Internal Issuing CA",
		[]string{"billing-prod-01.corp.example", "billing.corp.example"})

	activeAgent := seedAgent(t, db, "anchorix", "active")
	removedAgent := seedAgent(t, db, "anchorix", "removed")

	// Active agent: two stores. Removed agent: one store, removed.
	seedObservationRow(t, db, ctx, "anchorix", "obs-1", "cert-sig-1", activeAgent, "LocalMachine\\WebHosting", false)
	seedObservationRow(t, db, ctx, "anchorix", "obs-2", "cert-sig-1", activeAgent, "LocalMachine\\My", false)
	seedObservationRow(t, db, ctx, "anchorix", "obs-3", "cert-sig-1", removedAgent, "LocalMachine\\Removed", true)

	// Agent group on the active agent only.
	seedAgentGroupMembership(t, db, ctx, "anchorix", "grp-web", activeAgent)
	// A group on the REMOVED agent must NOT surface.
	seedAgentGroupMembership(t, db, ctx, "anchorix", "grp-ghost", removedAgent)

	// Cert tag + agent tag (on active agent) + agent tag on removed agent.
	seedTagAssign(t, db, ctx, "anchorix", "tag-env", "env", "prod", "certificate", "cert-sig-1")
	seedTagAssign(t, db, ctx, "anchorix", "tag-tier", "tier", "web", "agent", activeAgent)
	seedTagAssign(t, db, ctx, "anchorix", "tag-ghost", "ghost", "x", "agent", removedAgent)

	sigs, err := repo.ListCertificateSignalsPaged(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("ListCertificateSignalsPaged: %v", err)
	}
	s := findSignals(sigs, "cert-sig-1")
	if s == nil {
		t.Fatalf("cert-sig-1 not returned; got %d signals", len(sigs))
	}

	if s.Subject != "CN=billing-prod-01.corp.example" || s.Issuer != "CN=Internal Issuing CA" {
		t.Fatalf("subject/issuer mismatch: %q / %q", s.Subject, s.Issuer)
	}
	if !sameSet(s.SANs, []string{"billing-prod-01.corp.example", "billing.corp.example"}) {
		t.Fatalf("SANs = %v", s.SANs)
	}
	// Active observations only: removed store excluded.
	if !sameSet(s.StoreLocations, []string{"LocalMachine\\My", "LocalMachine\\WebHosting"}) {
		t.Fatalf("store locations = %v (want active only)", s.StoreLocations)
	}
	if !sort.StringsAreSorted(s.StoreLocations) {
		t.Fatalf("store locations not ascending: %v", s.StoreLocations)
	}
	if !sameSet(s.ObservingAgentIDs, []string{activeAgent}) {
		t.Fatalf("observing agents = %v; want only active agent %s", s.ObservingAgentIDs, activeAgent)
	}
	if !sameSet(s.ObservingAgentGroupIDs, []string{"grp-web"}) {
		t.Fatalf("observing agent groups = %v; want [grp-web] (ghost via removed agent excluded)", s.ObservingAgentGroupIDs)
	}
	if len(s.CertTags) != 1 || s.CertTags[0].Key != "env" || s.CertTags[0].Value != "prod" {
		t.Fatalf("cert tags = %+v", s.CertTags)
	}
	if len(s.AgentTags) != 1 || s.AgentTags[0].Key != "tier" || s.AgentTags[0].Value != "web" {
		t.Fatalf("agent tags = %+v; want only [tier=web] (ghost via removed agent excluded)", s.AgentTags)
	}
}

// TestListCertificateSignalsNoDuplicates verifies that multiple
// observations of the same cert collapse to DISTINCT signal sets.
func TestListCertificateSignalsNoDuplicates(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	seedCertMeta(t, db, ctx, "anchorix", "cert-dup-1", "CN=dup", "CN=ca", nil)
	a1 := seedAgent(t, db, "anchorix", "d1")
	a2 := seedAgent(t, db, "anchorix", "d2")
	// Two agents, SAME store_location → store set must dedup to one.
	seedObservationRow(t, db, ctx, "anchorix", "obs-d1", "cert-dup-1", a1, "LocalMachine\\Shared", false)
	seedObservationRow(t, db, ctx, "anchorix", "obs-d2", "cert-dup-1", a2, "LocalMachine\\Shared", false)
	// Both agents in the SAME group → group set must dedup to one.
	seedAgentGroupMembership(t, db, ctx, "anchorix", "grp-shared", a1)
	seedAgentGroupMembership(t, db, ctx, "anchorix", "grp-shared", a2)

	sigs, err := repo.ListCertificateSignalsPaged(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("ListCertificateSignalsPaged: %v", err)
	}
	s := findSignals(sigs, "cert-dup-1")
	if s == nil {
		t.Fatalf("cert-dup-1 not returned")
	}
	if len(s.StoreLocations) != 1 || s.StoreLocations[0] != "LocalMachine\\Shared" {
		t.Fatalf("store locations not deduped: %v", s.StoreLocations)
	}
	if len(s.ObservingAgentGroupIDs) != 1 || s.ObservingAgentGroupIDs[0] != "grp-shared" {
		t.Fatalf("agent groups not deduped: %v", s.ObservingAgentGroupIDs)
	}
	if len(s.ObservingAgentIDs) != 2 {
		t.Fatalf("observing agents = %v; want both distinct agents", s.ObservingAgentIDs)
	}
}

// TestListCertificateSignalsCrossOrgIsolation verifies the signal
// join never reaches across organizations — neither for the cert
// row itself nor for any of its joined signal sets.
func TestListCertificateSignalsCrossOrgIsolation(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	seedOrganization(t, db, "other", "Other Org")
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// anchorix cert + active agent observation.
	seedCertMeta(t, db, ctx, "anchorix", "cert-iso-a", "CN=a", "CN=ca", nil)
	agentA := seedAgent(t, db, "anchorix", "iso-a")
	seedObservationRow(t, db, ctx, "anchorix", "obs-iso-a", "cert-iso-a", agentA, "LocalMachine\\A", false)

	// other-org cert + agent + observation + tag (must never appear
	// in an anchorix query).
	seedCertMeta(t, db, ctx, "other", "cert-iso-b", "CN=b", "CN=ca", nil)
	agentB := seedAgent(t, db, "other", "iso-b")
	seedObservationRow(t, db, ctx, "other", "obs-iso-b", "cert-iso-b", agentB, "LocalMachine\\B", false)

	// Cross-org leakage probe: an 'other'-org tag_assignment whose
	// target_id is the ANCHORIX agent. Since tag_assignments target
	// integrity is service-layer (not FK) for agent targets, this row
	// inserts fine — and the signal join MUST NOT pick it up for the
	// anchorix cert because every LATERAL is org-scoped.
	seedTagAssign(t, db, ctx, "other", "tag-leak", "leak", "yes", "agent", agentA)

	anchorixSigs, err := repo.ListCertificateSignalsPaged(ctx, "anchorix", "", 100)
	if err != nil {
		t.Fatalf("anchorix signals: %v", err)
	}
	if len(anchorixSigs) != 1 || anchorixSigs[0].CertificateID != "cert-iso-a" {
		t.Fatalf("anchorix query leaked rows: %+v", anchorixSigs)
	}
	if len(anchorixSigs[0].AgentTags) != 0 {
		t.Fatalf("cross-org agent tag leaked: %+v", anchorixSigs[0].AgentTags)
	}

	otherSigs, err := repo.ListCertificateSignalsPaged(ctx, "other", "", 100)
	if err != nil {
		t.Fatalf("other signals: %v", err)
	}
	if len(otherSigs) != 1 || otherSigs[0].CertificateID != "cert-iso-b" {
		t.Fatalf("other query returned wrong rows: %+v", otherSigs)
	}
}

// TestListCertificateSignalsDisjointPagination walks the signal read
// in small pages and asserts pages are ordered, disjoint, and cover
// every cert exactly once.
func TestListCertificateSignalsDisjointPagination(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	repo := postgres.NewOwnershipRepository(db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const n = 7
	want := map[string]bool{}
	for i := 0; i < n; i++ {
		id := "cert-pg-" + string(rune('a'+i))
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", nil)
		want[id] = true
	}

	seen := map[string]bool{}
	cursor := ""
	var last string
	pages := 0
	for {
		page, err := repo.ListCertificateSignalsPaged(ctx, "anchorix", cursor, 2)
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		if len(page) == 0 {
			break
		}
		pages++
		for _, s := range page {
			if seen[s.CertificateID] {
				t.Fatalf("duplicate across pages: %s", s.CertificateID)
			}
			seen[s.CertificateID] = true
			if last != "" && s.CertificateID <= last {
				t.Fatalf("not ascending: %s after %s", s.CertificateID, last)
			}
			last = s.CertificateID
		}
		cursor = page[len(page)-1].CertificateID
		if len(page) < 2 {
			break
		}
	}
	if len(seen) != n {
		t.Fatalf("covered %d certs; want %d", len(seen), n)
	}
	if pages < 2 {
		t.Fatalf("expected multiple pages, got %d", pages)
	}
}

// TestListCertificateSignalsExplainBoundedPerCert is the binding
// query-shape test (H026B plan §3.1): the production statement must
// be paged by certificates (a Limit node) and must NOT use a
// fleet-wide GROUP BY (no "Group Key" anywhere in the plan — the
// per-cert LATERAL sub-aggregates are plain Aggregate nodes).
func TestListCertificateSignalsExplainBoundedPerCert(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Seed a few certs + observations so the planner has real shapes.
	for i := 0; i < 3; i++ {
		id := "cert-ex-" + string(rune('a'+i))
		seedCertMeta(t, db, ctx, "anchorix", id, "CN="+id, "CN=ca", nil)
		ag := seedAgent(t, db, "anchorix", "ex"+string(rune('a'+i)))
		seedObservationRow(t, db, ctx, "anchorix", "obs-ex-"+id, id, ag, "LocalMachine\\X", false)
	}

	plan := explainPlan(t, db, ctx, postgres.CertificateSignalsPagedQuery, "anchorix", "", 500)

	if !strings.Contains(plan, "Limit") {
		t.Fatalf("plan has no Limit node (paging not applied):\n%s", plan)
	}
	if !strings.Contains(plan, "certificates") {
		t.Fatalf("plan does not scan certificates as the driver:\n%s", plan)
	}
	if strings.Contains(plan, "Group Key") {
		t.Fatalf("plan contains a fleet-wide GROUP BY (forbidden shape):\n%s", plan)
	}
}

func explainPlan(t *testing.T, db *postgres.DB, ctx context.Context, query string, args ...any) string {
	t.Helper()
	var sb strings.Builder
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "EXPLAIN "+query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			sb.WriteString(line)
			sb.WriteString("\n")
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	return sb.String()
}
