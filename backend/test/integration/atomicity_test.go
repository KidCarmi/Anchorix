//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kidcarmi/anchorix/backend/internal/audit"
	"github.com/kidcarmi/anchorix/backend/internal/auth"
	"github.com/kidcarmi/anchorix/backend/internal/clock"
	"github.com/kidcarmi/anchorix/backend/internal/storage/postgres"
)

// failingRecorder wraps a real audit recorder and forces the
// configured action to error out. Used to drive the atomicity tests
// without modifying production audit behavior.
type failingRecorder struct {
	inner         audit.Recorder
	failOnAction  string
	failOnceArmed bool
}

func (f *failingRecorder) Record(ctx context.Context, e audit.Event) error {
	if f.failOnceArmed && e.Action == f.failOnAction {
		f.failOnceArmed = false
		return errors.New("synthetic audit failure for atomicity test")
	}
	return f.inner.Record(ctx, e)
}

func (f *failingRecorder) List(ctx context.Context, q audit.ListQuery) ([]audit.Event, error) {
	return f.inner.List(ctx, q)
}

// TestLoginRollsBackOnAuditFailure asserts that if the audit write
// inside Login fails, no session row is committed. The fix in this
// PR wraps sessions.Create + users.UpdateLastLogin + audit.Record
// in a single tx so partial state can't escape.
func TestLoginRollsBackOnAuditFailure(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	usersRepo := postgres.NewAuthRepository(db)
	sessionsRepo := postgres.NewSessionsRepository(db)
	realRecorder := postgres.NewAuditRecorder(db, clock.System{})
	failing := &failingRecorder{
		inner:         realRecorder,
		failOnAction:  "auth.login_succeeded",
		failOnceArmed: true,
	}

	passwd, err := auth.NewPasswordPolicy(10)
	if err != nil {
		t.Fatalf("password policy: %v", err)
	}
	sessPol, err := auth.NewSessionPolicy(8*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("session policy: %v", err)
	}
	svc, err := auth.NewService(usersRepo, sessionsRepo, failing, db, passwd, sessPol, clock.System{})
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}

	// Seed an admin so login has a real user to authenticate.
	if _, err := svc.CreateUser(context.Background(), "anchorix", testEmail, "Alice", testPassword, auth.RoleAdmin); err != nil {
		t.Fatalf("seed admin: %v", err)
	}

	// Attempt a login; the synthetic audit failure should propagate.
	_, err = svc.Login(context.Background(), auth.LoginInput{
		Email:    testEmail,
		Password: testPassword,
	})
	if err == nil {
		t.Fatal("Login: expected error from synthetic audit failure")
	}

	// Inspect: no sessions row should exist for that user.
	var count int
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&count)
	}); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != 0 {
		t.Fatalf("session count after rolled-back login = %d; want 0", count)
	}
}

// TestCreateUserRollsBackOnAuditFailure asserts that if the
// auth.admin_created audit write fails, no user row persists.
func TestCreateUserRollsBackOnAuditFailure(t *testing.T) {
	db := testDB(t)
	freshDatabase(t, db)

	usersRepo := postgres.NewAuthRepository(db)
	sessionsRepo := postgres.NewSessionsRepository(db)
	realRecorder := postgres.NewAuditRecorder(db, clock.System{})
	failing := &failingRecorder{
		inner:         realRecorder,
		failOnAction:  "auth.admin_created",
		failOnceArmed: true,
	}

	passwd, err := auth.NewPasswordPolicy(10)
	if err != nil {
		t.Fatalf("password policy: %v", err)
	}
	sessPol, err := auth.NewSessionPolicy(8*time.Hour, 24*time.Hour)
	if err != nil {
		t.Fatalf("session policy: %v", err)
	}
	svc, err := auth.NewService(usersRepo, sessionsRepo, failing, db, passwd, sessPol, clock.System{})
	if err != nil {
		t.Fatalf("auth.NewService: %v", err)
	}

	if err := usersRepo.EnsureOrganization(context.Background(), "anchorix", "Anchorix"); err != nil {
		t.Fatalf("ensure org: %v", err)
	}

	_, err = svc.CreateUser(context.Background(), "anchorix", testEmail, "Alice", testPassword, auth.RoleAdmin)
	if err == nil {
		t.Fatal("CreateUser: expected error from synthetic audit failure")
	}

	var count int
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.WithTxRaw(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE email = $1`, testEmail).Scan(&count)
	}); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if count != 0 {
		t.Fatalf("user count after rolled-back CreateUser = %d; want 0", count)
	}
}
