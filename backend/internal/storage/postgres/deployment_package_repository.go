package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/kidcarmi/anchorix/backend/internal/enrollment"
)

// uniqueViolationCode is PostgreSQL SQLSTATE 23505. Returned by
// the unique index on deployment_packages.bootstrap_secret_hash if
// a collision ever happened (probability of a SHA-256 collision is
// negligible, but the index still defends against repository bugs).
const uniqueViolationCode = "23505"

// DeploymentPackageRepository implements
// enrollment.DeploymentPackageRepository against PostgreSQL.
type DeploymentPackageRepository struct {
	db *DB
}

// NewDeploymentPackageRepository wires the repo. CLAUDE.md §8.8:
// constructor-based DI; no globals.
func NewDeploymentPackageRepository(db *DB) *DeploymentPackageRepository {
	return &DeploymentPackageRepository{db: db}
}

// Create inserts a new deployment package row.
func (r *DeploymentPackageRepository) Create(
	ctx context.Context,
	pkg *enrollment.DeploymentPackage,
	bootstrapSecretHash []byte,
) error {
	labels, err := json.Marshal(pkg.DefaultLabels)
	if err != nil {
		return fmt.Errorf("postgres: marshal labels: %w", err)
	}
	const q = `
		INSERT INTO deployment_packages (
			id, organization_id, name, description, package_type,
			agent_version, bootstrap_secret_hash, max_uses, uses_count,
			expires_at, created_by_user_id, created_at,
			default_group_name, default_labels
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14
		)`
	_, err = r.db.querierFor(ctx).Exec(ctx, q,
		pkg.ID, pkg.OrganizationID, pkg.Name, pkg.Description, string(pkg.PackageType),
		pkg.AgentVersion, bootstrapSecretHash, pkg.MaxUses, pkg.UsesCount,
		pkg.ExpiresAt, pkg.CreatedByUserID, pkg.CreatedAt,
		pkg.DefaultGroupName, labels,
	)
	if err != nil {
		return fmt.Errorf("postgres: create deployment package: %w", err)
	}
	return nil
}

// GetByBootstrapHash returns the package whose stored hash matches.
// Returns enrollment.ErrPackageNotFound on no match — the
// enrollment service then converts that into the wire-safe
// ErrEnrollmentRejected.
func (r *DeploymentPackageRepository) GetByBootstrapHash(
	ctx context.Context,
	hash []byte,
) (*enrollment.DeploymentPackage, error) {
	const q = `
		SELECT id, organization_id, name, description, package_type,
		       agent_version, max_uses, uses_count, expires_at,
		       revoked_at, revoked_by_user_id, revoked_reason,
		       created_by_user_id, created_at, last_used_at,
		       default_group_name, default_labels
		  FROM deployment_packages
		 WHERE bootstrap_secret_hash = $1`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, hash)
	pkg, err := scanDeploymentPackage(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, enrollment.ErrPackageNotFound
		}
		return nil, fmt.Errorf("postgres: get package by bootstrap hash: %w", err)
	}
	return pkg, nil
}

// GetByIDAndOrg returns the package only when both id AND
// organization_id match. The org scope is enforced at the WHERE
// clause so a cross-org id surfaces as ErrPackageNotFound rather
// than a forbidden — operators cannot enumerate the existence of
// packages in other orgs (CLAUDE.md §6 deterministic auth).
func (r *DeploymentPackageRepository) GetByIDAndOrg(
	ctx context.Context,
	id, organizationID string,
) (*enrollment.DeploymentPackage, error) {
	const q = `
		SELECT id, organization_id, name, description, package_type,
		       agent_version, max_uses, uses_count, expires_at,
		       revoked_at, revoked_by_user_id, revoked_reason,
		       created_by_user_id, created_at, last_used_at,
		       default_group_name, default_labels
		  FROM deployment_packages
		 WHERE id = $1 AND organization_id = $2`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, id, organizationID)
	pkg, err := scanDeploymentPackage(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, enrollment.ErrPackageNotFound
		}
		return nil, fmt.Errorf("postgres: get package by id and org: %w", err)
	}
	return pkg, nil
}

// Revoke flips revoked_at + revoked_by_user_id + revoked_reason on
// a single package row. The conditional UPDATE only matches rows
// where revoked_at IS NULL, so a concurrent revoke from another
// admin cannot double-write the columns. The caller (the service)
// is responsible for pre-checking and emitting the audit event in
// the same transaction; this method only owns the SQL.
//
// Returns enrollment.ErrPackageNotFound if no row matched the
// (id, organization_id, revoked_at IS NULL) predicate. The service
// distinguishes "not found in org" from "already revoked" by
// reading the package state first.
func (r *DeploymentPackageRepository) Revoke(
	ctx context.Context,
	id, organizationID, revokedByUserID, reason string,
	at time.Time,
) error {
	const q = `
		UPDATE deployment_packages
		   SET revoked_at         = $3,
		       revoked_by_user_id = $4,
		       revoked_reason     = $5
		 WHERE id = $1
		   AND organization_id = $2
		   AND revoked_at IS NULL`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q,
		id, organizationID, at, revokedByUserID, reason,
	)
	if err != nil {
		return fmt.Errorf("postgres: revoke deployment package: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either the package does not exist for this org, or it is
		// already revoked. The service has already confirmed
		// existence via GetByIDAndOrg, so a 0-row outcome here is
		// the concurrent-revoke race and is treated as "already
		// revoked" (idempotent success at the service layer).
		return enrollment.ErrPackageAlreadyRevoked
	}
	return nil
}

// IncrementUses is the atomic choke point for safe concurrent
// enrollment. The conditional UPDATE only succeeds when the
// package is still active at the moment of the SQL statement —
// any of the three lifecycle bounds (revoked, expired, exhausted)
// causes zero rows to be affected, and the caller then does a
// follow-up read to figure out which one failed.
func (r *DeploymentPackageRepository) IncrementUses(
	ctx context.Context,
	id string,
	at time.Time,
) error {
	const q = `
		UPDATE deployment_packages
		   SET uses_count   = uses_count + 1,
		       last_used_at = $2
		 WHERE id = $1
		   AND revoked_at IS NULL
		   AND expires_at > $2
		   AND uses_count < max_uses`
	tag, err := r.db.querierFor(ctx).Exec(ctx, q, id, at)
	if err != nil {
		return fmt.Errorf("postgres: increment package uses: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// Zero rows affected: figure out the specific reason so the
	// service can record the right rejection metadata. A second
	// read inside the same transaction is consistent with the
	// preceding UPDATE.
	return r.classifyIncrementFailure(ctx, id, at)
}

func (r *DeploymentPackageRepository) classifyIncrementFailure(
	ctx context.Context,
	id string,
	at time.Time,
) error {
	const q = `
		SELECT revoked_at, expires_at, uses_count, max_uses
		  FROM deployment_packages
		 WHERE id = $1`
	row := r.db.querierFor(ctx).QueryRow(ctx, q, id)
	var (
		revokedAt *time.Time
		expiresAt time.Time
		usesCount int
		maxUses   int
	)
	if err := row.Scan(&revokedAt, &expiresAt, &usesCount, &maxUses); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// The package was deleted between the UPDATE and the
			// follow-up SELECT. Treat as not-found so the caller
			// surfaces ErrEnrollmentRejected.
			return enrollment.ErrPackageNotFound
		}
		return fmt.Errorf("postgres: classify package increment failure: %w", err)
	}
	switch {
	case revokedAt != nil:
		return enrollment.ErrPackageRevoked
	case !at.Before(expiresAt):
		return enrollment.ErrPackageExpired
	case usesCount >= maxUses:
		return enrollment.ErrPackageExhausted
	}
	// Shouldn't happen — the UPDATE's WHERE clause matched none of
	// the rows but the SELECT shows the package as still active.
	// Race against a concurrent revoke that flipped state back, or
	// a clock skew on the at parameter. Surface as a generic
	// rejection so the agent still gets the same envelope.
	return enrollment.ErrEnrollmentRejected
}

// scanDeploymentPackage hydrates a DeploymentPackage from a pgx
// row. Pulled out so it can serve both GetByBootstrapHash and any
// future GetByID lookup without duplicating column lists.
func scanDeploymentPackage(row pgx.Row) (*enrollment.DeploymentPackage, error) {
	var (
		p               enrollment.DeploymentPackage
		packageType     string
		revokedAt       *time.Time
		revokedByUserID *string
		lastUsedAt      *time.Time
		labelsRaw       []byte
	)
	if err := row.Scan(
		&p.ID, &p.OrganizationID, &p.Name, &p.Description, &packageType,
		&p.AgentVersion, &p.MaxUses, &p.UsesCount, &p.ExpiresAt,
		&revokedAt, &revokedByUserID, &p.RevokedReason,
		&p.CreatedByUserID, &p.CreatedAt, &lastUsedAt,
		&p.DefaultGroupName, &labelsRaw,
	); err != nil {
		return nil, err
	}
	p.PackageType = enrollment.PackageType(packageType)
	p.RevokedAt = revokedAt
	if revokedByUserID != nil {
		p.RevokedByUserID = *revokedByUserID
	}
	p.LastUsedAt = lastUsedAt
	if len(labelsRaw) > 0 {
		_ = json.Unmarshal(labelsRaw, &p.DefaultLabels)
	}
	return &p, nil
}

// isUniqueViolation reports whether err is a Postgres unique
// constraint violation. Used by the agent repository to detect
// concurrent enrollments racing on the same install_id without
// caring about the rest of the error vocabulary.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == uniqueViolationCode
	}
	return false
}
