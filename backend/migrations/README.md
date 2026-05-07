# Database Migrations

Migrations are numbered, append-only SQL files. They are applied in order
by `anchorix migrate up`.

## Rules

1. **Append only.** Never edit a migration after it has been merged.
   Add a new file with the next number instead.
2. **Idempotent where possible.** Use `CREATE TABLE IF NOT EXISTS` only for
   non-canonical, side helper tables; canonical schema changes should fail
   loudly if the assumed state is wrong.
3. **Wrap in `BEGIN`/`COMMIT`.** Every migration is one transaction.
4. **No destructive changes without a plan.** Dropping columns or tables
   requires a documented two-phase migration (write code that handles both
   shapes; ship; then drop in a follow-up migration).
5. **Track versions.** Every migration must insert into `schema_migrations`.

## Naming

```
NNNN_short_description.sql
```

- `NNNN` is a zero-padded 4-digit sequence number (`0001`, `0002`, ...).
- `short_description` is `snake_case`.

## Conventions

- All `id` columns are `TEXT` opaque identifiers.
- All timestamps are `TIMESTAMPTZ` stored in UTC.
- All foreign keys are explicit (`ON DELETE` clause is mandatory).
- All booleans default to `FALSE` unless there's a strong reason otherwise.
- Audit-relevant tables enforce immutability with triggers.
