import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function AuditPage() {
  return (
    <>
      <PageHeader title="Audit" subtitle="Immutable record of state-changing actions." />
      <EmptyState
        title="No audit events yet."
        body="Audit events are recorded for logins, agent enrollments, finding actions, and provider configuration changes (CLAUDE.md §9)."
      />
    </>
  );
}
