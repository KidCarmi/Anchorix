import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function DashboardPage() {
  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle="High-level view of certificate posture and agent health."
      />
      <EmptyState
        title="Dashboard arrives in Phase 3."
        body="Once agents are reporting inventory, this view will summarize expiring certificates, open findings, and recent agent activity."
      />
    </>
  );
}
