import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function AgentsPage() {
  return (
    <>
      <PageHeader title="Agents" subtitle="Registered Windows discovery agents." />
      <EmptyState
        title="No agents registered yet."
        body="Issue an enrollment token from Phase 2 onward; this page will list the agents that complete enrollment."
      />
    </>
  );
}
