import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function FindingsPage() {
  return (
    <>
      <PageHeader title="Findings" subtitle="Risks identified in the certificate inventory." />
      <EmptyState
        title="No findings yet."
        body="Findings are computed after inventory ingestion (Phase 4)."
      />
    </>
  );
}
