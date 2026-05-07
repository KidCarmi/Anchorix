import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function CertificatesPage() {
  return (
    <>
      <PageHeader title="Certificates" subtitle="Inventory discovered across the estate." />
      <EmptyState
        title="No certificates ingested yet."
        body="Certificate metadata appears here once agents upload inventory (Phase 3)."
      />
    </>
  );
}
