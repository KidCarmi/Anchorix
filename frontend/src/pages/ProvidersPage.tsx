import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export function ProvidersPage() {
  return (
    <>
      <PageHeader title="Providers" subtitle="PKI, secret, and transport integrations." />
      <EmptyState
        title="No providers configured."
        body="The provider abstraction is read-only in v0.1. Concrete providers (ADCS, Vault, Smallstep, EJBCA) land in later phases without changes to this page (CLAUDE.md §10)."
      />
    </>
  );
}
