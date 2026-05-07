import type { ReactNode } from "react";

type Props = {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
};

export function PageHeader({ title, subtitle, actions }: Props) {
  return (
    <header className="mb-6 flex items-start justify-between">
      <div>
        <h1 className="text-2xl font-semibold text-anchor-900">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-anchor-700">{subtitle}</p>}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </header>
  );
}
