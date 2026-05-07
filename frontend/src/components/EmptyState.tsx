type Props = {
  title: string;
  body?: string;
};

export function EmptyState({ title, body }: Props) {
  return (
    <div className="rounded-md border border-dashed border-anchor-100 bg-white p-10 text-center">
      <p className="text-sm font-medium text-anchor-900">{title}</p>
      {body && <p className="mt-1 text-sm text-anchor-700">{body}</p>}
    </div>
  );
}
