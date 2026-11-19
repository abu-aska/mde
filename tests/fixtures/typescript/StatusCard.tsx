// UI module fixture with JSX and formal skip marker.
export interface StatusProps {
  label: string;
  verified: boolean;
}

export function StatusCard(props: StatusProps) {
  return (
    <section className="status-card">
      <h2>{props.label}</h2>
      <span>{props.verified ? "verified" : "pending"}</span>
    </section>
  );
}
