export type TabKey = "csr" | "toolkit";

export function Tabs(props: { active: TabKey; onChange: (t: TabKey) => void }) {
  const Button = ({ id, label }: { id: TabKey; label: string }) => (
    <button
      className={`btn ${props.active === id ? "btnPrimary" : ""}`}
      onClick={() => props.onChange(id)}
    >
      {label}
    </button>
  );

  return (
    <div className="row">
      <Button id="csr" label="CSR Decoder" />
      <Button id="toolkit" label="Converter Arquivos" />
    </div>
  );
}