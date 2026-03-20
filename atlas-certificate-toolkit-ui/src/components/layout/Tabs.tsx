export type TabKey = "csr" | "toolkit";

export function Tabs(props: { active: TabKey; onChange: (t: TabKey) => void }) {
  return (
    <div className="row">
      <button
        className={`btn ${props.active === "csr" ? "btnPrimary" : ""}`}
        onClick={() => props.onChange("csr")}
      >
        CSR Decoder
      </button>
      <button
        className={`btn ${props.active === "toolkit" ? "btnPrimary" : ""}`}
        onClick={() => props.onChange("toolkit")}
      >
        Converter Arquivos
      </button>
    </div>
  );
}
