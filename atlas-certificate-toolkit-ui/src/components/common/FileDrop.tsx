import { useRef } from "react";

export function FileDrop(props: {
  label: string;
  accept?: string;
  multiple?: boolean;
  onFiles: (files: File[]) => void;
}) {
  const ref = useRef<HTMLInputElement | null>(null);

  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
        <div>
          <strong style={{ display: "block", fontSize: 15 }}>{props.label}</strong>
          <div className="small">Arraste e solte ou selecione arquivo(s)</div>
        </div>
        <button className="btn" onClick={() => ref.current?.click()}>
          Selecionar
        </button>
      </div>

      <input
        ref={ref}
        type="file"
        accept={props.accept}
        multiple={props.multiple}
        style={{ display: "none" }}
        onChange={(e) => {
          const files = Array.from(e.target.files ?? []);
          if (files.length) props.onFiles(files);
          e.currentTarget.value = "";
        }}
      />

      <div
        style={{
          marginTop: 14,
          border: "1px dashed rgba(111, 194, 247, 0.3)",
          borderRadius: 20,
          padding: 22,
          textAlign: "center",
          color: "rgba(235, 245, 255, 0.82)",
          background:
            "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02)), linear-gradient(135deg, rgba(52,180,242,0.06), transparent 45%)",
        }}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const files = Array.from(e.dataTransfer.files ?? []);
          if (files.length) props.onFiles(files);
        }}
      >
        <div style={{ fontWeight: 700, marginBottom: 4 }}>Solte aqui</div>
        <div className="small">Arquivos PEM, CRT, KEY, PFX ou CSR</div>
      </div>
    </div>
  );
}
