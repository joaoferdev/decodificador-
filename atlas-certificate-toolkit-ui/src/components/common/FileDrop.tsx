import { useRef, useState } from "react";

export function FileDrop(props: {
  label: string;
  accept?: string;
  multiple?: boolean;
  onFiles: (files: File[]) => void;
}) {
  const ref = useRef<HTMLInputElement | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  return (
    <div className="card" style={{ padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12, alignItems: "center" }}>
        <div>
          <strong style={{ display: "block", fontSize: 15 }}>{props.label}</strong>
          <div className="small">Arraste e solte ou selecione arquivo(s)</div>
        </div>
        <button className="btn" onClick={() => ref.current?.click()} type="button">
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
          if (files.length > 0) props.onFiles(files);
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
          background: isDragging
            ? "linear-gradient(180deg, rgba(255,255,255,0.08), rgba(255,255,255,0.03)), linear-gradient(135deg, rgba(52,180,242,0.16), transparent 45%)"
            : "linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02)), linear-gradient(135deg, rgba(52,180,242,0.06), transparent 45%)"
        }}
        onDragEnter={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={(e) => {
          e.preventDefault();
          setIsDragging(false);
        }}
        onDrop={(e) => {
          e.preventDefault();
          setIsDragging(false);
          const files = Array.from(e.dataTransfer.files ?? []);
          if (files.length > 0) props.onFiles(files);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            ref.current?.click();
          }
        }}
        role="button"
        tabIndex={0}
      >
        <div style={{ fontWeight: 700, marginBottom: 4 }}>{isDragging ? "Solte para enviar" : "Solte aqui"}</div>
        <div className="small">Arquivos PEM, CRT, CER, KEY, PFX, P12, CSR ou TXT</div>
      </div>
    </div>
  );
}
