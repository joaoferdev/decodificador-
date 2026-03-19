import { useRef } from "react";

export function FileDrop(props: {
  label: string;
  accept?: string;
  multiple?: boolean;
  onFiles: (files: File[]) => void;
}) {
  const ref = useRef<HTMLInputElement | null>(null);

  return (
    <div className="card" style={{ padding: 14 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
        <div>
          <strong>{props.label}</strong>
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
          marginTop: 10,
          border: "1px dashed rgba(255,255,255,0.18)",
          borderRadius: 12,
          padding: 14,
          textAlign: "center",
          color: "rgba(255,255,255,0.75)",
        }}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          const files = Array.from(e.dataTransfer.files ?? []);
          if (files.length) props.onFiles(files);
        }}
      >
        Solte aqui
      </div>
    </div>
  );
}