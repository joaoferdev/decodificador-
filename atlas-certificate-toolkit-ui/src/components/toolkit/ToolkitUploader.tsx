import { useState } from "react";
import { createJob } from "../../api/toolkit";
import { FileDrop } from "../common/FileDrop";
import { Alert } from "../common/Alert";

export function ToolkitUploader(props: { onJobCreated: (jobId: string) => void }) {
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function handle(files: File[]) {
    setErr(null);
    setLoading(true);
    try {
      const res = await createJob(files);
      props.onJobCreated(res.jobId);
    } catch (e: any) {
      setErr(e?.message ?? "Erro ao criar job");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="card">
      <strong>Uploads (Jobs)</strong>
      <div className="small">Envie cert/key/chain/pfx e rode as recipes</div>

      {err ? (
        <div style={{ marginTop: 10 }}>
          <Alert kind="err" title="Erro" message={err} />
        </div>
      ) : null}

      <div style={{ marginTop: 12 }}>
        <FileDrop
          label="Enviar arquivos para criar Job"
          multiple
          accept=".pem,.crt,.cer,.key,.pfx,.p12,.txt"
          onFiles={handle}
        />
      </div>

      <div className="small" style={{ marginTop: 10 }}>
        {loading ? "Criando job..." : "Dica: para generate_pkcs12 envie server.crt + private.key (+ chain.pem se tiver)."}
      </div>
    </div>
  );
}