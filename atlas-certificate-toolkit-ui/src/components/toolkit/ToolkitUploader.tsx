import { useMemo, useState } from "react";
import { createJob } from "../../api/toolkit";
import { FileDrop } from "../common/FileDrop";
import { Alert } from "../common/Alert";

function formatSize(size: number) {
  if (size < 1024) return `${size} B`;
  return `${(size / 1024).toFixed(1)} KB`;
}

export function ToolkitUploader(props: { onJobCreated: (jobId: string) => void }) {
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [queuedFiles, setQueuedFiles] = useState<File[]>([]);

  const canSubmit = queuedFiles.length > 0 && !loading;

  const queuedLabel = useMemo(() => {
    if (!queuedFiles.length) return "Adicione os arquivos e envie quando terminar.";
    if (queuedFiles.length === 1) return "1 arquivo pronto para criar o job.";
    return `${queuedFiles.length} arquivos prontos para criar o job.`;
  }, [queuedFiles]);

  function addFiles(files: File[]) {
    setErr(null);
    setQueuedFiles((current) => {
      const next = [...current];
      for (const file of files) {
        const alreadyAdded = next.some(
          (item) =>
            item.name === file.name &&
            item.size === file.size &&
            item.lastModified === file.lastModified
        );
        if (!alreadyAdded) next.push(file);
      }
      return next;
    });
  }

  function removeFile(target: File) {
    setQueuedFiles((current) =>
      current.filter(
        (file) =>
          !(
            file.name === target.name &&
            file.size === target.size &&
            file.lastModified === target.lastModified
          )
      )
    );
  }

  async function submitJob() {
    if (!queuedFiles.length) return;

    setErr(null);
    setLoading(true);
    try {
      const res = await createJob(queuedFiles);
      setQueuedFiles([]);
      props.onJobCreated(res.jobId);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Erro ao criar job");
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
          label="Adicionar arquivos ao job"
          multiple
          accept=".pem,.crt,.cer,.key,.pfx,.p12,.txt"
          onFiles={addFiles}
        />
      </div>

      <div style={{ marginTop: 12 }}>
        <div className="small">{queuedLabel}</div>
      </div>

      {queuedFiles.length ? (
        <div className="list" style={{ marginTop: 10 }}>
          {queuedFiles.map((file) => (
            <div
              className="listRow"
              key={`${file.name}:${file.size}:${file.lastModified}`}
            >
              <div className="listMain">
                <div className="listTitle" title={file.name}>
                  {file.name}
                </div>
                <div className="small">{formatSize(file.size)}</div>
              </div>
              <button className="btn" disabled={loading} onClick={() => removeFile(file)} type="button">
                Remover
              </button>
            </div>
          ))}
        </div>
      ) : null}

      <div style={{ marginTop: 12, display: "flex", gap: 10, flexWrap: "wrap" }}>
        <button className="btn primary" disabled={!canSubmit} onClick={submitJob} type="button">
          {loading ? "Criando job..." : "Criar job com os arquivos"}
        </button>
        <button
          className="btn"
          disabled={!queuedFiles.length || loading}
          onClick={() => setQueuedFiles([])}
          type="button"
        >
          Limpar fila
        </button>
      </div>

      <div className="small" style={{ marginTop: 10 }}>
        {loading
          ? "Criando job..."
          : "Dica: voce pode adicionar certificado e chave em selecoes separadas antes de criar o job."}
      </div>
    </div>
  );
}
