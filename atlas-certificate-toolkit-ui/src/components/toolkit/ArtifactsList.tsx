import type { ArtifactPublic } from "../../api/toolkit";
import { artifactUsage, bytes } from "./helpers";

export function ArtifactsList(props: {
  artifacts: ArtifactPublic[];
  onDownload: (artifactId: string, filename: string) => void;
}) {
  const { artifacts, onDownload } = props;

  return (
    <>
      <div className="sectionTitle">Arquivos gerados</div>
      {artifacts.length > 0 ? (
        <div className="list">
          {artifacts.map((artifact) => (
            <div className="listRow" key={artifact.id}>
              <div className="listMain">
                <div className="listTitle" title={artifact.filename}>
                  {artifact.filename}
                </div>
                <div className="small">
                  {bytes(artifact.size)} | {artifact.mimeType}
                </div>
                <div className="small">{artifactUsage(artifact.filename)}</div>
              </div>
              <button
                className="btn"
                onClick={() => onDownload(artifact.id, artifact.filename)}
                type="button"
              >
                Baixar arquivo
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="small">Nenhum arquivo gerado ainda.</div>
      )}
    </>
  );
}
