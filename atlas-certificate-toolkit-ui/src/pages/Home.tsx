import { useState } from "react";
import { Tabs, type TabKey } from "../components/layout/Tabs";
import { CsrDecoder } from "../components/csr/CsrDecoder";
import { ToolkitUploader } from "../components/toolkit/ToolkitUploader";
import { JobRecipes } from "../components/toolkit/JobRecipes";

export function Home() {
  const [tab, setTab] = useState<TabKey>("csr");
  const [jobId, setJobId] = useState<string | null>(null);

  return (
    <div className="toolkitTheme">
      <section className="workspaceShell" id="status">
        <div className="workspaceHeader">
          <div className="workspaceLead">
            <div className="workspaceEyebrow">Toolkit Publico</div>
            <h2 className="workspaceTitle">CSR Decoder e conversao de certificados</h2>
            <p className="workspaceText">
              Use o decoder para consultar um CSR ou envie arquivos para converter e baixar o resultado.
            </p>
          </div>

          <div className="workspaceStats">
            <div className="workspaceBadge">
              <strong>2</strong>
              <span>Modos</span>
            </div>
            <div className="workspaceBadge accent">
              <strong>{jobId ? "1" : "0"}</strong>
              <span>Processamento ativo</span>
            </div>
          </div>
        </div>

        <div className="workspaceToolbar">
          <Tabs active={tab} onChange={setTab} />
        </div>

        <div style={{ height: 14 }} />

        {tab === "csr" ? (
          <div id="csr">
            <CsrDecoder />
          </div>
        ) : (
          <div className="toolkitWorkspace workspaceGrid" id="toolkit">
            <div className="toolkitSidebar">
              <ToolkitUploader onJobCreated={(id) => setJobId(id)} />
            </div>
            <div className="toolkitMain">
              {jobId ? (
                <JobRecipes jobId={jobId} onReset={() => setJobId(null)} />
              ) : (
                <div className="card workspaceEmpty">Envie os arquivos para comecar.</div>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
