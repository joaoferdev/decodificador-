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
            <div className="workspaceEyebrow">Painel Atlas</div>
            <h2 className="workspaceTitle">Operacoes de certificados em um painel unico</h2>
            <p className="workspaceText">
              Decodificacao de CSR e conversao de arquivos em um painel unico, pronto para
              incorporacao.
            </p>
          </div>

          <div className="workspaceStats">
            <div className="workspaceBadge">
              <strong>2</strong>
              <span>Modos</span>
            </div>
            <div className="workspaceBadge accent">
              <strong>{jobId ? "1" : "0"}</strong>
              <span>Job ativo</span>
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
                <div className="card workspaceEmpty">Faca upload dos arquivos para comecar.</div>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
