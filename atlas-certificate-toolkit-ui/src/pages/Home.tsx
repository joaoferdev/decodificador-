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
      <Tabs active={tab} onChange={setTab} />
      <div style={{ height: 12 }} />

      {tab === "csr" ? (
        <CsrDecoder />
      ) : (
        <div className="row" style={{ alignItems: "stretch" }}>
          <div style={{ flex: 1, minWidth: 320 }}>
            <ToolkitUploader onJobCreated={(id) => setJobId(id)} />
          </div>
          <div style={{ flex: 2, minWidth: 420 }}>
            {jobId ? (
              <JobRecipes jobId={jobId} onReset={() => setJobId(null)} />
            ) : (
              <div className="card">Faça upload dos arquivos para começar.</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}