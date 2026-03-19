import { useEffect, useMemo, useState } from "react";
import type { JobPublic } from "../../api/toolkit";
import { getJob, runRecipe, downloadArtifact } from "../../api/toolkit";
import { Alert } from "../common/Alert";

function bytes(n: number) {
  if (!Number.isFinite(n)) return "—";
  const units = ["B", "KB", "MB", "GB"];
  let x = n;
  let u = 0;
  while (x >= 1024 && u < units.length - 1) {
    x /= 1024;
    u++;
  }
  return `${x.toFixed(u === 0 ? 0 : 1)} ${units[u]}`;
}

// Case-insensitive + trim
function hasType(job: JobPublic | null, t: string) {
  const want = String(t).trim().toLowerCase();
  return (job?.parsed ?? []).some(
    (p: any) => String(p.detectedType).trim().toLowerCase() === want
  );
}

export function JobRecipes(props: { jobId: string; onReset?: () => void }) {
  const jobId = props.jobId;

  const [job, setJob] = useState<JobPublic | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const [extractPassword, setExtractPassword] = useState("");
  const [generatePassword, setGeneratePassword] = useState("");

  const [showExtractPw, setShowExtractPw] = useState(false);
  const [showGeneratePw, setShowGeneratePw] = useState(false);

  async function refresh() {
    const j = await getJob(jobId);
    setJob(j);
  }

  
  function clearAll() {
    setErr(null);
    setBusy(null);
    setLoading(false);

    setExtractPassword("");
    setGeneratePassword("");
    setShowExtractPw(false);
    setShowGeneratePw(false);

    setJob(null);

   
    props.onReset?.();
  }

  useEffect(() => {
    let alive = true;
    setErr(null);
    setJob(null);

    (async () => {
      try {
        const j = await getJob(jobId);
        if (alive) setJob(j);
      } catch (e: any) {
        if (alive) setErr(e?.message ?? String(e));
      }
    })();

    return () => {
      alive = false;
    };
  }, [jobId]);

  const canBuildBundle = useMemo(() => hasType(job, "x509_certificate"), [job]);
  const canExtractPfx = useMemo(() => hasType(job, "pkcs12"), [job]);
  const canGeneratePfx = useMemo(
    () => hasType(job, "x509_certificate") && hasType(job, "private_key"),
    [job]
  );

  const warnings = (job?.analysis?.warnings ?? []) as { code: string; message: string }[];
  const artifacts = job?.artifacts ?? [];

  async function doRecipe(recipe: string, body?: any) {
    setErr(null);
    setLoading(true);
    setBusy(recipe);

    try {
      await runRecipe(jobId, recipe, body ?? {});
      await refresh();
    } catch (e: any) {
      setErr(e?.message ?? "Erro ao executar recipe");
    } finally {
      setLoading(false);
      setBusy(null);
    }
  }

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <div>
          <div className="sectionTitle">CONVERSOR / CONVERTER</div>
          <div className="small">
            Job: <code>{jobId}</code>
          </div>
        </div>

        <div className="row" style={{ gap: 8 }}>
          <button
            className="btn"
            disabled={loading}
            onClick={() => refresh().catch((e) => setErr(e?.message ?? String(e)))}
          >
            Atualizar / Refresh
          </button>

          <button
            className="btn"
            disabled={loading}
            onClick={clearAll}
            title="Limpa o estado atual para você enviar novos arquivos e gerar outro PFX"
          >
            Limpar / Novo Job
          </button>
        </div>
      </div>

      <div className="divider" />

      {err ? <Alert kind="err" title="Erro / Error" message={err} /> : null}

      <div style={{ marginTop: 12 }} className="grid2">
        {/* ESQUERDA */}
        <div className="cardInner">
          <div className="sectionTitle">ARQUIVOS / INPUTS</div>

          {job?.inputs?.length ? (
            <div className="list">
              {job.inputs.map((f) => (
                <div className="listRow" key={f.id}>
                  <div className="listMain">
                    <div className="listTitle">{f.originalName}</div>
                    <div className="small">
                      {bytes(f.size)} • {f.mimeType}
                    </div>
                  </div>
                  <div className="pill">{f.id}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="small">Carregando / Loading…</div>
          )}

          <div className="divider" />

          <div className="sectionTitle">DETECÇÃO / DETECTION</div>
          {(job?.parsed ?? []).length ? (
            <div className="chips">
              {(job?.parsed ?? []).map((p: any, idx: number) => (
                <div className="chip" key={`${p.inputId}:${p.detectedType}:${idx}`}>
                  <strong>{String(p.detectedType).toUpperCase()}</strong>
                  <span
                    className="small"
                    style={{
                      marginLeft: 8,
                      maxWidth: 520,
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                      display: "inline-block",
                      verticalAlign: "bottom",
                    }}
                    title={p.subject ?? p.inputId}
                  >
                    {p.subject ? p.subject : p.inputId}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="small">Nenhum arquivo detectado ainda. / Nothing detected yet.</div>
          )}

          {warnings.length ? (
            <>
              <div className="divider" />
              <div className="sectionTitle">AVISOS / WARNINGS</div>
              <div className="row" style={{ alignItems: "stretch" }}>
                {warnings.map((w, i) => (
                  <Alert key={i} kind="warn" title={w.code} message={w.message} />
                ))}
              </div>
            </>
          ) : null}
        </div>

        {/* DIREITA */}
        <div className="cardInner">
          <div className="sectionTitle">AÇÕES / ACTIONS</div>

          <div className="actionGrid">
            {/* Build bundle */}
            <div className="actionCard">
              <div className="actionTitle">Montar CA Bundle</div>
              <div className="small">Build bundle (CRT + Chain)</div>
              <div className="divider" />

              <button
                className="btn primary"
                disabled={!canBuildBundle || loading}
                onClick={() => doRecipe("build_bundle")}
              >
                {busy === "build_bundle" ? "Processando..." : "Gerar Bundle / Build"}
              </button>

              {!canBuildBundle ? (
                <div className="small muted" style={{ marginTop: 8 }}>
                  Requer um certificado (.crt/.pem).
                </div>
              ) : null}
            </div>

            {/* Extract pkcs12 */}
            <div className="actionCard">
              <div className="actionTitle">Extrair PFX</div>
              <div className="small">Extract PKCS#12</div>
              <div className="divider" />

              <label className="small">Senha / Password</label>
              <div className="row" style={{ marginTop: 6 }}>
                <input
                  className="input"
                  type={showExtractPw ? "text" : "password"}
                  value={extractPassword}
                  onChange={(e) => setExtractPassword(e.target.value)}
                  placeholder="(se houver)"
                  name="extract-pfx-password"
                  autoComplete="off"
                  inputMode="text"
                />
                <button className="btn" onClick={() => setShowExtractPw((s) => !s)} type="button">
                  {showExtractPw ? "Ocultar" : "Mostrar"}
                </button>
              </div>

              <div style={{ marginTop: 10 }}>
                <button
                  className="btn primary"
                  disabled={!canExtractPfx || loading}
                  onClick={() => doRecipe("extract_pkcs12", { password: extractPassword })}
                >
                  {busy === "extract_pkcs12" ? "Extraindo..." : "Extrair / Extract"}
                </button>
              </div>

              {!canExtractPfx ? (
                <div className="small muted" style={{ marginTop: 8 }}>
                  Requer um .pfx/.p12.
                </div>
              ) : null}
            </div>

            {/* Generate pkcs12 */}
            <div className="actionCard">
              <div className="actionTitle">Gerar PFX</div>
              <div className="small">Generate PKCS#12 (CRT + KEY)</div>
              <div className="divider" />

              <label className="small">Senha / Password</label>
              <div className="row" style={{ marginTop: 6 }}>
                <input
                  className="input"
                  type={showGeneratePw ? "text" : "password"}
                  value={generatePassword}
                  onChange={(e) => setGeneratePassword(e.target.value)}
                  placeholder="defina uma senha"
                  name="generate-pfx-password"
                  autoComplete="new-password"
                  inputMode="text"
                />
                <button className="btn" onClick={() => setShowGeneratePw((s) => !s)} type="button">
                  {showGeneratePw ? "Ocultar" : "Mostrar"}
                </button>
              </div>

              <div style={{ marginTop: 10 }}>
                <button
                  className="btn primary"
                  disabled={!canGeneratePfx || loading || !generatePassword.trim()}
                  onClick={() => doRecipe("generate_pkcs12", { password: generatePassword })}
                >
                  {busy === "generate_pkcs12" ? "Gerando..." : "Gerar PFX / Generate"}
                </button>
              </div>

              {!canGeneratePfx ? (
                <div className="small muted" style={{ marginTop: 8 }}>
                  Requer <code>X509_CERTIFICATE</code> + <code>PRIVATE_KEY</code>. (chain opcional)
                </div>
              ) : null}

              {canGeneratePfx && !generatePassword.trim() ? (
                <div className="small muted" style={{ marginTop: 8 }}>
                  Defina uma senha para o PFX.
                </div>
              ) : null}
            </div>
          </div>

          <div className="divider" />

          <div className="sectionTitle">RESULTADOS / OUTPUTS</div>
          {artifacts.length ? (
            <div className="list">
              {artifacts.map((a) => (
                <div className="listRow" key={a.id}>
                  <div className="listMain">
                    <div className="listTitle" title={a.filename}>
                      {a.filename}
                    </div>
                    <div className="small">
                      {bytes(a.size)} • {a.mimeType}
                    </div>
                  </div>

                  <button className="btn" onClick={() => downloadArtifact(jobId, a.id)}>
                    Download
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="small">Nenhum arquivo gerado ainda. / No outputs yet.</div>
          )}
        </div>
      </div>
    </div>
  );
}