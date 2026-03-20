import { useEffect, useMemo, useState } from "react";
import type { JobPublic, ParsedItem, Warning } from "../../api/toolkit";
import { downloadArtifact, getJob, runRecipe } from "../../api/toolkit";
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

function hasType(job: JobPublic | null, t: string) {
  const want = String(t).trim().toLowerCase();
  return (job?.parsed ?? []).some((p) => String(p.detectedType).trim().toLowerCase() === want);
}

function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

type ConversionKey =
  | "export_pem"
  | "export_crt"
  | "export_der"
  | "export_key"
  | "generate_pfx"
  | "generate_p12"
  | "extract_pkcs12"
  | "build_bundle";

type ConversionOption = {
  key: ConversionKey;
  label: string;
  requirements: string;
  passwordMode: "none" | "source" | "output" | "source-and-output";
  isEnabled: boolean;
  run: () => Promise<void>;
  buttonLabel: string;
  primary?: boolean;
};

export function JobRecipes(props: { jobId: string; onReset?: () => void }) {
  const jobId = props.jobId;

  const [job, setJob] = useState<JobPublic | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [selectedAction, setSelectedAction] = useState<ConversionKey>("export_pem");

  const [sourcePassword, setSourcePassword] = useState("");
  const [outputPassword, setOutputPassword] = useState("");
  const [showSourcePassword, setShowSourcePassword] = useState(false);
  const [showOutputPassword, setShowOutputPassword] = useState(false);

  async function refresh() {
    const j = await getJob(jobId);
    setJob(j);
  }

  function clearAll() {
    setErr(null);
    setBusy(null);
    setLoading(false);
    setSourcePassword("");
    setOutputPassword("");
    setShowSourcePassword(false);
    setShowOutputPassword(false);
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
      } catch (e: unknown) {
        if (alive) setErr(errorMessage(e, "Falha ao carregar job"));
      }
    })();

    return () => {
      alive = false;
    };
  }, [jobId]);

  const hasCert = useMemo(() => hasType(job, "x509_certificate"), [job]);
  const hasKey = useMemo(() => hasType(job, "private_key"), [job]);
  const hasPkcs12 = useMemo(() => hasType(job, "pkcs12"), [job]);

  const onlyPkcs12 = hasPkcs12 && !hasCert && !hasKey;
  const canBuildBundle = hasCert;
  const canExtractPkcs12 = hasPkcs12;
  const canExportCert = hasCert || hasPkcs12;
  const canExportKey = hasKey || hasPkcs12;
  const canGeneratePkcs12 = (hasCert && hasKey) || hasPkcs12;

  const warnings: Warning[] = job?.analysis?.warnings ?? [];
  const artifacts = job?.artifacts ?? [];

  async function doRecipe(recipe: string, body?: Record<string, unknown>) {
    setErr(null);
    setLoading(true);
    setBusy(recipe);
    try {
      await runRecipe(jobId, recipe, body ?? {});
      await refresh();
    } catch (e: unknown) {
      setErr(errorMessage(e, "Erro ao executar ação"));
    } finally {
      setLoading(false);
      setBusy(null);
    }
  }

  function exportFormats(formats: string[], needsOutputPassword = false) {
    return doRecipe("export_formats", {
      formats,
      ...(onlyPkcs12 ? { sourcePassword } : {}),
      ...(needsOutputPassword ? { outputPassword } : {})
    });
  }

  const options: ConversionOption[] = [
    {
      key: "export_pem",
      label: "Exportar PEM",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado (.pem/.crt) ou PFX/P12",
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: canExportCert,
      run: () => exportFormats(["pem"]),
      buttonLabel: "Exportar PEM"
    },
    {
      key: "export_crt",
      label: "Exportar CRT",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado (.pem/.crt) ou PFX/P12",
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: canExportCert,
      run: () => exportFormats(["crt"]),
      buttonLabel: "Exportar CRT"
    },
    {
      key: "export_der",
      label: "Exportar DER",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado (.pem/.crt) ou PFX/P12",
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: canExportCert,
      run: () => exportFormats(["der"]),
      buttonLabel: "Exportar DER"
    },
    {
      key: "export_key",
      label: "Exportar KEY",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Chave privada (.key/.pem) ou PFX/P12",
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: canExportKey,
      run: () => exportFormats(["key"]),
      buttonLabel: "Exportar KEY"
    },
    {
      key: "generate_pfx",
      label: "Gerar PFX",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado + chave privada ou PFX/P12",
      passwordMode: onlyPkcs12 ? "source-and-output" : "output",
      isEnabled: canGeneratePkcs12,
      run: () => exportFormats(["pfx"], true),
      buttonLabel: "Gerar PFX",
      primary: true
    },
    {
      key: "generate_p12",
      label: "Gerar P12",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado + chave privada ou PFX/P12",
      passwordMode: onlyPkcs12 ? "source-and-output" : "output",
      isEnabled: canGeneratePkcs12,
      run: () => exportFormats(["p12"], true),
      buttonLabel: "Gerar P12",
      primary: true
    },
    {
      key: "extract_pkcs12",
      label: "Extrair PKCS#12",
      requirements: "PFX/P12 + senha de origem",
      passwordMode: "source",
      isEnabled: canExtractPkcs12,
      run: () => doRecipe("extract_pkcs12", { password: sourcePassword }),
      buttonLabel: "Extrair PKCS#12"
    },
    {
      key: "build_bundle",
      label: "Gerar Bundle",
      requirements: "Certificado(s) em PEM/CRT",
      passwordMode: "none",
      isEnabled: canBuildBundle,
      run: () => doRecipe("build_bundle"),
      buttonLabel: "Gerar Bundle"
    }
  ];

  const selected = options.find((option) => option.key === selectedAction) ?? options[0];
  const requiresSourcePassword =
    selected.passwordMode === "source" || selected.passwordMode === "source-and-output";
  const requiresOutputPassword =
    selected.passwordMode === "output" || selected.passwordMode === "source-and-output";
  const missingPassword =
    (requiresSourcePassword && !sourcePassword.trim()) ||
    (requiresOutputPassword && !outputPassword.trim());

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <div>
          <div className="sectionTitle">Conversor de arquivos</div>
          <div className="small">
            Job: <code>{jobId}</code>
          </div>
        </div>

        <div className="row" style={{ gap: 8 }}>
          <button
            className="btn"
            disabled={loading}
            onClick={() =>
              refresh().catch((e: unknown) => setErr(errorMessage(e, "Falha ao atualizar")))
            }
          >
            Atualizar
          </button>
          <button className="btn" disabled={loading} onClick={clearAll}>
            Novo Job
          </button>
        </div>
      </div>

      <div className="divider" />

      {err ? <Alert kind="err" title="Erro" message={err} /> : null}

      <div className="grid2" style={{ marginTop: 12 }}>
        <div className="cardInner">
          <div className="sectionTitle">Entradas do job</div>

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
            <div className="small">Carregando...</div>
          )}

          <div className="divider" />

          <div className="sectionTitle">Detecção</div>
          {(job?.parsed ?? []).length ? (
            <div className="chips">
              {(job?.parsed ?? []).map((p: ParsedItem, idx: number) => (
                <div className="chip" key={`${p.inputId}:${p.detectedType}:${idx}`}>
                  <strong>{String(p.detectedType).toUpperCase()}</strong>
                  <span className="small" title={p.subject ?? p.inputId}>
                    {p.subject ? p.subject : p.inputId}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="small">Nenhum arquivo detectado ainda.</div>
          )}

          {warnings.length ? (
            <>
              <div className="divider" />
              <div className="sectionTitle">Avisos</div>
              <div className="list">
                {warnings.map((w, i) => (
                  <Alert key={i} kind="warn" title={w.code} message={w.message} />
                ))}
              </div>
            </>
          ) : null}
        </div>

        <div className="cardInner">
          <div className="sectionTitle">Conversão</div>
          <div className="small">Escolha o formato e execute uma ação por vez.</div>

          <div className="conversionPanel">
            <div className="conversionTopbar">
              <div className="conversionField">
                <label className="small">Tipo de conversão</label>
                <select
                  className="input selectInput"
                  value={selected.key}
                  onChange={(e) => setSelectedAction(e.target.value as ConversionKey)}
                >
                  {options.map((option) => (
                    <option key={option.key} value={option.key}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>

              <div className="conversionActions">
                <button
                  className={selected.primary ? "btn primary" : "btn"}
                  disabled={!selected.isEnabled || loading || missingPassword}
                  onClick={() => selected.run()}
                >
                  {busy ? "Processando..." : selected.buttonLabel}
                </button>
              </div>
            </div>

            <div className="conversionSummary">
              <div className="conversionSummaryRow">
                <span className="recipeLabel">Necessário</span>
                <strong>{selected.requirements}</strong>
              </div>
              {!selected.isEnabled ? (
                <div className="conversionSummaryRow">
                  <span className="recipeLabel">Status</span>
                  <strong>Envie os arquivos exigidos para habilitar esta conversão.</strong>
                </div>
              ) : null}
              <div className="conversionMeta">
                <div className="metaChip">
                  <span className="recipeLabel">Formato</span>
                  <strong>{selected.label}</strong>
                </div>
                <div className="metaChip">
                  <span className="recipeLabel">Senha</span>
                  <strong>
                    {requiresSourcePassword && requiresOutputPassword
                      ? "Origem + geração"
                      : requiresSourcePassword
                        ? "Arquivo de origem"
                        : requiresOutputPassword
                          ? "Arquivo gerado"
                          : "Não exige"}
                  </strong>
                </div>
              </div>
            </div>

            {requiresSourcePassword ? (
              <div className="conversionField">
                <label className="small">Senha do arquivo de origem</label>
                <div className="row actionPasswordControls">
                  <input
                    className="input"
                    type={showSourcePassword ? "text" : "password"}
                    value={sourcePassword}
                    onChange={(e) => setSourcePassword(e.target.value)}
                    placeholder="senha do PFX/P12"
                    autoComplete="off"
                    inputMode="text"
                  />
                  <button className="btn" type="button" onClick={() => setShowSourcePassword((s) => !s)}>
                    {showSourcePassword ? "Ocultar" : "Mostrar"}
                  </button>
                </div>
              </div>
            ) : null}

            {requiresOutputPassword ? (
              <div className="conversionField">
                <label className="small">Senha do arquivo gerado</label>
                <div className="row actionPasswordControls">
                  <input
                    className="input"
                    type={showOutputPassword ? "text" : "password"}
                    value={outputPassword}
                    onChange={(e) => setOutputPassword(e.target.value)}
                    placeholder="defina a senha"
                    autoComplete="off"
                    inputMode="text"
                  />
                  <button className="btn" type="button" onClick={() => setShowOutputPassword((s) => !s)}>
                    {showOutputPassword ? "Ocultar" : "Mostrar"}
                  </button>
                </div>
              </div>
            ) : null}

          </div>

          <div className="divider" />

          <div className="sectionTitle">Arquivos gerados</div>
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
            <div className="small">Nenhum arquivo gerado ainda.</div>
          )}
        </div>
      </div>
    </div>
  );
}
