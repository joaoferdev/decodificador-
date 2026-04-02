import { useEffect, useMemo, useState } from "react";
import type { JobPublic, Warning } from "../../api/toolkit";
import { downloadArtifact, getJob, runRecipe } from "../../api/toolkit";
import { Alert } from "../common/Alert";
import { ArtifactsList } from "./ArtifactsList";
import { errorMessage, formatExpiration, hasType, type ConversionOption, type ConversionKey } from "./helpers";
import { JobInputsPanel } from "./JobInputsPanel";
import { RecipeActionForm } from "./RecipeActionForm";

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
    setJob(await getJob(jobId));
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
        const nextJob = await getJob(jobId);
        if (alive) setJob(nextJob);
      } catch (error: unknown) {
        if (alive) setErr(errorMessage(error, "Nao foi possivel carregar esse processamento."));
      }
    })();

    return () => {
      alive = false;
    };
  }, [jobId]);

  const hasCert = useMemo(() => hasType(job, "x509_certificate"), [job]);
  const hasKey = useMemo(() => hasType(job, "private_key"), [job]);
  const hasPkcs12 = useMemo(() => hasType(job, "pkcs12"), [job]);
  const certificateItems = job?.parsed?.filter((item) => item.detectedType === "x509_certificate") ?? [];
  const hasLeafCertificate = certificateItems.some((item) => !item.isCertificateAuthority);
  const hasIntermediateCertificate = certificateItems.some((item) => item.isCertificateAuthority && !item.isSelfSigned);
  const onlyPkcs12 = hasPkcs12 && !hasCert && !hasKey;
  const warnings: Warning[] = job?.analysis?.warnings ?? [];
  const keyCertMismatch = warnings.find((warning) => warning.code === "KEY_CERT_MISMATCH") ?? null;
  const ambiguousPairWarning = warnings.find((warning) => warning.code === "AMBIGUOUS_CERT_KEY_PAIR") ?? null;
  const missingIntermediateWarning = warnings.find((warning) => warning.code === "INTERMEDIATE_CERT_REQUIRED") ?? null;
  const missingServerCertWarning = warnings.find((warning) => warning.code === "SERVER_CERT_REQUIRED") ?? null;
  const ambiguousServerCertWarning = warnings.find((warning) => warning.code === "AMBIGUOUS_SERVER_CERTIFICATE") ?? null;
  const multipleCertificatesWarning = warnings.find((warning) => warning.code === "MULTIPLE_CERTIFICATES") ?? null;
  const multiplePrivateKeysWarning = warnings.find((warning) => warning.code === "MULTIPLE_PRIVATE_KEYS") ?? null;
  const encryptedKeyWarning = warnings.find((warning) => warning.code === "KEY_ENCRYPTED") ?? null;
  const invalidChainWarning = warnings.find((warning) => warning.code === "CHAIN_INVALID") ?? null;
  const rootIncludedWarning = warnings.find((warning) => warning.code === "ROOT_INCLUDED") ?? null;
  const artifacts = job?.artifacts ?? [];
  const jobMissing = !job && !loading && !err;
  const canExportCertificateOnly = hasCert && !multipleCertificatesWarning;
  const expirationText = formatExpiration(job?.expiresAt);

  async function doRecipe(recipe: string, body?: Record<string, unknown>) {
    setErr(null);
    setLoading(true);
    setBusy(recipe);
    try {
      await runRecipe(jobId, recipe, body ?? {});
      await refresh();
    } catch (error: unknown) {
      const message = errorMessage(error, "Nao foi possivel concluir essa conversao.");
      if (/expirado|nao encontrado/i.test(message)) {
        props.onReset?.();
      }
      setErr(message);
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
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado (.pem/.crt/.cer/.der) ou PFX/P12",
      resultLabel: "Um arquivo PEM com o certificado.",
      deploymentHint: "Use quando o servidor pedir o certificado principal em PEM.",
      passwordHint: onlyPkcs12 ? "Informe a senha do arquivo enviado." : undefined,
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: (hasCert || hasPkcs12) && !multipleCertificatesWarning,
      unavailableReason: multipleCertificatesWarning
        ? "Encontramos mais de um certificado. Envie apenas o certificado que voce quer exportar."
        : undefined,
      run: () => exportFormats(["pem"]),
      buttonLabel: "Exportar PEM"
    },
    {
      key: "export_crt",
      label: "Exportar CRT",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado (.pem/.crt/.cer/.der) ou PFX/P12",
      resultLabel: "Um arquivo CRT com o certificado principal.",
      deploymentHint: "Use este arquivo como certificado principal em servidores que pedem CRT ou CER.",
      passwordHint: onlyPkcs12 ? "Informe a senha do arquivo enviado." : undefined,
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: (hasCert || hasPkcs12) && !multipleCertificatesWarning,
      unavailableReason: multipleCertificatesWarning
        ? "Encontramos mais de um certificado. Envie apenas o certificado que voce quer exportar."
        : undefined,
      run: () => exportFormats(["crt"]),
      buttonLabel: "Exportar CRT"
    },
    {
      key: "export_der",
      label: "Exportar DER",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Certificado (.pem/.crt/.cer/.der) ou PFX/P12",
      resultLabel: "Um arquivo DER com o certificado principal.",
      deploymentHint: "Use quando a plataforma exigir o certificado em DER binario.",
      passwordHint: onlyPkcs12 ? "Informe a senha do arquivo enviado." : undefined,
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: (hasCert || hasPkcs12) && !multipleCertificatesWarning,
      unavailableReason: multipleCertificatesWarning
        ? "Encontramos mais de um certificado. Envie apenas o certificado que voce quer exportar."
        : undefined,
      run: () => exportFormats(["der"]),
      buttonLabel: "Exportar DER"
    },
    {
      key: "export_key",
      label: "Exportar KEY",
      requirements: onlyPkcs12 ? "PFX/P12 + senha de origem" : "Chave privada (.key/.pem) ou PFX/P12",
      resultLabel: "Um arquivo KEY com a chave privada.",
      deploymentHint: "Use este arquivo como chave privada correspondente ao certificado principal.",
      passwordHint: onlyPkcs12 ? "Informe a senha do arquivo enviado." : undefined,
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled: (hasKey || hasPkcs12) && !multiplePrivateKeysWarning && !ambiguousPairWarning,
      unavailableReason: multiplePrivateKeysWarning
        ? "Encontramos mais de uma chave privada. Envie apenas a chave que voce quer exportar."
        : ambiguousPairWarning
          ? "Nao foi possivel identificar qual chave deve ser usada. Envie apenas um par de arquivos."
          : undefined,
      run: () => exportFormats(["key"]),
      buttonLabel: "Exportar KEY"
    },
    {
      key: "generate_pfx",
      label: "Gerar PFX",
      requirements: onlyPkcs12
        ? "PFX/P12 completo + senha de origem"
        : "Certificado do servidor + chave privada correspondente + intermediarios",
      resultLabel: "Um arquivo PFX pronto para uso no servidor.",
      passwordHint: onlyPkcs12
        ? "Informe a senha do arquivo enviado e a senha do novo PFX."
        : "Informe a senha do novo arquivo PFX.",
      validationHint: onlyPkcs12
        ? "Vamos usar o certificado e a chave do arquivo enviado para gerar um novo PFX."
        : "Antes de gerar o arquivo, vamos verificar se a chave privada pertence ao certificado enviado e se a cadeia esta correta.",
      deploymentHint: "Use este arquivo unico em IIS, Windows ou em plataformas que importam PFX/P12.",
      passwordMode: onlyPkcs12 ? "source-and-output" : "output",
      isEnabled:
        (((hasLeafCertificate && hasKey && hasIntermediateCertificate) || hasPkcs12) &&
          !keyCertMismatch &&
          !ambiguousPairWarning &&
          !missingIntermediateWarning &&
          !missingServerCertWarning &&
          !ambiguousServerCertWarning &&
          !invalidChainWarning),
      unavailableReason: keyCertMismatch
        ? "Para gerar PFX, envie a chave privada correspondente a este certificado."
        : ambiguousPairWarning
          ? "Nao foi possivel identificar um unico par de certificado e chave para gerar o PFX."
          : missingIntermediateWarning
            ? "Para gerar PFX, envie tambem o certificado intermediario da cadeia."
            : missingServerCertWarning
              ? "Para gerar PFX, envie o certificado principal do servidor."
              : ambiguousServerCertWarning
                ? "Encontramos mais de um certificado principal. Envie apenas o certificado do servidor correto."
                : invalidChainWarning
                  ? "Os certificados enviados nao formam uma cadeia valida para gerar um PFX pronto para servidor."
          : undefined,
      run: () => exportFormats(["pfx"], true),
      buttonLabel: "Gerar PFX",
      primary: true
    },
    {
      key: "generate_p12",
      label: "Gerar P12",
      requirements: onlyPkcs12
        ? "PFX/P12 completo + senha de origem"
        : "Certificado do servidor + chave privada correspondente + intermediarios",
      resultLabel: "Um arquivo P12 pronto para uso no servidor.",
      passwordHint: onlyPkcs12
        ? "Informe a senha do arquivo enviado e a senha do novo P12."
        : "Informe a senha do novo arquivo P12.",
      validationHint: onlyPkcs12
        ? "Vamos usar o certificado e a chave do arquivo enviado para gerar um novo P12."
        : "Antes de gerar o arquivo, vamos verificar se a chave privada pertence ao certificado enviado e se a cadeia esta correta.",
      deploymentHint: "Use este arquivo unico quando a plataforma pedir um P12 com certificado, chave e cadeia.",
      passwordMode: onlyPkcs12 ? "source-and-output" : "output",
      isEnabled:
        (((hasLeafCertificate && hasKey && hasIntermediateCertificate) || hasPkcs12) &&
          !keyCertMismatch &&
          !ambiguousPairWarning &&
          !missingIntermediateWarning &&
          !missingServerCertWarning &&
          !ambiguousServerCertWarning &&
          !invalidChainWarning),
      unavailableReason: keyCertMismatch
        ? "Para gerar P12, envie a chave privada correspondente a este certificado."
        : ambiguousPairWarning
          ? "Nao foi possivel identificar um unico par de certificado e chave para gerar o P12."
          : missingIntermediateWarning
            ? "Para gerar P12, envie tambem o certificado intermediario da cadeia."
            : missingServerCertWarning
              ? "Para gerar P12, envie o certificado principal do servidor."
              : ambiguousServerCertWarning
                ? "Encontramos mais de um certificado principal. Envie apenas o certificado do servidor correto."
                : invalidChainWarning
                  ? "Os certificados enviados nao formam uma cadeia valida para gerar um P12 pronto para servidor."
          : undefined,
      run: () => exportFormats(["p12"], true),
      buttonLabel: "Gerar P12",
      primary: true
    },
    {
      key: "extract_pkcs12",
      label: "Extrair PKCS#12",
      requirements: "PFX/P12 + senha de origem",
      resultLabel: "Certificado, chave privada e, quando existirem, os arquivos de chain e fullchain.",
      deploymentHint: "Use os arquivos extraidos conforme o tipo de servidor: CRT + KEY + CHAIN ou FULLCHAIN.",
      passwordHint: "Informe a senha do arquivo enviado para extrair os arquivos.",
      passwordMode: "source",
      isEnabled: hasPkcs12,
      run: () => doRecipe("extract_pkcs12", { password: sourcePassword }),
      buttonLabel: "Extrair PKCS#12"
    },
    {
      key: "build_bundle",
      label: "Gerar Fullchain",
      requirements: onlyPkcs12
        ? "PFX/P12 com certificado principal e intermediarios + senha de origem"
        : "Certificado do servidor + intermediarios da cadeia",
      resultLabel: "Um arquivo fullchain pronto para uso no servidor.",
      deploymentHint: "Use este arquivo como fullchain em Nginx, Apache e outros servidores Linux.",
      validationHint: "Vamos verificar se os intermediarios pertencem ao certificado principal e montar o fullchain na ordem correta.",
      passwordHint: onlyPkcs12 ? "Informe a senha do arquivo enviado para montar o fullchain." : undefined,
      passwordMode: onlyPkcs12 ? "source" : "none",
      isEnabled:
        ((hasLeafCertificate && hasIntermediateCertificate) || hasPkcs12) &&
        !multipleCertificatesWarning &&
        !missingIntermediateWarning &&
        !missingServerCertWarning &&
        !ambiguousServerCertWarning &&
        !invalidChainWarning,
      unavailableReason: missingIntermediateWarning
        ? "Para gerar o fullchain, envie tambem o certificado intermediario da cadeia."
        : missingServerCertWarning
          ? "Para gerar o fullchain, envie o certificado principal do servidor."
          : ambiguousServerCertWarning
            ? "Encontramos mais de um certificado principal. Envie apenas o certificado do servidor correto."
        : invalidChainWarning
          ? "Os certificados enviados nao formam uma cadeia valida para montar o fullchain."
        : multipleCertificatesWarning
          ? "Encontramos mais de um certificado. Envie apenas os certificados da mesma cadeia."
        : undefined,
      run: () => doRecipe("build_bundle", onlyPkcs12 ? { sourcePassword } : undefined),
      buttonLabel: "Gerar Fullchain"
    }
  ];

  const selected = options.find((option) => option.key === selectedAction) ?? options[0];
  const requiresSourcePassword =
    selected.passwordMode === "source" || selected.passwordMode === "source-and-output";
  const requiresOutputPassword =
    selected.passwordMode === "output" || selected.passwordMode === "source-and-output";
  const missingPassword =
    (requiresSourcePassword && sourcePassword.trim().length === 0) ||
    (requiresOutputPassword && outputPassword.trim().length === 0);

  return (
    <div className="card">
      <div className="row" style={{ justifyContent: "space-between", alignItems: "baseline" }}>
        <div>
          <div className="sectionTitle">Converter arquivos</div>
          <div className="small">Escolha o tipo de arquivo que voce quer gerar. {expirationText}</div>
        </div>

        <div className="row" style={{ gap: 8 }}>
          <button
            className="btn"
            disabled={loading}
            onClick={() => refresh().catch((error: unknown) => setErr(errorMessage(error, "Nao foi possivel atualizar os dados.")))}
            type="button"
          >
            Atualizar
          </button>
          <button className="btn" disabled={loading} onClick={clearAll} type="button">
            Enviar novos arquivos
          </button>
        </div>
      </div>

      <div className="divider" />

      {err ? <Alert kind="err" title="Nao foi possivel concluir a conversao" message={err} /> : null}
      {keyCertMismatch ? (
        <div style={{ marginTop: 12 }}>
          <Alert
            kind="warn"
            title="A chave privada nao corresponde a este certificado"
            message={
              canExportCertificateOnly
                ? "Voce ainda pode exportar arquivos do certificado, como PEM, CRT e DER. Para gerar PFX ou P12, envie a chave privada correspondente."
                : keyCertMismatch.message
            }
          />
        </div>
      ) : null}
      {!keyCertMismatch && ambiguousPairWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert
            kind="err"
            title="Nao foi possivel escolher um unico par de arquivos"
            message={ambiguousPairWarning.message}
          />
        </div>
      ) : null}
      {missingIntermediateWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="warn" title="Certificado intermediario necessario" message={missingIntermediateWarning.message} />
        </div>
      ) : null}
      {missingServerCertWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="warn" title="Certificado principal do servidor necessario" message={missingServerCertWarning.message} />
        </div>
      ) : null}
      {ambiguousServerCertWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="warn" title="Mais de um certificado principal encontrado" message={ambiguousServerCertWarning.message} />
        </div>
      ) : null}
      {invalidChainWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="err" title="A cadeia de certificados nao esta correta" message={invalidChainWarning.message} />
        </div>
      ) : null}
      {multipleCertificatesWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="warn" title="Mais de um certificado encontrado" message={multipleCertificatesWarning.message} />
        </div>
      ) : null}
      {multiplePrivateKeysWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="warn" title="Mais de uma chave privada encontrada" message={multiplePrivateKeysWarning.message} />
        </div>
      ) : null}
      {!keyCertMismatch && encryptedKeyWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="warn" title="Atencao antes de gerar PFX ou P12" message={encryptedKeyWarning.message} />
        </div>
      ) : null}
      {rootIncludedWarning ? (
        <div style={{ marginTop: 12 }}>
          <Alert kind="warn" title="Certificado raiz encontrado" message={rootIncludedWarning.message} />
        </div>
      ) : null}
      {jobMissing ? (
        <Alert
          kind="warn"
          title="Arquivos expirados"
          message="Os arquivos enviados nao estao mais disponiveis. Envie novamente para continuar."
        />
      ) : null}

      <div className="grid2" style={{ marginTop: 12 }}>
        <JobInputsPanel job={job} warnings={warnings} />

        <div className="cardInner">
          <div className="sectionTitle">Tipo de conversao</div>
          <div className="small">Escolha o arquivo que voce quer gerar.</div>

          <RecipeActionForm
            selectedKey={selectedAction}
            selected={selected}
            options={options}
            loading={loading}
            busy={busy}
            missingPassword={missingPassword}
            requiresSourcePassword={requiresSourcePassword}
            requiresOutputPassword={requiresOutputPassword}
            sourcePassword={sourcePassword}
            outputPassword={outputPassword}
            showSourcePassword={showSourcePassword}
            showOutputPassword={showOutputPassword}
            onChangeSelected={setSelectedAction}
            onChangeSourcePassword={setSourcePassword}
            onChangeOutputPassword={setOutputPassword}
            onToggleSourcePassword={() => setShowSourcePassword((state) => !state)}
            onToggleOutputPassword={() => setShowOutputPassword((state) => !state)}
          />

          <div className="divider" />

          <ArtifactsList
            artifacts={artifacts}
            onDownload={(artifactId, filename) => downloadArtifact(jobId, artifactId, filename)}
          />
          <div className="small" style={{ marginTop: 10 }}>
            Arquivos gerados ficam disponiveis por tempo limitado. {expirationText}
          </div>
        </div>
      </div>
    </div>
  );
}

