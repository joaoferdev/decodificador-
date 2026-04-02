import type { JobPublic, ParsedItem, Warning } from "../../api/toolkit";
import { Alert } from "../common/Alert";
import { bytes } from "./helpers";

function typeLabel(item: ParsedItem) {
  if (item.detectedType === "x509_certificate") {
    if (item.isCertificateAuthority && item.isSelfSigned) return "Certificado raiz";
    if (item.isCertificateAuthority) return "Certificado intermediario";
    return "Certificado do servidor";
  }

  switch (item.detectedType) {
    case "private_key":
      return "Chave privada";
    case "pkcs12":
      return "Arquivo PFX/P12";
    case "csr":
      return "CSR";
    default:
      return "Arquivo identificado";
  }
}

function warningTitle(code: string) {
  switch (code) {
    case "KEY_CERT_MISMATCH":
      return "Certificado e chave nao correspondem";
    case "AMBIGUOUS_CERT_KEY_PAIR":
      return "Nao foi possivel identificar um unico par";
    case "MULTIPLE_CERTIFICATES":
      return "Mais de um certificado encontrado";
    case "MULTIPLE_PRIVATE_KEYS":
      return "Mais de uma chave privada encontrada";
    case "KEY_ENCRYPTED":
      return "Chave privada protegida por senha";
    case "CERT_EXPIRED":
      return "Certificado expirado";
    case "INTERMEDIATE_CA_CERTIFICATE":
      return "Certificado intermediario da cadeia";
    case "ROOT_CA_CERTIFICATE":
      return "Certificado raiz da cadeia";
    case "INTERMEDIATE_CERT_REQUIRED":
      return "Certificado intermediario necessario";
    case "SERVER_CERT_REQUIRED":
      return "Certificado principal do servidor necessario";
    case "AMBIGUOUS_SERVER_CERTIFICATE":
      return "Mais de um certificado principal encontrado";
    case "CHAIN_INVALID":
      return "Cadeia de certificados invalida";
    case "ROOT_INCLUDED":
      return "Certificado raiz encontrado";
    default:
      return "Atencao";
  }
}

function warningKind(code: string, hasServerCertificate: boolean) {
  if (code === "INTERMEDIATE_CA_CERTIFICATE" && hasServerCertificate) return "info" as const;
  if (code === "ROOT_CA_CERTIFICATE" && hasServerCertificate) return "info" as const;
  return "warn" as const;
}

function warningPresentation(warning: Warning, hasServerCertificate: boolean, job: JobPublic | null) {
  const intermediateItem = (job?.parsed ?? []).find(
    (item) => item.detectedType === "x509_certificate" && item.isCertificateAuthority && !item.isSelfSigned
  );
  const rootItem = (job?.parsed ?? []).find(
    (item) => item.detectedType === "x509_certificate" && item.isCertificateAuthority && item.isSelfSigned
  );
  const intermediateFileName =
    intermediateItem ? job?.inputs?.find((file) => file.id === intermediateItem.inputId)?.originalName : null;
  const rootFileName =
    rootItem ? job?.inputs?.find((file) => file.id === rootItem.inputId)?.originalName : null;

  if (warning.code === "INTERMEDIATE_CA_CERTIFICATE" && hasServerCertificate) {
    return {
      kind: "info" as const,
      title: "Certificado intermediario identificado",
      message: intermediateFileName
        ? `O arquivo ${intermediateFileName} foi identificado como intermediario da cadeia e sera usado junto com o certificado do servidor.`
        : "Esse arquivo foi identificado como intermediario da cadeia e sera usado junto com o certificado do servidor."
    };
  }

  if (warning.code === "ROOT_CA_CERTIFICATE" && hasServerCertificate) {
    return {
      kind: "info" as const,
      title: "Certificado raiz identificado",
      message: rootFileName
        ? `O arquivo ${rootFileName} e o certificado raiz da cadeia. Em muitos servidores ele nao precisa ser instalado junto.`
        : "Esse arquivo e o certificado raiz da cadeia. Em muitos servidores ele nao precisa ser instalado junto."
    };
  }

  return {
    kind: warningKind(warning.code, hasServerCertificate),
    title: warningTitle(warning.code),
    message: warning.message
  };
}

export function JobInputsPanel(props: { job: JobPublic | null; warnings: Warning[] }) {
  const { job, warnings } = props;
  const hasServerCertificate = (job?.parsed ?? []).some(
    (item) => item.detectedType === "x509_certificate" && !item.isCertificateAuthority
  );

  return (
    <div className="cardInner">
      <div className="sectionTitle">Arquivos enviados</div>

      {job?.inputs?.length ? (
        <div className="list">
          {job.inputs.map((file) => (
            <div className="listRow" key={file.id}>
              <div className="listMain">
                <div className="listTitle">{file.originalName}</div>
                <div className="small">{bytes(file.size)}</div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="small">Carregando...</div>
      )}

      <div className="divider" />

      <div className="sectionTitle">Arquivos identificados</div>
      {(job?.parsed ?? []).length > 0 ? (
        <div className="chips">
          {(job?.parsed ?? []).map((item: ParsedItem, index: number) => (
            <div className="chip" key={`${item.inputId}:${item.detectedType}:${index}`}>
              <strong>{typeLabel(item)}</strong>
              <span className="small" title={item.subject ?? item.inputId}>
                {item.subject ? item.subject : item.inputId}
              </span>
            </div>
          ))}
        </div>
      ) : (
        <div className="small">Nenhum arquivo identificado ainda.</div>
      )}

      {warnings.length > 0 ? (
        <>
          <div className="divider" />
          <div className="sectionTitle">Avisos</div>
          <div className="list">
            {warnings.map((warning, index) => {
              const presentation = warningPresentation(warning, hasServerCertificate, job);
              return (
                <Alert
                  key={index}
                  kind={presentation.kind}
                  title={presentation.title}
                  message={presentation.message}
                />
              );
            })}
          </div>
        </>
      ) : null}
    </div>
  );
}
