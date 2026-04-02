import type { InputFile, ParsedObject } from "../domain/types.js";
import {
  classifyCertificates,
  collectCertificatePems,
  collectPrivateKeyPems,
  resolveCertificateKeyPair,
  resolveServerCertificateChain
} from "../crypto/materials.js";
import { ToolkitException } from "../utils/errors.js";

export type Analysis = {
  warnings: Array<{ code: string; message: string }>;
};

export function analyze(files: InputFile[], parsed: ParsedObject[]): Analysis {
  const warnings: Array<{ code: string; message: string }> = [];

  const now = Date.now();
  for (const p of parsed) {
    if (p.detectedType === "x509_certificate" && p.notAfter) {
      const exp = Date.parse(p.notAfter);
      if (!Number.isNaN(exp) && exp < now) {
        warnings.push({ code: "CERT_EXPIRED", message: `Esse certificado expirou em ${p.notAfter}` });
      }
    }
    if (p.detectedType === "x509_certificate" && p.isCertificateAuthority) {
      warnings.push({
        code: p.isSelfSigned ? "ROOT_CA_CERTIFICATE" : "INTERMEDIATE_CA_CERTIFICATE",
        message: p.isSelfSigned
          ? "Este arquivo parece ser um certificado raiz da cadeia. Ele nao costuma ser usado como certificado principal do servidor."
          : "Este arquivo parece ser um certificado intermediario da cadeia. Ele nao costuma ser usado como certificado principal do servidor."
      });
    }
    if (p.detectedType === "private_key" && p.encrypted) {
      warnings.push({ code: "KEY_ENCRYPTED", message: "A chave privada esta protegida por senha. Ela precisara ser desbloqueada para gerar um PFX." });
    }
  }

  const certPems = collectCertificatePems(files, parsed);
  const keyPems = collectPrivateKeyPems(files, parsed);
  const certRoles = classifyCertificates(certPems);
  if (certRoles.leafCertificates.length > 1 || (certRoles.leafCertificates.length === 0 && certPems.length > 1)) {
    warnings.push({
      code: "MULTIPLE_CERTIFICATES",
      message: "Encontramos mais de um certificado. Para evitar erro, envie apenas o certificado que deseja converter."
    });
  }
  if (keyPems.length > 1) {
    warnings.push({
      code: "MULTIPLE_PRIVATE_KEYS",
      message: "Encontramos mais de uma chave privada. Para evitar erro, envie apenas a chave privada correta."
    });
  }
  if (certPems.length > 0 && keyPems.length > 0) {
    try {
      resolveCertificateKeyPair(files, parsed);
    } catch (error: unknown) {
      if (
        error instanceof ToolkitException &&
        (
          error.code === "KEY_CERT_MISMATCH" ||
          error.code === "AMBIGUOUS_CERT_KEY_PAIR" ||
          error.code === "SERVER_CERT_REQUIRED"
        )
      ) {
        warnings.push({
          code: error.code,
          message: error.message
        });
      }
    }
  }

  if (certPems.length > 0) {
    if (certRoles.rootCertificates.length > 0) {
      warnings.push({
        code: "ROOT_INCLUDED",
        message: "Encontramos um certificado raiz. Na maioria dos servidores, ele nao precisa entrar no PFX nem no fullchain."
      });
    }

    try {
      resolveServerCertificateChain(files, parsed);
    } catch (error: unknown) {
      if (
        error instanceof ToolkitException &&
        (
          error.code === "INTERMEDIATE_CERT_REQUIRED" ||
          error.code === "SERVER_CERT_REQUIRED" ||
          error.code === "AMBIGUOUS_SERVER_CERTIFICATE" ||
          error.code === "CHAIN_INVALID"
        )
      ) {
        warnings.push({
          code: error.code,
          message: error.message
        });
      }
    }
  }

  return { warnings };
}
