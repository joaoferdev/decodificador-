import type { ParsedObject } from "../domain/types.js";

export type Analysis = {
  warnings: Array<{ code: string; message: string }>;
};

export function analyze(parsed: ParsedObject[]): Analysis {
  const warnings: Array<{ code: string; message: string }> = [];

  const now = Date.now();
  for (const p of parsed) {
    if (p.detectedType === "x509_certificate" && p.notAfter) {
      const exp = Date.parse(p.notAfter);
      if (!Number.isNaN(exp) && exp < now) {
        warnings.push({ code: "CERT_EXPIRED", message: `Certificado expirado em ${p.notAfter}` });
      }
    }
    if (p.detectedType === "private_key" && p.encrypted) {
      warnings.push({ code: "KEY_ENCRYPTED", message: "Chave privada criptografada: será necessário senha para gerar PFX." });
    }
  }

  return { warnings };
}