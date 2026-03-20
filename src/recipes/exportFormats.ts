import * as forgeNs from "node-forge";
import type { Artifact, InputFile, ParsedObject } from "../domain/types.js";
import { randomId, sha256Hex } from "../utils/crypto.js";
import { ToolkitException } from "../utils/errors.js";

const forge: any = (forgeNs as any).default ?? forgeNs;
const OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1";
const OID_PKCS8_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";
const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";

type ExportFormat = "pem" | "crt" | "key" | "der" | "pfx" | "p12";

function createArtifact(filename: string, mimeType: string, bytes: Buffer): Artifact {
  return {
    id: randomId("artifact"),
    filename,
    mimeType,
    size: bytes.length,
    sha256: sha256Hex(bytes),
    bytes
  };
}

function normalizePem(pem: string): string {
  const s = pem.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n").trim();
  return s.endsWith("\n") ? s : `${s}\n`;
}

function extractPemBlocks(text: string, re: RegExp): string[] {
  return (text.match(re) ?? []).map((block) => normalizePem(block));
}

function collectCertificatePems(files: InputFile[], parsed: ParsedObject[]): string[] {
  const certIds = new Set(
    parsed
      .filter((p) => p.detectedType === "x509_certificate" && p.encoding === "pem")
      .map((p) => p.inputId)
  );

  const certs: string[] = [];
  for (const file of files) {
    if (!certIds.has(file.id)) continue;
    certs.push(
      ...extractPemBlocks(
        file.bytes.toString("utf8"),
        /-----BEGIN (?:TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:TRUSTED )?CERTIFICATE-----/g
      ).map((pem) =>
        pem
          .replace(/-----BEGIN TRUSTED CERTIFICATE-----/g, "-----BEGIN CERTIFICATE-----")
          .replace(/-----END TRUSTED CERTIFICATE-----/g, "-----END CERTIFICATE-----")
      )
    );
  }

  return certs;
}

function collectPrivateKeyPem(files: InputFile[], parsed: ParsedObject[]): string | null {
  const keyIds = new Set(
    parsed
      .filter((p) => p.detectedType === "private_key" && p.encoding === "pem")
      .map((p) => p.inputId)
  );

  for (const file of files) {
    if (!keyIds.has(file.id)) continue;
    const matches = extractPemBlocks(
      file.bytes.toString("utf8"),
      /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/g
    );
    if (matches.length > 0) return matches[0] ?? null;
  }

  return null;
}

function extractFromPkcs12(
  files: InputFile[],
  parsed: ParsedObject[],
  password: string | undefined
): { certPems: string[]; keyPem: string | null } | null {
  const pfxObj = parsed.find((p) => p.detectedType === "pkcs12");
  if (!pfxObj) return null;

  if (!password) {
    throw new ToolkitException(
      "PASSWORD_REQUIRED",
      "Informe a senha do PFX/P12 para exportar formatos derivados.",
      400
    );
  }

  const pfxFile = files.find((f) => f.id === pfxObj.inputId);
  if (!pfxFile) {
    throw new ToolkitException("INPUT_NOT_FOUND", "Arquivo PFX/P12 nao encontrado.", 400);
  }

  let p12: any;
  try {
    const pfxDer = forge.util.createBuffer(pfxFile.bytes.toString("binary"));
    const asn1 = forge.asn1.fromDer(pfxDer);
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, password);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.toLowerCase();

    if (normalized.includes("invalid password") || normalized.includes("mac could not be verified")) {
      throw new ToolkitException("PASSWORD_INVALID", "Senha do PFX/P12 invalida.", 400);
    }

    throw new ToolkitException("PKCS12_INVALID", "O arquivo enviado nao e um PFX/P12 valido.", 400);
  }

  const bagsPkcs8 = p12.getBags({ bagType: OID_PKCS8_SHROUDED_KEY_BAG }) as any;
  const bagsKey = p12.getBags({ bagType: OID_KEY_BAG }) as any;
  const keyBags = (bagsPkcs8?.[OID_PKCS8_SHROUDED_KEY_BAG] ?? bagsKey?.[OID_KEY_BAG] ?? []) as any[];
  const key = keyBags[0]?.key ?? null;

  const bagsCert = p12.getBags({ bagType: OID_CERT_BAG }) as any;
  const certBags = (bagsCert?.[OID_CERT_BAG] ?? []) as any[];
  const certPems = certBags.map((b) => normalizePem(forge.pki.certificateToPem(b.cert)));

  if (certPems.length === 0) {
    throw new ToolkitException("PFX_NO_CERT", "O PFX/P12 nao contem certificado utilizavel.", 400);
  }

  return {
    certPems,
    keyPem: key ? normalizePem(forge.pki.privateKeyToPem(key)) : null
  };
}

function buildPkcs12Artifact(filename: string, certPems: string[], keyPem: string, password: string): Artifact {
  const certs = certPems.map((pem) => forge.pki.certificateFromPem(pem));
  const key = forge.pki.privateKeyFromPem(keyPem);

  const p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, certs, password, {
    generateLocalKeyId: true,
    friendlyName: "atlas-cert"
  });

  const der = forge.asn1.toDer(p12Asn1).getBytes();
  return createArtifact(filename, "application/x-pkcs12", Buffer.from(der, "binary"));
}

export function recipeExportFormats(
  files: InputFile[],
  parsed: ParsedObject[],
  params: { formats: string[]; sourcePassword?: string; outputPassword?: string }
): Artifact[] {
  const formats = Array.from(
    new Set(
      (params.formats ?? [])
        .map((value) => String(value).trim().toLowerCase())
        .filter(Boolean)
    )
  ) as ExportFormat[];

  if (formats.length === 0) {
    throw new ToolkitException("FORMATS_REQUIRED", "Informe ao menos um formato para exportacao.", 400);
  }

  const unsupported = formats.filter((format) => !["pem", "crt", "key", "der", "pfx", "p12"].includes(format));
  if (unsupported.length > 0) {
    throw new ToolkitException(
      "UNSUPPORTED_FORMAT",
      `Formato(s) nao suportado(s): ${unsupported.join(", ")}.`,
      400
    );
  }

  let certPems = collectCertificatePems(files, parsed);
  let keyPem = collectPrivateKeyPem(files, parsed);

  if (
    certPems.length === 0 ||
    (formats.includes("key") && !keyPem) ||
    ((formats.includes("pfx") || formats.includes("p12")) && !keyPem)
  ) {
    const fromPkcs12 = extractFromPkcs12(files, parsed, params.sourcePassword);
    if (fromPkcs12) {
      if (certPems.length === 0) certPems = fromPkcs12.certPems;
      if (!keyPem) keyPem = fromPkcs12.keyPem;
    }
  }

  if (certPems.length === 0 && formats.some((format) => format !== "key")) {
    throw new ToolkitException("CERT_NOT_FOUND", "Nao foi encontrado certificado utilizavel para exportacao.", 400);
  }

  const artifacts: Artifact[] = [];
  const certBundle = certPems.join("");
  const primaryCertPem = certPems[0];

  if (!primaryCertPem && formats.some((format) => format !== "key")) {
    throw new ToolkitException("CERT_NOT_FOUND", "Nao foi encontrado certificado principal para exportacao.", 400);
  }

  const ensuredPrimaryCertPem = primaryCertPem ?? "";

  for (const format of formats) {
    if (format === "pem") {
      artifacts.push(createArtifact("certificates.pem", "application/x-pem-file", Buffer.from(certBundle, "utf8")));
      continue;
    }

    if (format === "crt") {
      artifacts.push(createArtifact("certificate.crt", "application/x-x509-ca-cert", Buffer.from(ensuredPrimaryCertPem, "utf8")));
      continue;
    }

    if (format === "key") {
      if (!keyPem) {
        throw new ToolkitException("KEY_NOT_FOUND", "Nao foi encontrada chave privada para exportacao.", 400);
      }
      artifacts.push(createArtifact("private.key", "application/x-pem-file", Buffer.from(keyPem, "utf8")));
      continue;
    }

    if (format === "der") {
      const cert = forge.pki.certificateFromPem(ensuredPrimaryCertPem);
      const asn1 = forge.pki.certificateToAsn1(cert);
      const der = forge.asn1.toDer(asn1).getBytes();
      artifacts.push(createArtifact("certificate.der", "application/pkix-cert", Buffer.from(der, "binary")));
      continue;
    }

    if (format === "pfx" || format === "p12") {
      if (!keyPem) {
        throw new ToolkitException("KEY_NOT_FOUND", "Nao foi encontrada chave privada para gerar PKCS#12.", 400);
      }
      if (!params.outputPassword) {
        throw new ToolkitException("PASSWORD_REQUIRED", "Defina uma senha para gerar PFX/P12.", 400);
      }
      artifacts.push(buildPkcs12Artifact(`certificate.${format}`, certPems, keyPem, params.outputPassword));
    }
  }

  return artifacts;
}
