import type { Artifact, InputFile, ParsedObject } from "../domain/types.js";
import forge from "../vendor/forge.js";
import { ToolkitException } from "../utils/errors.js";
import {
  certificateArtifactBaseName,
  collectCertificatePems,
  collectPrivateKeyPems,
  createArtifact,
  extractMaterialsFromPkcs12,
  resolveCertificateSelection,
  resolveCertificateSelectionFromPems,
  resolveCertificateKeyPair,
  resolveCertificateKeyPairFromPems,
  resolveServerCertificateChainFromPems
} from "../crypto/materials.js";
import { assertPrivateKeyMatchesCertificate } from "../crypto/pkcs12Validation.js";

type ExportFormat = "pem" | "crt" | "key" | "der" | "pfx" | "p12";

function buildPkcs12Artifact(filename: string, certPems: string[], keyPem: string, password: string): Artifact {
  assertPrivateKeyMatchesCertificate(certPems[0] ?? "", keyPem);
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
  params: { formats: string[]; sourcePassword?: string | undefined; outputPassword?: string | undefined }
): Artifact[] {
  const formats = Array.from(
    new Set(
      (params.formats ?? [])
        .map((value) => String(value).trim().toLowerCase())
        .filter(Boolean)
    )
  ) as ExportFormat[];

  if (formats.length === 0) {
    throw new ToolkitException("FORMATS_REQUIRED", "Escolha pelo menos um formato para gerar.", 400);
  }

  const supported = new Set<ExportFormat>(["pem", "crt", "key", "der", "pfx", "p12"]);
  const unsupported = formats.filter((format) => !supported.has(format));
  if (unsupported.length > 0) {
    throw new ToolkitException(
      "UNSUPPORTED_FORMAT",
      `Formato nao suportado: ${unsupported.join(", ")}.`,
      400
    );
  }

  let certPems = collectCertificatePems(files, parsed);
  let keyPems = collectPrivateKeyPems(files, parsed);
  let keyPem = keyPems[0] ?? null;

  if (
    certPems.length === 0 ||
    (formats.includes("key") && keyPems.length === 0) ||
    ((formats.includes("pfx") || formats.includes("p12")) && !keyPem)
  ) {
    const materials = extractMaterialsFromPkcs12(files, parsed, params.sourcePassword);
    if (materials) {
      if (certPems.length === 0) certPems = materials.certPems;
      if (keyPems.length === 0 && materials.keyPem) {
        keyPems = [materials.keyPem];
        keyPem = materials.keyPem;
      }
    }
  }

  if (certPems.length === 0 && formats.some((format) => format !== "key")) {
    throw new ToolkitException("CERT_NOT_FOUND", "Nao encontramos um certificado valido para essa conversao.", 400);
  }

  const primaryCertPem = certPems[0];
  if (!primaryCertPem && formats.some((format) => format !== "key")) {
    throw new ToolkitException("CERT_NOT_FOUND", "Nao encontramos um certificado principal para essa conversao.", 400);
  }

  const artifacts: Artifact[] = [];
  const artifactBaseName = certificateArtifactBaseName(files, parsed);
  const needsResolvedPair = formats.some((format) => format === "key" || format === "pfx" || format === "p12");
  const needsSingleCertificate = formats.some((format) => format === "crt" || format === "der");
  const resolvedCertificate =
    certPems.length > 0 && needsSingleCertificate
      ? resolveCertificateSelection(files, parsed) ??
        resolveCertificateSelectionFromPems(certPems)
      : null;
  const resolvedPair =
    certPems.length > 0 && keyPems.length > 0 && needsResolvedPair
      ? resolveCertificateKeyPair(
          files,
          parsed
        ) ??
        resolveCertificateKeyPairFromPems(certPems, keyPems)
      : null;

  for (const format of formats) {
    if (format === "pem") {
      const certificatePem = resolveCertificateSelectionFromPems(certPems).certPem;
      artifacts.push(
        createArtifact(`${artifactBaseName}.pem`, "application/x-pem-file", Buffer.from(certificatePem, "utf8"))
      );
      continue;
    }

    if (format === "crt") {
      if (!resolvedCertificate) {
        throw new ToolkitException("CERT_NOT_FOUND", "Nao encontramos um certificado principal para essa conversao.", 400);
      }
      artifacts.push(
        createArtifact(`${artifactBaseName}.crt`, "application/x-x509-ca-cert", Buffer.from(resolvedCertificate.certPem, "utf8"))
      );
      continue;
    }

    if (format === "key") {
      if (!resolvedPair?.keyPem) {
        throw new ToolkitException("KEY_NOT_FOUND", "Nao encontramos uma chave privada para essa conversao.", 400);
      }
      artifacts.push(createArtifact(`${artifactBaseName}.key`, "application/x-pem-file", Buffer.from(resolvedPair.keyPem, "utf8")));
      continue;
    }

    if (format === "der") {
      if (!resolvedCertificate) {
        throw new ToolkitException("CERT_NOT_FOUND", "Nao encontramos um certificado principal para essa conversao.", 400);
      }
      const cert = forge.pki.certificateFromPem(resolvedCertificate.certPem);
      const asn1 = forge.pki.certificateToAsn1(cert);
      const der = forge.asn1.toDer(asn1).getBytes();
      artifacts.push(createArtifact(`${artifactBaseName}.der`, "application/pkix-cert", Buffer.from(der, "binary")));
      continue;
    }

    if (!resolvedPair?.keyPem) {
      throw new ToolkitException("KEY_NOT_FOUND", "Nao encontramos uma chave privada para gerar o arquivo.", 400);
    }

    if (!params.outputPassword) {
      throw new ToolkitException("PASSWORD_REQUIRED", "Informe uma senha para gerar o novo arquivo.", 400);
    }

    const serverChain = resolveServerCertificateChainFromPems(resolvedPair.allCertPems);

    artifacts.push(
      buildPkcs12Artifact(
        `${artifactBaseName}.${format}`,
        [serverChain.leafCertPem, ...serverChain.intermediateCertPems],
        resolvedPair.keyPem,
        params.outputPassword
      )
    );
  }

  return artifacts;
}
