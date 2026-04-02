import type { Artifact, InputFile, ParsedObject } from "../domain/types.js";
import {
  certificateArtifactBaseName,
  createArtifact,
  extractMaterialsFromPkcs12,
  resolveServerCertificateChain,
  resolveServerCertificateChainFromPems
} from "../crypto/materials.js";
import { ToolkitException } from "../utils/errors.js";

export function recipeBuildBundle(
  files: InputFile[],
  parsed: ParsedObject[],
  params?: { sourcePassword?: string }
): Artifact[] {
  let chain = resolveServerCertificateChain(files, parsed);
  if (!chain) {
    const materials = extractMaterialsFromPkcs12(files, parsed, params?.sourcePassword);
    if (!materials) {
      throw new ToolkitException(
        "SERVER_CERT_REQUIRED",
        "Envie o certificado do servidor e os intermediarios para gerar o fullchain.",
        400
      );
    }
    chain = resolveServerCertificateChainFromPems(materials.certPems);
  }

  const chainPem = `${chain.intermediateCertPems.join("\n")}\n`;
  const bundle = `${[chain.leafCertPem, ...chain.intermediateCertPems].join("\n")}\n`;
  const artifactBaseName = certificateArtifactBaseName(files, parsed);
  return [
    createArtifact(`${artifactBaseName}-chain.pem`, "application/x-pem-file", Buffer.from(chainPem, "utf8")),
    createArtifact(`${artifactBaseName}-fullchain.pem`, "application/x-pem-file", Buffer.from(bundle, "utf8"))
  ];
}
