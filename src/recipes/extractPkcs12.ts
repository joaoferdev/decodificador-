import type { Artifact, InputFile, ParsedObject } from "../domain/types.js";
import {
  certificateArtifactBaseName,
  createArtifact,
  extractMaterialsFromPkcs12,
  resolveCertificateSelectionFromPems,
  resolveServerCertificateChainFromPems
} from "../crypto/materials.js";
import { ToolkitException } from "../utils/errors.js";

export function recipeExtractPkcs12(
  files: InputFile[],
  parsed: ParsedObject[],
  params: { password: string }
): Artifact[] {
  if (!params.password) {
    throw new ToolkitException("PASSWORD_REQUIRED", "Informe a senha do arquivo PFX/P12 para extrair os arquivos.", 400);
  }

  const materials = extractMaterialsFromPkcs12(files, parsed, params.password);
  if (!materials) {
    throw new ToolkitException("MISSING_PFX", "Envie um arquivo PFX ou P12 para extrair os arquivos.", 400);
  }

  if (!materials.keyPem) {
    throw new ToolkitException("PFX_NO_KEY", "O arquivo PFX/P12 nao contem uma chave privada utilizavel.", 400);
  }

  const artifactBaseName = certificateArtifactBaseName(files, parsed);
  const artifacts: Artifact[] = [
    createArtifact(`${artifactBaseName}.key`, "application/x-pem-file", Buffer.from(materials.keyPem, "utf8"))
  ];

  const selectedCertificate = resolveCertificateSelectionFromPems(materials.certPems);
  artifacts.push(
    createArtifact(`${artifactBaseName}.crt`, "application/x-x509-ca-cert", Buffer.from(selectedCertificate.certPem, "utf8"))
  );

  try {
    const chain = resolveServerCertificateChainFromPems(materials.certPems);
    artifacts.push(
      createArtifact(
        `${artifactBaseName}-chain.pem`,
        "application/x-pem-file",
        Buffer.from(`${chain.intermediateCertPems.join("\n")}\n`, "utf8")
      )
    );
    artifacts.push(
      createArtifact(
        `${artifactBaseName}-fullchain.pem`,
        "application/x-pem-file",
        Buffer.from(`${[chain.leafCertPem, ...chain.intermediateCertPems].join("\n")}\n`, "utf8")
      )
    );
  } catch (error) {
    if (!(error instanceof ToolkitException)) throw error;
    artifacts.push(
      createArtifact(
        `${artifactBaseName}-certificates.pem`,
        "application/x-pem-file",
        Buffer.from(materials.certPems.join(""), "utf8")
      )
    );
  }

  return artifacts;
}
