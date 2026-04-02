import type { Artifact, InputFile, ParsedObject } from "../domain/types.js";
import forge from "../vendor/forge.js";
import {
  certificateArtifactBaseName,
  createArtifact,
  resolveCertificateKeyPair,
  resolveServerCertificateChainFromPems
} from "../crypto/materials.js";
import { assertPrivateKeyMatchesCertificate } from "../crypto/pkcs12Validation.js";
import { ToolkitException } from "../utils/errors.js";

export function recipeGeneratePkcs12(
  files: InputFile[],
  parsed: ParsedObject[],
  params: { password: string }
): Artifact {
  if (!params.password) {
    throw new ToolkitException("PASSWORD_REQUIRED", "Informe uma senha para gerar o arquivo PFX.", 400);
  }

  const pair = resolveCertificateKeyPair(files, parsed);

  if (!pair?.keyPem) {
    throw new ToolkitException(
      "MISSING_INPUTS",
      "Para gerar o arquivo, envie um certificado e uma chave privada compativeis."
    );
  }

  const serverChain = resolveServerCertificateChainFromPems(pair.allCertPems);
  assertPrivateKeyMatchesCertificate(pair.certPem, pair.keyPem);

  let certs: any[];
  try {
    certs = [serverChain.leafCertPem, ...serverChain.intermediateCertPems].map((pem) => forge.pki.certificateFromPem(pem));
  } catch (error: any) {
    throw new ToolkitException("CERT_PARSE_FAILED", "Nao foi possivel ler o certificado enviado.", 400);
  }

  let key: any;
  try {
    key = forge.pki.privateKeyFromPem(pair.keyPem);
  } catch (error: any) {
    throw new ToolkitException("KEY_PARSE_FAILED", "Nao foi possivel ler a chave privada enviada.", 400);
  }

  let p12Asn1: any;
  try {
    p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, certs, params.password, {
      generateLocalKeyId: true,
      friendlyName: "atlas-cert"
    });
  } catch (error: any) {
    throw new ToolkitException("PFX_BUILD_FAILED", "Nao foi possivel gerar o arquivo PFX/P12.", 400);
  }

  const der = forge.asn1.toDer(p12Asn1).getBytes();
  const artifactBaseName = certificateArtifactBaseName(files, parsed);
  return createArtifact(`${artifactBaseName}.pfx`, "application/x-pkcs12", Buffer.from(der, "binary"));
}
