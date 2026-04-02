import { createPrivateKey, createPublicKey, X509Certificate } from "node:crypto";
import { ToolkitException } from "../utils/errors.js";

function getCertificatePublicKeyDer(certPem: string): Buffer {
  try {
    const cert = new X509Certificate(certPem);
    return cert.publicKey.export({ type: "spki", format: "der" });
  } catch (error: unknown) {
    throw new ToolkitException("CERT_PARSE_FAILED", "Nao foi possivel ler o certificado enviado.", 400);
  }
}

function getPrivateKeyPublicKeyDer(keyPem: string): Buffer {
  const normalizedPem = String(keyPem);
  if (
    normalizedPem.includes("BEGIN ENCRYPTED PRIVATE KEY") ||
    normalizedPem.includes("Proc-Type: 4,ENCRYPTED") ||
    normalizedPem.includes("DEK-Info:")
  ) {
    throw new ToolkitException(
      "KEY_ENCRYPTED",
      "A chave privada enviada esta protegida por senha. Envie uma chave sem senha para continuar.",
      400
    );
  }

  try {
    const privateKey = createPrivateKey(normalizedPem);
    return createPublicKey(privateKey).export({ type: "spki", format: "der" });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (
      message.includes("passphrase") ||
      message.includes("password") ||
      message.includes("encrypted") ||
      message.includes("decrypt")
    ) {
      throw new ToolkitException(
        "KEY_ENCRYPTED",
        "A chave privada enviada esta protegida por senha. Envie uma chave sem senha para continuar.",
        400
      );
    }

    throw new ToolkitException("KEY_PARSE_FAILED", "Nao foi possivel ler a chave privada enviada.", 400);
  }
}

export function certificateMatchesPrivateKey(certPem: string, keyPem: string): boolean {
  const certPublicDer = getCertificatePublicKeyDer(certPem);
  const keyPublicDer = getPrivateKeyPublicKeyDer(keyPem);
  return certPublicDer.equals(keyPublicDer);
}

export function assertPrivateKeyMatchesCertificate(certPem: string, keyPem: string) {
  const matches = certificateMatchesPrivateKey(certPem, keyPem);

  if (!matches) {
    throw new ToolkitException(
      "KEY_CERT_MISMATCH",
      "A chave privada enviada nao corresponde a este certificado. Para continuar, envie o certificado e a chave privada do mesmo par.",
      400
    );
  }
}
