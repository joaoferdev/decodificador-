import * as forgeNs from "node-forge";
import type { InputFile, ParsedObject, Artifact } from "../domain/types.js";
import { sha256Hex, randomId } from "../utils/crypto.js";
import { ToolkitException } from "../utils/errors.js";

const forge: any = (forgeNs as any).default ?? forgeNs;

function firstMatch(text: string, re: RegExp): string | null {
  const m = text.match(re);
  return m?.[0] ?? null;
}

function normalizePem(pem: string): string {
  
  const s = pem.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n").trim();
  return s.endsWith("\n") ? s : s + "\n";
}

export function recipeGeneratePkcs12(
  files: InputFile[],
  parsed: ParsedObject[],
  params: { password: string }
): Artifact {
  if (!params.password) throw new ToolkitException("PASSWORD_REQUIRED", "Senha é obrigatória para gerar PFX.");

  const certObj = parsed.find((p) => p.detectedType === "x509_certificate");
  const keyObj = parsed.find((p) => p.detectedType === "private_key");

  if (!certObj || !keyObj) {
    throw new ToolkitException( 
      "MISSING_INPUTS",
      "Para gerar PFX, é necessário certificado + chave privada (arquivos PEM)."
    );
  }

  if (keyObj.encrypted) {
    throw new ToolkitException(
      "KEY_ENCRYPTED",
      "No MVP, a geração de PFX aceita apenas chave não criptografada."
    );
  }

  const certFile = files.find((f) => f.id === certObj.inputId);
  const keyFile = files.find((f) => f.id === keyObj.inputId);
  if (!certFile || !keyFile) throw new ToolkitException("INPUT_NOT_FOUND", "Arquivos de entrada não encontrados.");

  const certText = certFile.bytes.toString("utf8");
  const keyText = keyFile.bytes.toString("utf8");

  // CERT
  const certPemRaw =
    firstMatch(certText, /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/) ??
    firstMatch(certText, /-----BEGIN TRUSTED CERTIFICATE-----[\s\S]*?-----END TRUSTED CERTIFICATE-----/);

  if (!certPemRaw) throw new ToolkitException("CERT_NOT_FOUND", "Certificado PEM não encontrado.");

  
  const certPem = normalizePem(
    certPemRaw
      .replace(/-----BEGIN TRUSTED CERTIFICATE-----/g, "-----BEGIN CERTIFICATE-----")
      .replace(/-----END TRUSTED CERTIFICATE-----/g, "-----END CERTIFICATE-----")
  );

  // KEY
  const keyPemRaw =
    firstMatch(keyText, /-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/) ??
    firstMatch(keyText, /-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----/) ??
    firstMatch(keyText, /-----BEGIN EC PRIVATE KEY-----[\s\S]*?-----END EC PRIVATE KEY-----/);

  if (!keyPemRaw) throw new ToolkitException("KEY_NOT_FOUND", "Chave privada PEM não encontrada.");

  const keyPem = normalizePem(keyPemRaw);

  // Parse com mensagens claras
  let cert: forgeNs.pki.Certificate;
  try {
    cert = forge.pki.certificateFromPem(certPem);
  } catch (e: any) {
    throw new ToolkitException("CERT_PARSE_FAILED", `Falha ao ler certificado PEM: ${String(e?.message ?? e)}`);
  }

  let key: any;
  try {
    key = forge.pki.privateKeyFromPem(keyPem);
  } catch (e: any) {
    throw new ToolkitException("KEY_PARSE_FAILED", `Falha ao ler chave privada PEM: ${String(e?.message ?? e)}`);
  }

  // Gera PKCS#12
  let p12Asn1: any;
  try {
    p12Asn1 = forge.pkcs12.toPkcs12Asn1(key, [cert], params.password, {
      generateLocalKeyId: true,
      friendlyName: "atlas-cert"
    });
  } catch (e: any) {
    throw new ToolkitException("PFX_BUILD_FAILED", `Falha ao montar PKCS#12: ${String(e?.message ?? e)}`);
  }

  const der = forge.asn1.toDer(p12Asn1).getBytes();
  const bytes = Buffer.from(der, "binary");

  return {
    id: randomId("artifact"),
    filename: "certificate.pfx",
    mimeType: "application/x-pkcs12",
    sha256: sha256Hex(bytes),
    bytes
  };
}