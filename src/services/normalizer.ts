import type { InputFile, ParsedObject } from "../domain/types.js";
import {
  type CertificateLike,
  type CsrLike,
  asn1FromDer,
  certificateFromAsn1,
  certificateToPem,
  certificateFromPem,
  certificationRequestFromPem,
  privateKeyFromPem
} from "../crypto/forgeAdapter.js";
import { detectPkcs12 } from "../crypto/materials.js";
import { detectEncoding, detectType } from "./detector.js";
import { splitPemBlocks } from "../utils/pem.js";
import { sha1Hex, sha256Hex } from "./fingerprints.js";

function dnToString(dn: { attributes?: Array<{ shortName?: string; name?: string; value?: unknown }> }): string {
  try {
    return (dn.attributes ?? [])
      .map((attribute) => `${attribute.shortName || attribute.name}=${String(attribute.value ?? "")}`)
      .join(", ");
  } catch {
    return "";
  }
}

function extractSansFromCert(cert: CertificateLike): string[] {
  const ext = cert.extensions?.find((item) => item.name === "subjectAltName");
  const altNames = ext?.altNames ?? [];
  return altNames
    .filter((item) => item.type === 2 && typeof item.value === "string")
    .map((item) => String(item.value));
}

function extractEkuFromCert(cert: CertificateLike): string[] {
  const eku = cert.extensions?.find((item) => item.name === "extKeyUsage");
  if (!eku) return [];
  return Object.keys(eku).filter((key) => eku[key] === true);
}

function certificateAuthorityInfo(cert: CertificateLike): {
  isCertificateAuthority: boolean;
  isSelfSigned: boolean;
} {
  const basicConstraints = cert.extensions?.find((item) => item.name === "basicConstraints");
  const subject = dnToString(cert.subject);
  const issuer = dnToString(cert.issuer);

  return {
    isCertificateAuthority: basicConstraints?.cA === true,
    isSelfSigned: Boolean(subject) && subject === issuer
  };
}

function publicKeyInfo(cert: CertificateLike): { publicKeyType: "RSA" | "EC" | "UNKNOWN"; publicKeyBits?: number } {
  const publicKey = cert.publicKey;

  if (publicKey?.n?.bitLength) {
    return { publicKeyType: "RSA", publicKeyBits: publicKey.n.bitLength() };
  }

  if (publicKey?.type === "ec" || publicKey?.curve || publicKey?.ecdsa) {
    return { publicKeyType: "EC" };
  }

  return { publicKeyType: "UNKNOWN" };
}

function tryParseCertificate(pem: string): CertificateLike | null {
  try {
    return certificateFromPem(pem);
  } catch {
    return null;
  }
}

function tryParseCsr(pem: string): CsrLike | null {
  try {
    return certificationRequestFromPem(pem);
  } catch {
    return null;
  }
}

function tryParsePrivateKey(pem: string): { encrypted: boolean; key: ReturnType<typeof privateKeyFromPem> | null } | null {
  try {
    return { encrypted: false, key: privateKeyFromPem(pem) };
  } catch {
    const encrypted = /ENCRYPTED PRIVATE KEY|Proc-Type:\s*4,ENCRYPTED/i.test(pem);
    return encrypted ? { encrypted: true, key: null } : null;
  }
}

function tryParseDerCertificate(bytes: Buffer): { cert: CertificateLike; pem: string } | null {
  try {
    const cert = certificateFromAsn1(asn1FromDer(bytes));
    return {
      cert,
      pem: certificateToPem(cert)
    };
  } catch {
    return null;
  }
}

function pushCertificate(
  output: ParsedObject[],
  file: InputFile,
  pem: string,
  cert: CertificateLike,
  encoding: "pem" | "der" = "pem"
) {
  const publicKey = publicKeyInfo(cert);
  const authorityInfo = certificateAuthorityInfo(cert);
  output.push({
    inputId: file.id,
    detectedType: "x509_certificate",
    encoding,
    subject: dnToString(cert.subject),
    issuer: dnToString(cert.issuer),
    sans: extractSansFromCert(cert),
    eku: extractEkuFromCert(cert),
    fingerprintSha1: sha1Hex(Buffer.from(pem, "utf8")),
    fingerprintSha256: sha256Hex(Buffer.from(pem, "utf8")),
    publicKeyType: publicKey.publicKeyType,
    ...(cert.serialNumber ? { serialHex: cert.serialNumber } : {}),
    ...(cert.validity?.notBefore ? { notBefore: cert.validity.notBefore.toISOString() } : {}),
    ...(cert.validity?.notAfter ? { notAfter: cert.validity.notAfter.toISOString() } : {}),
    ...(publicKey.publicKeyBits !== undefined ? { publicKeyBits: publicKey.publicKeyBits } : {}),
    ...(authorityInfo.isCertificateAuthority ? { isCertificateAuthority: true } : {}),
    ...(authorityInfo.isSelfSigned ? { isSelfSigned: true } : {})
  });
}

function pushCsr(output: ParsedObject[], file: InputFile, pem: string, csr: CsrLike) {
  const sans: string[] = [];

  try {
    const attr = csr.getAttribute?.({ name: "extensionRequest" });
    const extensions = attr?.extensions ?? [];
    const sanExt = extensions.find((item) => item.name === "subjectAltName");
    const altNames = sanExt?.altNames ?? [];
    for (const item of altNames) {
      if (item.type === 2 && typeof item.value === "string") {
        sans.push(item.value);
      }
    }
  } catch {
    // no-op
  }

  output.push({
    inputId: file.id,
    detectedType: "csr",
    encoding: "pem",
    subject: dnToString(csr.subject),
    sans,
    fingerprintSha1: sha1Hex(Buffer.from(pem, "utf8")),
    fingerprintSha256: sha256Hex(Buffer.from(pem, "utf8"))
  });
}

function pushKey(
  output: ParsedObject[],
  file: InputFile,
  pem: string,
  key: { encrypted: boolean; key: ReturnType<typeof privateKeyFromPem> | null }
) {
  output.push({
    inputId: file.id,
    detectedType: "private_key",
    encoding: "pem",
    encrypted: key.encrypted,
    keyType: key.key?.n ? "RSA" : key.key?.type === "ec" ? "EC" : "UNKNOWN",
    fingerprintSha1: sha1Hex(Buffer.from(pem, "utf8")),
    fingerprintSha256: sha256Hex(Buffer.from(pem, "utf8")),
    ...(key.key?.n?.bitLength ? { keyBits: key.key.n.bitLength() } : {})
  });
}

export function normalizeInputs(files: InputFile[]): ParsedObject[] {
  const output: ParsedObject[] = [];

  for (const file of files) {
    const encoding = detectEncoding(file.bytes);

    if (encoding === "pem") {
      const text = file.bytes.toString("utf8");
      const blocks = splitPemBlocks(text);
      const hintedType = detectType(file.bytes, encoding);

      if (blocks.length === 0) {
        output.push({
          inputId: file.id,
          detectedType: hintedType,
          encoding: "pem",
          note: "PEM sem blocos BEGIN/END reconheciveis"
        });
        continue;
      }

      for (const pem of blocks) {
        const cert = tryParseCertificate(pem);
        if (cert) {
          pushCertificate(output, file, pem, cert);
          continue;
        }

        const csr = tryParseCsr(pem);
        if (csr) {
          pushCsr(output, file, pem, csr);
          continue;
        }

        const key = tryParsePrivateKey(pem);
        if (key) {
          pushKey(output, file, pem, key);
          continue;
        }

        output.push({
          inputId: file.id,
          detectedType: hintedType,
          encoding: "pem",
          note: "Bloco PEM nao pode ser interpretado pelo forge"
        });
      }

      continue;
    }

    if (encoding === "der") {
      const pkcs12 = detectPkcs12(file.bytes);
      if (!pkcs12) {
        const cert = tryParseDerCertificate(file.bytes);
        if (cert) {
          pushCertificate(output, file, cert.pem, cert.cert, "der");
          continue;
        }
      }
      output.push({
        inputId: file.id,
        detectedType: pkcs12 ? "pkcs12" : "unknown",
        encoding: "der",
        note: pkcs12
          ? "PKCS#12 binario identificado por inspecao ASN.1"
          : "Arquivo DER binario sem tipo reconhecido"
      });
      continue;
    }

    output.push({
      inputId: file.id,
      detectedType: "unknown",
      encoding,
      note: "Formato nao identificado"
    });
  }

  return output;
}
