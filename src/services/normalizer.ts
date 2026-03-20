import forge from "../vendor/forge.js";
import type * as ForgeTypes from "node-forge";

import type { InputFile, ParsedObject } from "../domain/types.js";
import { detectEncoding, detectType } from "./detector.js";
import { splitPemBlocks } from "../utils/pem.js";
import { sha1Hex, sha256Hex } from "./fingerprints.js";

function dnToString(dn: any): string {
  try {
    return dn.attributes.map((a: any) => `${a.shortName || a.name}=${a.value}`).join(", ");
  } catch {
    return "";
  }
}

function extractSansFromCert(cert: ForgeTypes.pki.Certificate): string[] {
  const ext = (cert as any).extensions?.find((e: any) => e.name === "subjectAltName");
  const altNames = ext?.altNames ?? [];
  return altNames
    .filter((a: any) => a.type === 2 && typeof a.value === "string")
    .map((a: any) => a.value);
}

function extractEkuFromCert(cert: ForgeTypes.pki.Certificate): string[] {
  const eku = (cert as any).extensions?.find((e: any) => e.name === "extKeyUsage");
  if (!eku) return [];
  return Object.keys(eku).filter((k) => (eku as any)[k] === true);
}

function publicKeyInfo(cert: ForgeTypes.pki.Certificate): {
  publicKeyType: "RSA" | "EC" | "UNKNOWN";
  publicKeyBits?: number;
} {
  const pk: any = (cert as any).publicKey;

  if (pk?.n?.bitLength) {
    return { publicKeyType: "RSA", publicKeyBits: pk.n.bitLength() };
  }

  if (pk?.type === "ec" || pk?.curve || pk?.ecdsa) {
    return { publicKeyType: "EC" };
  }

  return { publicKeyType: "UNKNOWN" };
}

function tryParseCertificate(pem: string): ForgeTypes.pki.Certificate | null {
  try {
    // forge runtime vem do vendor/forge.js
    return (forge.pki as any).certificateFromPem(pem);
  } catch {
    return null;
  }
}

function tryParseCsr(pem: string): any | null {
  try {
    return (forge.pki as any).certificationRequestFromPem(pem);
  } catch {
    return null;
  }
}

function tryParsePrivateKey(pem: string): { encrypted: boolean; key: any | null } | null {
  try {
    const key = (forge.pki as any).privateKeyFromPem(pem);
    return { encrypted: false, key };
  } catch {
    const isEnc = /ENCRYPTED PRIVATE KEY|Proc-Type:\s*4,ENCRYPTED/i.test(pem);
    if (isEnc) return { encrypted: true, key: null };
    return null;
  }
}

export function normalizeInputs(files: InputFile[]): ParsedObject[] {
  const out: ParsedObject[] = [];

  for (const f of files) {
    const encoding = detectEncoding(f.bytes);

    if (encoding === "pem") {
      const text = f.bytes.toString("utf8");
      const blocks = splitPemBlocks(text);

      const hinted = detectType(f.bytes, encoding);

      if (blocks.length === 0) {
        out.push({
          inputId: f.id,
          detectedType: hinted,
          encoding: "pem",
          note: "PEM sem blocos BEGIN/END reconhecíveis"
        });
        continue;
      }

      for (const pem of blocks) {
        const fp1 = sha1Hex(Buffer.from(pem, "utf8"));
        const fp256 = sha256Hex(Buffer.from(pem, "utf8"));

        // 1) CERT (pelo header)
        if (/BEGIN (X509 )?CERTIFICATE/i.test(pem)) {
          const cert = tryParseCertificate(pem);
          if (cert) {
            const pk = publicKeyInfo(cert);
            out.push({
              inputId: f.id,
              detectedType: "x509_certificate",
              encoding: "pem",
              subject: dnToString((cert as any).subject),
              issuer: dnToString((cert as any).issuer),
              serialHex: (cert as any).serialNumber,
              notBefore: (cert as any).validity?.notBefore?.toISOString(),
              notAfter: (cert as any).validity?.notAfter?.toISOString(),
              sans: extractSansFromCert(cert),
              eku: extractEkuFromCert(cert),
              fingerprintSha1: fp1,
              fingerprintSha256: fp256,
              publicKeyType: pk.publicKeyType,
              ...(pk.publicKeyBits !== undefined ? { publicKeyBits: pk.publicKeyBits } : {})
            });
            continue;
          }
        }

        // 2) CSR (pelo header)
        if (/BEGIN (NEW )?CERTIFICATE REQUEST/i.test(pem)) {
          const csr = tryParseCsr(pem);
          if (csr) {
            const sans: string[] = [];
            try {
              const attr = csr.getAttribute?.({ name: "extensionRequest" });
              const exts = attr?.extensions ?? [];
              const sanExt = exts.find((e: any) => e.name === "subjectAltName");
              const altNames = sanExt?.altNames ?? [];
              for (const a of altNames) if (a.type === 2 && typeof a.value === "string") sans.push(a.value);
            } catch {}

            out.push({
              inputId: f.id,
              detectedType: "csr",
              encoding: "pem",
              subject: dnToString(csr.subject),
              sans,
              fingerprintSha1: fp1,
              fingerprintSha256: fp256
            });
            continue;
          }
        }

        // 3) PRIVATE KEY (pelo header)
        if (/BEGIN (EC |RSA )?PRIVATE KEY/i.test(pem) || /BEGIN ENCRYPTED PRIVATE KEY/i.test(pem)) {
          const key = tryParsePrivateKey(pem);
          if (key) {
            out.push({
              inputId: f.id,
              detectedType: "private_key",
              encoding: "pem",
              encrypted: key.encrypted,
              keyType: key.key?.n ? "RSA" : "UNKNOWN",
              keyBits: key.key?.n?.bitLength?.() ?? undefined,
              fingerprintSha1: fp1,
              fingerprintSha256: fp256
            });
            continue;
          }
        }

        // 4) fallback geral
        const cert = tryParseCertificate(pem);
        if (cert) {
          const pk = publicKeyInfo(cert);
          out.push({
            inputId: f.id,
            detectedType: "x509_certificate",
            encoding: "pem",
            subject: dnToString((cert as any).subject),
            issuer: dnToString((cert as any).issuer),
            serialHex: (cert as any).serialNumber,
            notBefore: (cert as any).validity?.notBefore?.toISOString(),
            notAfter: (cert as any).validity?.notAfter?.toISOString(),
            sans: extractSansFromCert(cert),
            eku: extractEkuFromCert(cert),
            fingerprintSha1: fp1,
            fingerprintSha256: fp256,
            publicKeyType: pk.publicKeyType,
            ...(pk.publicKeyBits !== undefined ? { publicKeyBits: pk.publicKeyBits } : {})
          });
          continue;
        }

        const csr = tryParseCsr(pem);
        if (csr) {
          out.push({
            inputId: f.id,
            detectedType: "csr",
            encoding: "pem",
            subject: dnToString(csr.subject),
            fingerprintSha1: fp1,
            fingerprintSha256: fp256
          });
          continue;
        }

        const key = tryParsePrivateKey(pem);
        if (key) {
          out.push({
            inputId: f.id,
            detectedType: "private_key",
            encoding: "pem",
            encrypted: key.encrypted,
            keyType: key.key?.n ? "RSA" : "UNKNOWN",
            keyBits: key.key?.n?.bitLength?.() ?? undefined,
            fingerprintSha1: fp1,
            fingerprintSha256: fp256
          });
          continue;
        }

        out.push({
          inputId: f.id,
          detectedType: hinted,
          encoding: "pem",
          note: "Bloco PEM não pôde ser interpretado pelo forge"
        });
      }

      continue;
    }

    if (encoding === "der") {
      const lowerName = f.originalName.toLowerCase();
      const looksLikePkcs12 = lowerName.endsWith(".pfx") || lowerName.endsWith(".p12");

      out.push({
        inputId: f.id,
        detectedType: looksLikePkcs12 ? "pkcs12" : "unknown",
        encoding: "der",
        note: looksLikePkcs12
          ? "PKCS#12 binario identificado pela extensao do arquivo"
          : "Arquivo DER binario sem tipo reconhecido"
      });
      continue;
    }

    out.push({
      inputId: f.id,
      detectedType: "unknown",
      encoding,
      note: "Formato não identificado"
    });
  }

  return out;
}
