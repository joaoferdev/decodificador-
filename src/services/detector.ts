import type { Encoding, DetectedType } from "../domain/types.js";

export function detectEncoding(bytes: Buffer): Encoding {
  const text = bytes.toString("utf8");
  if (text.includes("-----BEGIN ")) return "pem";

  const sample = bytes.slice(0, Math.min(bytes.length, 1024));
  const printable = sample.reduce((acc, b) => {
    const isPrintable = b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126);
    return acc + (isPrintable ? 1 : 0);
  }, 0);

  const ratio = printable / (sample.length || 1);
  return ratio < 0.85 ? "der" : "unknown";
}

export function detectType(bytes: Buffer, encoding: Encoding): DetectedType {
  if (encoding !== "pem") {
    return "unknown";
  }

  const t = bytes.toString("utf8");

  
  if (/BEGIN (X509 )?CERTIFICATE/i.test(t)) return "x509_certificate";

  
  if (/BEGIN (NEW )?CERTIFICATE REQUEST/i.test(t)) return "csr";

  
  if (/BEGIN (EC |RSA )?PRIVATE KEY/i.test(t)) return "private_key";
  if (/BEGIN ENCRYPTED PRIVATE KEY/i.test(t)) return "private_key";

  
  if (/BEGIN PKCS12/i.test(t)) return "pkcs12";

  return "unknown";
}
