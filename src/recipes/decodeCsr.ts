import forge from "../vendor/forge.js";
import type { InputFile, ParsedObject } from "../domain/types.js";
import { splitPemBlocks } from "../utils/pem.js";
import { sha1Hex, sha256Hex } from "../services/fingerprints.js";
import { ToolkitException } from "../utils/errors.js";

type SubjectMap = Record<string, string | string[]>;

type Warning = { code: string; message: string };

const WEAK_SIG_OIDS = new Set([
  "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
  "1.3.14.3.2.29" // sha1WithRSAEncryption legado
]);

function dnToString(dn: any): string {
  try {
    return (dn.attributes ?? []).map((a: any) => `${a.shortName || a.name}=${a.value}`).join(", ");
  } catch {
    return "";
  }
}

function dnToObject(dn: any): SubjectMap {
  const out: SubjectMap = {};
  const attrs = (dn?.attributes ?? []) as any[];

  for (const a of attrs) {
    const key = (a.shortName || a.name || a.type || "UNKNOWN") as string;
    const val = String(a.value ?? "");

    if (out[key] === undefined) {
      out[key] = val;
      continue;
    }

    const cur = out[key];
    out[key] = Array.isArray(cur) ? [...cur, val] : [cur, val];
  }

  return out;
}

function oidToName(oid: string | undefined): string | undefined {
  if (!oid) return undefined;

  const oids: Record<string, string> = (forge.pki as any).oids ?? {};
  const hit = Object.entries(oids).find(([, v]) => v === oid);
  return hit?.[0];
}

function publicKeyInfoFromCsr(csr: any): { algorithm: "RSA" | "EC" | "UNKNOWN"; bits?: number; exponent?: number } {
  const pk: any = csr?.publicKey;

  // RSA
  if (pk?.n?.bitLength && pk?.e) {
    const bits = Number(pk.n.bitLength());
    const exp = typeof pk.e?.intValue === "function" ? pk.e.intValue() : undefined;

    return {
      algorithm: "RSA",
      ...(Number.isFinite(bits) ? { bits } : {}),
      ...(Number.isFinite(exp) ? { exponent: exp } : {})
    };
  }

  // EC (forge varia)
  if (pk?.type === "ec" || pk?.curve || pk?.ecdsa || pk?.ecparams) {
    return { algorithm: "EC" };
  }

  return { algorithm: "UNKNOWN" };
}

function getExtensionRequest(csr: any): any[] {
  try {
    const attr = csr.getAttribute({ name: "extensionRequest" });
    return attr?.extensions ?? [];
  } catch {
    return [];
  }
}

function parseSAN(ext: any): { dns?: string[]; ip?: string[]; email?: string[]; uri?: string[]; other?: any[] } {
  const altNames = ext?.altNames ?? [];
  const dns: string[] = [];
  const ip: string[] = [];
  const email: string[] = [];
  const uri: string[] = [];
  const other: any[] = [];

  for (const a of altNames) {
    // 1=email, 2=dns, 6=uri, 7=ip
    if (a?.type === 2 && typeof a.value === "string") dns.push(a.value);
    else if (a?.type === 7) {
      if (typeof a.value === "string") ip.push(a.value);
      else other.push(a);
    } else if (a?.type === 1 && typeof a.value === "string") email.push(a.value);
    else if (a?.type === 6 && typeof a.value === "string") uri.push(a.value);
    else other.push(a);
  }

  return {
    ...(dns.length ? { dns } : {}),
    ...(ip.length ? { ip } : {}),
    ...(email.length ? { email } : {}),
    ...(uri.length ? { uri } : {}),
    ...(other.length ? { other } : {})
  };
}

function parseKeyUsage(ext: any): string[] {
  if (!ext) return [];
  const keys = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly"
  ];
  return keys.filter((k) => ext[k] === true);
}

function parseExtKeyUsage(ext: any): string[] {
  if (!ext) return [];
  return Object.keys(ext).filter((k) => ext[k] === true);
}

function parseBasicConstraints(ext: any): { ca?: boolean; pathLenConstraint?: number } {
  if (!ext) return {};
  const ca = typeof ext.cA === "boolean" ? ext.cA : undefined;
  const plc = typeof ext.pathLenConstraint === "number" ? ext.pathLenConstraint : undefined;

  return {
    ...(ca !== undefined ? { ca } : {}),
    ...(plc !== undefined ? { pathLenConstraint: plc } : {})
  };
}

function findCsrPemFromFiles(files: InputFile[], parsed: ParsedObject[]): { pem: string; inputId: string } {
  const csrParsed = parsed.find((p) => p.detectedType === "csr");
  const fileId = csrParsed?.inputId;

  const candidates = fileId ? files.filter((f) => f.id === fileId) : files;

  for (const f of candidates) {
    const text = f.bytes.toString("utf8");
    const blocks = splitPemBlocks(text);
    for (const b of blocks) {
      if (/BEGIN (NEW )?CERTIFICATE REQUEST/i.test(b)) {
        return { pem: b, inputId: f.id };
      }
    }
  }

  throw new ToolkitException("CSR_NOT_FOUND", "Nenhum CSR (BEGIN CERTIFICATE REQUEST) foi encontrado no job.", 400);
}

function parseCsr(pem: string): any {
  try {
    return (forge.pki as any).certificationRequestFromPem(pem);
  } catch (e: any) {
    throw new ToolkitException("CSR_PARSE_FAILED", `Falha ao ler CSR PEM: ${e?.message ?? String(e)}`, 400);
  }
}

export function recipeDecodeCsr(
  files: InputFile[],
  parsed: ParsedObject[]
): {
  inputId: string;
  type: "csr";
  subjectString: string;
  subject: SubjectMap;
  publicKey: { algorithm: "RSA" | "EC" | "UNKNOWN"; bits?: number; exponent?: number };
  signature: { valid: boolean; algorithm?: string; oid?: string };
  extensions: {
    subjectAltName: { dns: string[]; ip: string[]; email: string[]; uri: string[] };
    keyUsage: string[];
    extendedKeyUsage: string[];
    basicConstraints: ReturnType<typeof parseBasicConstraints>;
    raw?: any[];
  };
  fingerprints: { sha1: string; sha256: string };
  warnings: Warning[];
} {
  const { pem, inputId } = findCsrPemFromFiles(files, parsed);
  const csr = parseCsr(pem);

  const fp1 = sha1Hex(Buffer.from(pem, "utf8"));
  const fp256 = sha256Hex(Buffer.from(pem, "utf8"));

  const subjectString = dnToString(csr.subject);
  const subject = dnToObject(csr.subject);

  const publicKey = publicKeyInfoFromCsr(csr);

  let signatureValid = false;
  try {
    signatureValid = typeof csr.verify === "function" ? !!csr.verify() : false;
  } catch {
    signatureValid = false;
  }

  const sigOid = (csr as any).signatureOid as string | undefined;
  const sigAlgName = oidToName(sigOid);

  const exts = getExtensionRequest(csr);

  const sanExt = exts.find((e: any) => e?.name === "subjectAltName" || e?.id === (forge.pki as any).oids?.subjectAltName);
  const keyUsageExt = exts.find((e: any) => e?.name === "keyUsage" || e?.id === (forge.pki as any).oids?.keyUsage);
  const ekuExt = exts.find((e: any) => e?.name === "extKeyUsage" || e?.id === (forge.pki as any).oids?.extKeyUsage);
  const bcExt = exts.find((e: any) => e?.name === "basicConstraints" || e?.id === (forge.pki as any).oids?.basicConstraints);

  // subjectAltName SEMPRE arrays
  const sanParsed = sanExt ? parseSAN(sanExt) : {};
  const subjectAltName = {
    dns: sanParsed.dns ?? [],
    ip: sanParsed.ip ?? [],
    email: sanParsed.email ?? [],
    uri: sanParsed.uri ?? []
  };

  const keyUsage = keyUsageExt ? parseKeyUsage(keyUsageExt) : [];
  const extendedKeyUsage = ekuExt ? parseExtKeyUsage(ekuExt) : [];
  const basicConstraints = bcExt ? parseBasicConstraints(bcExt) : {};

  const extensions = {
    subjectAltName,
    keyUsage,
    extendedKeyUsage,
    basicConstraints,
    ...(exts.length ? { raw: exts } : {})
  };

  const warnings: Warning[] = [];

  if (sigOid && WEAK_SIG_OIDS.has(sigOid)) {
    warnings.push({
      code: "WEAK_SIGNATURE_ALG",
      message: "CSR assinado com SHA1 (sha1WithRSAEncryption). Recomenda-se gerar CSR com SHA256."
    });
  }

  const sanHasAny =
    subjectAltName.dns.length +
      subjectAltName.ip.length +
      subjectAltName.email.length +
      subjectAltName.uri.length >
    0;

  if (!sanHasAny) {
    warnings.push({
      code: "NO_SAN",
      message: "CSR nao contem Subject Alternative Name (SAN). Muitos emissores exigem SAN (ex.: DNS)."
    });
  }

  return {
    inputId,
    type: "csr",
    subjectString,
    subject,
    publicKey,
    signature: {
      valid: signatureValid,
      ...(sigAlgName ? { algorithm: sigAlgName } : {}),
      ...(sigOid ? { oid: sigOid } : {})
    },
    extensions,
    fingerprints: {
      sha1: fp1,
      sha256: fp256
    },
    warnings
  };
}