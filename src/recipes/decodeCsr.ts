import type { DecodedCsrAnalysis, InputFile, ParsedObject, WarningItem } from "../domain/types.js";
import {
  type CsrLike,
  type DistinguishedNameAttribute,
  certificationRequestFromPem,
  getOidMap
} from "../crypto/forgeAdapter.js";
import { splitPemBlocks } from "../utils/pem.js";
import { sha1Hex, sha256Hex } from "../services/fingerprints.js";
import { ToolkitException } from "../utils/errors.js";

type SubjectMap = Record<string, string | string[]>;
type BasicConstraints = NonNullable<DecodedCsrAnalysis["extensions"]["basicConstraints"]>;

const WEAK_SIG_OIDS = new Set([
  "1.2.840.113549.1.1.5",
  "1.3.14.3.2.29"
]);

function dnToString(attributesLike: { attributes?: DistinguishedNameAttribute[] }): string {
  try {
    return (attributesLike.attributes ?? [])
      .map((attribute) => `${attribute.shortName || attribute.name}=${String(attribute.value ?? "")}`)
      .join(", ");
  } catch {
    return "";
  }
}

function dnToObject(attributesLike: { attributes?: DistinguishedNameAttribute[] }): SubjectMap {
  const output: SubjectMap = {};

  for (const attribute of attributesLike.attributes ?? []) {
    const key = String(attribute.shortName || attribute.name || attribute.type || "UNKNOWN");
    const value = String(attribute.value ?? "");

    if (output[key] === undefined) {
      output[key] = value;
      continue;
    }

    const current = output[key];
    output[key] = Array.isArray(current) ? [...current, value] : [current, value];
  }

  return output;
}

function oidToName(oid: string | undefined): string | undefined {
  if (!oid) return undefined;
  const oids = getOidMap();
  const hit = Object.entries(oids).find(([, value]) => value === oid);
  return hit?.[0];
}

function publicKeyInfoFromCsr(csr: CsrLike): DecodedCsrAnalysis["publicKey"] {
  const publicKey = csr.publicKey;

  if (publicKey?.n?.bitLength && publicKey.e) {
    const bits = Number(publicKey.n.bitLength());
    const exponent = typeof publicKey.e.intValue === "function" ? publicKey.e.intValue() : undefined;
    return {
      algorithm: "RSA",
      ...(Number.isFinite(bits) ? { bits } : {}),
      ...(typeof exponent === "number" && Number.isFinite(exponent) ? { exponent } : {})
    };
  }

  if (publicKey?.type === "ec" || publicKey?.curve || publicKey?.ecdsa || publicKey?.ecparams) {
    return { algorithm: "EC" };
  }

  return { algorithm: "UNKNOWN" };
}

function getExtensionRequest(csr: CsrLike) {
  try {
    return csr.getAttribute?.({ name: "extensionRequest" })?.extensions ?? [];
  } catch {
    return [];
  }
}

function parseSan(extension: { altNames?: Array<{ type?: number; value?: unknown }> }) {
  const dns: string[] = [];
  const ip: string[] = [];
  const email: string[] = [];
  const uri: string[] = [];

  for (const altName of extension.altNames ?? []) {
    if (altName.type === 2 && typeof altName.value === "string") dns.push(altName.value);
    else if (altName.type === 7 && typeof altName.value === "string") ip.push(altName.value);
    else if (altName.type === 1 && typeof altName.value === "string") email.push(altName.value);
    else if (altName.type === 6 && typeof altName.value === "string") uri.push(altName.value);
  }

  return { dns, ip, email, uri };
}

function parseKeyUsage(extension: Record<string, unknown> | undefined): string[] {
  if (!extension) return [];
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
  return keys.filter((key) => extension[key] === true);
}

function parseExtKeyUsage(extension: Record<string, unknown> | undefined): string[] {
  if (!extension) return [];
  return Object.keys(extension).filter((key) => extension[key] === true);
}

function parseBasicConstraints(extension: { cA?: boolean; pathLenConstraint?: number } | undefined): BasicConstraints {
  if (!extension) return {};
  return {
    ...(typeof extension.cA === "boolean" ? { ca: extension.cA } : {}),
    ...(typeof extension.pathLenConstraint === "number"
      ? { pathLenConstraint: extension.pathLenConstraint }
      : {})
  };
}

function findCsrPemFromFiles(files: InputFile[], parsed: ParsedObject[]): { pem: string; inputId: string } {
  const parsedCsr = parsed.find((item) => item.detectedType === "csr");
  const candidates = parsedCsr ? files.filter((file) => file.id === parsedCsr.inputId) : files;

  for (const file of candidates) {
    const blocks = splitPemBlocks(file.bytes.toString("utf8"));
    for (const block of blocks) {
      if (/BEGIN (NEW )?CERTIFICATE REQUEST/i.test(block)) {
        return { pem: block, inputId: file.id };
      }
    }
  }

  throw new ToolkitException("CSR_NOT_FOUND", "Nao encontramos um CSR valido nos dados enviados.", 400);
}

function parseCsr(pem: string): CsrLike {
  try {
    return certificationRequestFromPem(pem);
  } catch (error: unknown) {
    throw new ToolkitException("CSR_PARSE_FAILED", "Nao foi possivel ler o CSR enviado.", 400);
  }
}

export function recipeDecodeCsr(files: InputFile[], parsed: ParsedObject[]): DecodedCsrAnalysis {
  const { pem, inputId } = findCsrPemFromFiles(files, parsed);
  const csr = parseCsr(pem);
  const sigOid = csr.signatureOid;
  const exts = getExtensionRequest(csr);
  const oids = getOidMap();

  const sanExt = exts.find((ext) => ext.name === "subjectAltName" || ext.id === oids.subjectAltName);
  const keyUsageExt = exts.find((ext) => ext.name === "keyUsage" || ext.id === oids.keyUsage);
  const ekuExt = exts.find((ext) => ext.name === "extKeyUsage" || ext.id === oids.extKeyUsage);
  const bcExt = exts.find((ext) => ext.name === "basicConstraints" || ext.id === oids.basicConstraints);

  const subjectAltName = sanExt ? parseSan(sanExt) : { dns: [], ip: [], email: [], uri: [] };
  const warnings: WarningItem[] = [];

  if (sigOid && WEAK_SIG_OIDS.has(sigOid)) {
    warnings.push({
      code: "WEAK_SIGNATURE_ALG",
      message: "Esse CSR foi assinado com SHA1. Recomendamos gerar um novo CSR com SHA256."
    });
  }

  if (subjectAltName.dns.length + subjectAltName.ip.length + subjectAltName.email.length + subjectAltName.uri.length === 0) {
    warnings.push({
      code: "NO_SAN",
      message: "Esse CSR nao contem SAN. Muitos emissores exigem esse campo."
    });
  }

  let signatureValid = false;
  try {
    signatureValid = typeof csr.verify === "function" ? Boolean(csr.verify()) : false;
  } catch {
    signatureValid = false;
  }

  const signatureAlgorithm = oidToName(sigOid);
  const signature = {
    valid: signatureValid,
    ...(signatureAlgorithm ? { algorithm: signatureAlgorithm } : {}),
    ...(sigOid ? { oid: sigOid } : {})
  };

  return {
    inputId,
    type: "csr",
    subjectString: dnToString(csr.subject),
    subject: dnToObject(csr.subject),
    publicKey: publicKeyInfoFromCsr(csr),
    signature,
    extensions: {
      subjectAltName,
      keyUsage: parseKeyUsage(keyUsageExt),
      extendedKeyUsage: parseExtKeyUsage(ekuExt),
      basicConstraints: parseBasicConstraints(bcExt),
      ...(exts.length ? { raw: exts } : {})
    },
    fingerprints: {
      sha1: sha1Hex(Buffer.from(pem, "utf8")),
      sha256: sha256Hex(Buffer.from(pem, "utf8"))
    },
    warnings
  };
}
