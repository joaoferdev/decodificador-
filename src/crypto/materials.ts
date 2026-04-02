import type {
  Artifact,
  CertificateRoleInfo,
  InputFile,
  Pkcs12ExtractedMaterials,
  ParsedObject,
  ResolvedCertificateKeyPair,
  ResolvedCertificateSelection,
  ResolvedServerCertificateChain
} from "../domain/types.js";
import {
  asn1FromDer,
  certificateFromAsn1,
  certificateFromPem,
  certificateToPem,
  getOidMap,
  pkcs12FromAsn1,
  privateKeyToPem
} from "./forgeAdapter.js";
import { certificateMatchesPrivateKey } from "./pkcs12Validation.js";
import { ToolkitException } from "../utils/errors.js";
import { randomId, sha256Hex } from "../utils/crypto.js";

const OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1";
const OID_PKCS8_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";
const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";

export function createArtifact(filename: string, mimeType: string, bytes: Buffer): Artifact {
  return {
    id: randomId("artifact"),
    filename,
    mimeType,
    size: bytes.length,
    sha256: sha256Hex(bytes),
    bytes
  };
}

function stripExtension(filename: string): string {
  const cleaned = filename.replace(/[\\/]+/g, "_").trim();
  return cleaned.replace(/\.[^.]+$/i, "") || "certificate";
}

function extractCommonName(subject: string | undefined): string | null {
  if (!subject) return null;
  const match = subject.match(/(?:^|,\s*)CN=([^,]+)/i);
  return match?.[1]?.trim() || null;
}

function slugifyName(value: string): string {
  return value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .toLowerCase() || "certificate";
}

export function certificateArtifactBaseName(files: InputFile[], parsed: ParsedObject[]): string {
  const certificateObject = parsed.find((item) => item.detectedType === "x509_certificate");
  if (certificateObject) {
    const sourceFile = files.find((file) => file.id === certificateObject.inputId);
    const commonName = extractCommonName(certificateObject.subject);
    if (commonName) return slugifyName(commonName);
    if (sourceFile?.originalName) return slugifyName(stripExtension(sourceFile.originalName));
  }

  const pkcs12Object = parsed.find((item) => item.detectedType === "pkcs12");
  if (pkcs12Object) {
    const sourceFile = files.find((file) => file.id === pkcs12Object.inputId);
    if (sourceFile?.originalName) return slugifyName(stripExtension(sourceFile.originalName));
  }

  return "certificate";
}

export function normalizePem(pem: string): string {
  const normalized = pem.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n").trim();
  return normalized.endsWith("\n") ? normalized : `${normalized}\n`;
}

export function extractPemBlocks(text: string, expression: RegExp): string[] {
  return (text.match(expression) ?? []).map((block) => normalizePem(block));
}

export function parsePkcs12(bytes: Buffer, password: string) {
  const asn1 = asn1FromDer(bytes);
  return pkcs12FromAsn1(asn1, password);
}

export function detectPkcs12(bytes: Buffer): boolean {
  try {
    parsePkcs12(bytes, "");
    return true;
  } catch (error) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    return message.includes("invalid password") || message.includes("mac could not be verified");
  }
}

export function parsePkcs12OrThrow(bytes: Buffer, password: string) {
  try {
    return parsePkcs12(bytes, password);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.toLowerCase();

    if (normalized.includes("invalid password") || normalized.includes("mac could not be verified")) {
      throw new ToolkitException("PASSWORD_INVALID", "A senha do arquivo PFX/P12 esta incorreta.", 400);
    }

    throw new ToolkitException("PKCS12_INVALID", "O arquivo enviado nao e um PFX/P12 valido.", 400);
  }
}

function collectPemByType(
  files: InputFile[],
  parsed: ParsedObject[],
  detectedType: ParsedObject["detectedType"],
  expression: RegExp
): string[] {
  const ids = new Set(
    parsed
      .filter((item) => item.detectedType === detectedType && item.encoding === "pem")
      .map((item) => item.inputId)
  );

  const blocks: string[] = [];
  for (const file of files) {
    if (!ids.has(file.id)) continue;
    blocks.push(...extractPemBlocks(file.bytes.toString("utf8"), expression));
  }

  return blocks;
}

export function collectCertificatePems(files: InputFile[], parsed: ParsedObject[]): string[] {
  const pemBlocks = collectPemByType(
    files,
    parsed,
    "x509_certificate",
    /-----BEGIN (?:TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:TRUSTED )?CERTIFICATE-----/g
  ).map((pem) =>
    pem
      .replace(/-----BEGIN TRUSTED CERTIFICATE-----/g, "-----BEGIN CERTIFICATE-----")
      .replace(/-----END TRUSTED CERTIFICATE-----/g, "-----END CERTIFICATE-----")
  );

  const derIds = new Set(
    parsed
      .filter((item) => item.detectedType === "x509_certificate" && item.encoding === "der")
      .map((item) => item.inputId)
  );

  const derBlocks = files
    .filter((file) => derIds.has(file.id))
    .map((file) => certificatePemFromDer(file.bytes));

  return [...pemBlocks, ...derBlocks];
}

export function collectPrivateKeyPems(files: InputFile[], parsed: ParsedObject[]): string[] {
  return collectPemByType(
    files,
    parsed,
    "private_key",
    /-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----/g
  );
}

export function collectPrimaryPrivateKeyPem(files: InputFile[], parsed: ParsedObject[]): string | null {
  return collectPrivateKeyPems(files, parsed)[0] ?? null;
}

function dnIdentity(attributes: unknown[] | undefined): string {
  return JSON.stringify(attributes ?? []);
}

function certificateRoleFromPem(pem: string): CertificateRoleInfo {
  const cert = certificateFromPem(pem);
  const basicConstraints = cert.extensions?.find((item) => item.name === "basicConstraints");
  const subjectId = dnIdentity(cert.subject?.attributes);
  const issuerId = dnIdentity(cert.issuer?.attributes);

  return {
    pem,
    isCertificateAuthority: basicConstraints?.cA === true,
    isSelfSigned: subjectId.length > 0 && subjectId === issuerId,
    subjectId,
    issuerId
  };
}

function classifyCertificateRoles(certPems: string[]) {
  const roles = certPems.map((pem) => certificateRoleFromPem(pem));
  const leafCertificates = roles.filter((item) => !item.isCertificateAuthority);
  const intermediateCertificates = roles.filter((item) => item.isCertificateAuthority && !item.isSelfSigned);
  const rootCertificates = roles.filter((item) => item.isCertificateAuthority && item.isSelfSigned);

  return {
    roles,
    leafCertificates,
    intermediateCertificates,
    rootCertificates
  };
}

export function certificatePemFromDer(bytes: Buffer): string {
  const cert = certificateFromAsn1(asn1FromDer(bytes));
  return normalizePem(certificateToPem(cert));
}

export function classifyCertificates(certPems: string[]) {
  return classifyCertificateRoles(certPems);
}

function sortIntermediateCertificates(intermediateCertificates: CertificateRoleInfo[], leafCertificate: CertificateRoleInfo) {
  const ordered: CertificateRoleInfo[] = [];
  const remaining = [...intermediateCertificates];
  let expectedIssuer = leafCertificate.issuerId;

  while (remaining.length > 0) {
    const nextIndex = remaining.findIndex((item) => item.subjectId === expectedIssuer);
    if (nextIndex === -1) {
      throw new ToolkitException(
        "CHAIN_INVALID",
        "Os certificados intermediarios enviados nao formam uma cadeia valida com o certificado principal do servidor.",
        400
      );
    }

    const [next] = remaining.splice(nextIndex, 1);
    ordered.push(next!);
    expectedIssuer = next!.issuerId;
  }

  return ordered;
}

export function validateServerCertificateChain(certPems: string[]): ResolvedServerCertificateChain {
  const { leafCertificates, intermediateCertificates, rootCertificates } = classifyCertificateRoles(certPems);

  if (leafCertificates.length === 0) {
    throw new ToolkitException(
      "SERVER_CERT_REQUIRED",
      "Nao encontramos o certificado principal do servidor. Envie o certificado do servidor junto com os intermediarios.",
      400
    );
  }

  if (leafCertificates.length > 1) {
    throw new ToolkitException(
      "AMBIGUOUS_SERVER_CERTIFICATE",
      "Encontramos mais de um certificado principal. Envie apenas o certificado do servidor que deseja usar.",
      400
    );
  }

  if (intermediateCertificates.length === 0) {
    throw new ToolkitException(
      "INTERMEDIATE_CERT_REQUIRED",
      "Envie tambem o certificado intermediario da cadeia para gerar esse arquivo corretamente para uso no servidor.",
      400
    );
  }

  const leafCertificate = leafCertificates[0]!;
  const orderedIntermediates = sortIntermediateCertificates(intermediateCertificates, leafCertificate);
  const lastIssuer = orderedIntermediates[orderedIntermediates.length - 1]!.issuerId;
  const matchingRoots = rootCertificates.filter((item) => item.subjectId === lastIssuer);

  if (rootCertificates.length > 0 && matchingRoots.length === 0) {
    throw new ToolkitException(
      "CHAIN_INVALID",
      "Os certificados enviados nao formam uma cadeia valida. Revise a ordem e confirme se os intermediarios pertencem ao certificado principal.",
      400
    );
  }

  return {
    leafCertPem: leafCertificate.pem,
    intermediateCertPems: orderedIntermediates.map((item) => item.pem),
    rootCertPems: matchingRoots.map((item) => item.pem),
    allCertPems: [
      leafCertificate.pem,
      ...orderedIntermediates.map((item) => item.pem),
      ...matchingRoots.map((item) => item.pem)
    ]
  };
}

export function requireIntermediateCertificates(certPems: string[]) {
  const { intermediateCertificates } = classifyCertificateRoles(certPems);
  if (intermediateCertificates.length === 0) {
    throw new ToolkitException(
      "INTERMEDIATE_CERT_REQUIRED",
      "Envie tambem o certificado intermediario da cadeia para gerar esse arquivo corretamente para uso no servidor.",
      400
    );
  }
}

export function resolveCertificateSelection(
  files: InputFile[],
  parsed: ParsedObject[]
): ResolvedCertificateSelection | null {
  const certPems = collectCertificatePems(files, parsed);
  if (certPems.length === 0) return null;

  return resolveCertificateSelectionFromPems(certPems);
}

export function resolveCertificateSelectionFromPems(certPems: string[]): ResolvedCertificateSelection {
  if (certPems.length === 0) {
    throw new ToolkitException("CERT_NOT_FOUND", "Nao encontramos um certificado valido para essa conversao.", 400);
  }

  const { leafCertificates, intermediateCertificates, rootCertificates } = classifyCertificateRoles(certPems);
  if (certPems.length === 1) {
    return {
      certPem: certPems[0]!,
      allCertPems: certPems
    };
  }

  if (leafCertificates.length === 1) {
    return {
      certPem: leafCertificates[0]!.pem,
      allCertPems: [
        leafCertificates[0]!.pem,
        ...intermediateCertificates.map((item) => item.pem),
        ...rootCertificates.map((item) => item.pem)
      ]
    };
  }

  if (leafCertificates.length === 0 && intermediateCertificates.length === 1 && rootCertificates.length === 0) {
    return {
      certPem: intermediateCertificates[0]!.pem,
      allCertPems: certPems
    };
  }

  if (leafCertificates.length === 0 && rootCertificates.length === 1 && intermediateCertificates.length === 0) {
    return {
      certPem: rootCertificates[0]!.pem,
      allCertPems: certPems
    };
  }

  throw new ToolkitException(
    "AMBIGUOUS_CERTIFICATES",
    "Encontramos mais de um certificado e nao foi possivel escolher com seguranca qual deles deve ser convertido.",
    400
  );
}

export function resolveCertificateKeyPair(
  files: InputFile[],
  parsed: ParsedObject[]
): ResolvedCertificateKeyPair | null {
  const certPems = collectCertificatePems(files, parsed);
  const keyPems = collectPrivateKeyPems(files, parsed);

  if (certPems.length === 0 || keyPems.length === 0) {
    return null;
  }

  return resolveCertificateKeyPairFromPems(certPems, keyPems);
}

export function resolveCertificateKeyPairFromPems(
  certPems: string[],
  keyPems: string[]
): ResolvedCertificateKeyPair {
  if (certPems.length === 0 || keyPems.length === 0) {
    throw new ToolkitException("MISSING_INPUTS", "Envie um certificado e uma chave privada compativeis.", 400);
  }

  const { leafCertificates } = classifyCertificateRoles(certPems);
  if (leafCertificates.length === 0) {
    throw new ToolkitException(
      "SERVER_CERT_REQUIRED",
      "Nao encontramos um certificado principal do servidor. Envie o certificado do servidor junto com os intermediarios.",
      400
    );
  }

  const matches: Array<{ certPem: string; keyPem: string }> = [];
  for (const certPem of leafCertificates.map((item) => item.pem)) {
    for (const keyPem of keyPems) {
      if (certificateMatchesPrivateKey(certPem, keyPem)) {
        matches.push({ certPem, keyPem });
      }
    }
  }

  if (matches.length === 0) {
    throw new ToolkitException(
      "KEY_CERT_MISMATCH",
      "Os arquivos enviados nao formam um par valido. Envie apenas o certificado e a chave privada correspondentes.",
      400
    );
  }

  if (matches.length > 1 || leafCertificates.length > 1 || keyPems.length > 1) {
    throw new ToolkitException(
      "AMBIGUOUS_CERT_KEY_PAIR",
      "Encontramos mais de um certificado ou mais de uma chave privada. Envie apenas os arquivos do mesmo par para continuar.",
      400
    );
  }

  return {
    certPem: matches[0]!.certPem,
    keyPem: matches[0]!.keyPem,
    allCertPems: [
      matches[0]!.certPem,
      ...certPems.filter((pem) => pem !== matches[0]!.certPem)
    ]
  };
}

export function resolveServerCertificateChain(files: InputFile[], parsed: ParsedObject[]): ResolvedServerCertificateChain | null {
  const certPems = collectCertificatePems(files, parsed);
  if (certPems.length === 0) return null;
  return validateServerCertificateChain(certPems);
}

export function extractMaterialsFromPkcs12(
  files: InputFile[],
  parsed: ParsedObject[],
  password: string | undefined
): Pkcs12ExtractedMaterials | null {
  const pfxObject = parsed.find((item) => item.detectedType === "pkcs12");
  if (!pfxObject) return null;

  if (!password) {
    throw new ToolkitException(
      "PASSWORD_REQUIRED",
      "Informe a senha do arquivo PFX/P12 para continuar.",
      400
    );
  }

  const pfxFile = files.find((file) => file.id === pfxObject.inputId);
  if (!pfxFile) {
    throw new ToolkitException("INPUT_NOT_FOUND", "O arquivo PFX/P12 nao foi encontrado.", 400);
  }

  const p12 = parsePkcs12OrThrow(pfxFile.bytes, password);
  const bagsPkcs8 = p12.getBags({ bagType: OID_PKCS8_SHROUDED_KEY_BAG });
  const bagsKey = p12.getBags({ bagType: OID_KEY_BAG });
  const keyBags = bagsPkcs8[OID_PKCS8_SHROUDED_KEY_BAG] ?? bagsKey[OID_KEY_BAG] ?? [];
  const key = keyBags[0]?.key ?? null;

  const bagsCert = p12.getBags({ bagType: OID_CERT_BAG });
  const certBags = bagsCert[OID_CERT_BAG] ?? [];
  const certPems = certBags
    .map((bag) => bag.cert)
    .filter((cert): cert is NonNullable<typeof cert> => Boolean(cert))
    .map((cert) => normalizePem(certificateToPem(cert)));

  if (certPems.length === 0) {
    throw new ToolkitException("PFX_NO_CERT", "O arquivo PFX/P12 nao contem um certificado utilizavel.", 400);
  }

  const { leafCertificates, intermediateCertificates, rootCertificates } = classifyCertificateRoles(certPems);
  const orderedCertPems = [
    ...leafCertificates.map((item) => item.pem),
    ...intermediateCertificates.map((item) => item.pem),
    ...rootCertificates.map((item) => item.pem)
  ];

  return {
    certPems: orderedCertPems.length > 0 ? orderedCertPems : certPems,
    keyPem: key ? normalizePem(privateKeyToPem(key)) : null
  };
}

export function resolveServerCertificateChainFromPems(certPems: string[]): ResolvedServerCertificateChain {
  return validateServerCertificateChain(certPems);
}

export function getForgeOids() {
  return getOidMap();
}
