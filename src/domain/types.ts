export type DetectedType =
  | "x509_certificate"
  | "private_key"
  | "csr"
  | "pkcs12"
  | "unknown";

export type Encoding = "pem" | "der" | "unknown";

export type InputFile = {
  id: string;
  originalName: string;
  mimeType: string;
  size: number;
  sha256: string;
  bytes: Buffer;
};

export type ParsedObject = {
  inputId: string;
  detectedType: DetectedType;
  encoding: Encoding;
  subject?: string;
  issuer?: string;
  serialHex?: string;
  notBefore?: string;
  notAfter?: string;
  sans?: string[];
  eku?: string[];  
  encrypted?: boolean;
  keyType?: "RSA" | "EC" | "UNKNOWN";
  keyBits?: number;
  note?: string;
  fingerprintSha1?: string;
  fingerprintSha256?: string;
  publicKeyBits?: number;
  publicKeyType?: "RSA" | "EC" | "UNKNOWN";
  isCertificateAuthority?: boolean;
  isSelfSigned?: boolean;
};

export type WarningItem = {
  code: string;
  message: string;
};

export type ResolvedCertificateSelection = {
  certPem: string;
  allCertPems: string[];
};

export type ResolvedCertificateKeyPair = {
  certPem: string;
  keyPem: string;
  allCertPems: string[];
};

export type ResolvedServerCertificateChain = {
  leafCertPem: string;
  intermediateCertPems: string[];
  rootCertPems: string[];
  allCertPems: string[];
};

export type CertificateRoleInfo = {
  pem: string;
  isCertificateAuthority: boolean;
  isSelfSigned: boolean;
  subjectId: string;
  issuerId: string;
};

export type Pkcs12ExtractedMaterials = {
  certPems: string[];
  keyPem: string | null;
};

export type DecodedCsrAnalysis = {
  inputId: string;
  type: "csr";
  subjectString: string;
  subject: Record<string, string | string[]>;
  publicKey: { algorithm: "RSA" | "EC" | "UNKNOWN"; bits?: number; exponent?: number };
  signature: { valid: boolean; algorithm?: string; oid?: string };
  extensions: {
    subjectAltName: { dns: string[]; ip: string[]; email: string[]; uri: string[] };
    keyUsage: string[];
    extendedKeyUsage: string[];
    basicConstraints: { ca?: boolean; pathLenConstraint?: number };
    raw?: unknown[];
  };
  fingerprints: { sha1: string; sha256: string };
  warnings: WarningItem[];
};

export type JobAnalysis = {
  warnings?: WarningItem[];
  decodedCsr?: DecodedCsrAnalysis;
};

export type Job = {
  id: string;
  createdAt: string;
  expiresAt: string;
  status: "created" | "parsed" | "expired";
  inputs: Omit<InputFile, "bytes">[];
  parsed: ParsedObject[];
  analysis?: JobAnalysis;
};

export type Artifact = {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
  sha256: string;
  bytes: Buffer;
};

export type JobPublic = {
  id: string;
  createdAt: string;
  expiresAt: string;
  status: "created" | "parsed" | "expired";
  inputs: Omit<InputFile, "bytes">[];
  parsed: ParsedObject[];
  analysis?: JobAnalysis;
  artifacts: Omit<Artifact, "bytes">[];
};
