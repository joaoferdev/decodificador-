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
  publicKeyBits?: number 
  publicKeyType?: "RSA" | "EC" | "UNKNOWN"
};

export type Job = {
  id: string;
  createdAt: string;
  status: "created" | "parsed" | "expired";
  inputs: Omit<InputFile, "bytes">[];
  parsed: ParsedObject[];
  analysis?: any;
};

export type Artifact = {
  id: string;
  filename: string;
  mimeType: string;
  sha256: string;
  bytes: Buffer;
};

export type JobPublic = {
  id: string;
  createdAt: string;
  status: "created" | "parsed" | "expired";
  inputs: Omit<InputFile, "bytes">[];
  parsed: ParsedObject[];
  analysis?: any;
  artifacts: Omit<Artifact, "bytes">[];
};