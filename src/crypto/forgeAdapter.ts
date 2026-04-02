import forge from "../vendor/forge.js";

export type DistinguishedNameAttribute = {
  shortName?: string;
  name?: string;
  type?: string;
  value?: unknown;
};

export type DistinguishedNameLike = {
  attributes?: DistinguishedNameAttribute[];
};

export type SubjectAltNameEntry = {
  type?: number;
  value?: unknown;
};

export type ExtensionLike = {
  name?: string;
  id?: string;
  altNames?: SubjectAltNameEntry[];
  cA?: boolean;
  pathLenConstraint?: number;
  [key: string]: unknown;
};

export type CertificateLike = {
  subject: DistinguishedNameLike;
  issuer: DistinguishedNameLike;
  serialNumber?: string;
  validity?: {
    notBefore?: Date;
    notAfter?: Date;
  };
  extensions?: ExtensionLike[];
  publicKey?: {
    n?: { bitLength?: () => number };
    type?: string;
    curve?: unknown;
    ecdsa?: unknown;
  };
};

export type CsrLike = {
  subject: DistinguishedNameLike;
  publicKey?: {
    n?: { bitLength?: () => number };
    e?: { intValue?: () => number };
    type?: string;
    curve?: unknown;
    ecdsa?: unknown;
    ecparams?: unknown;
  };
  signatureOid?: string;
  verify?: () => boolean;
  getAttribute?: (options: { name: string }) => { extensions?: ExtensionLike[] } | undefined;
};

export type PrivateKeyLike = {
  n?: { bitLength?: () => number };
  type?: string;
};

export type Pkcs12Like = {
  getBags: (options: { bagType: string }) => Record<string, Array<{ cert?: unknown; key?: unknown }>>;
};

export function getOidMap(): Record<string, string> {
  return ((forge.pki as unknown as { oids?: Record<string, string> }).oids ?? {});
}

export function certificateFromPem(pem: string): CertificateLike {
  return (forge.pki as any).certificateFromPem(pem) as CertificateLike;
}

export function certificateFromAsn1(asn1: unknown): CertificateLike {
  return (forge.pki as any).certificateFromAsn1(asn1) as CertificateLike;
}

export function certificationRequestFromPem(pem: string): CsrLike {
  return (forge.pki as any).certificationRequestFromPem(pem) as CsrLike;
}

export function privateKeyFromPem(pem: string): PrivateKeyLike {
  return (forge.pki as any).privateKeyFromPem(pem) as PrivateKeyLike;
}

export function privateKeyToPem(key: unknown): string {
  return (forge.pki as any).privateKeyToPem(key);
}

export function certificateToPem(cert: unknown): string {
  return (forge.pki as any).certificateToPem(cert);
}

export function certificateToAsn1(cert: unknown): unknown {
  return (forge.pki as any).certificateToAsn1(cert);
}

export function asn1ToDer(asn1: unknown): string {
  return forge.asn1.toDer(asn1 as any).getBytes();
}

export function asn1FromDer(bytes: Buffer): unknown {
  const derBuffer = forge.util.createBuffer(bytes.toString("binary"));
  return forge.asn1.fromDer(derBuffer);
}

export function pkcs12FromAsn1(asn1: unknown, password: string): Pkcs12Like {
  return forge.pkcs12.pkcs12FromAsn1(asn1 as any, password) as Pkcs12Like;
}

export function toPkcs12Asn1(key: unknown, certs: unknown[], password: string, options: Record<string, unknown>): unknown {
  return forge.pkcs12.toPkcs12Asn1(key as any, certs as any[], password, options);
}
