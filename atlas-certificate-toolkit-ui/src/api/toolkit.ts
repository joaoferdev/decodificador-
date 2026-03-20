import { apiFetch } from "./client";

export type Warning = { code: string; message: string };
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export type DecodedCsr = {
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
    basicConstraints: Record<string, unknown>;
  };
  fingerprints: { sha1: string; sha256: string };
  warnings?: Warning[];
};

export type JobAnalysis = {
  warnings?: Warning[];
  decodedCsr?: DecodedCsr;
};

export async function decodeCsrFromPem(pem: string) {
  return apiFetch<{ decoded: DecodedCsr; warnings: Warning[] }>("/toolkit/csr/decode", {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify({ pem }),
  });
}

export async function decodeCsrFromFile(file: File) {
  const fd = new FormData();
  fd.append("files", file);
  return apiFetch<{ decoded: DecodedCsr; warnings: Warning[] }>("/toolkit/csr/decode", {
    method: "POST",
    body: fd,
  });
}

export type ArtifactPublic = {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
  sha256?: string;
};

export type ParsedItem = {
  inputId: string;
  detectedType: string;
  subject?: string;
  sans?: string[];
  fingerprintSha1?: string;
  fingerprintSha256?: string;
};

export type JobPublic = {
  id: string;
  createdAt: string;
  status: string;
  inputs: { id: string; originalName: string; size: number; sha256: string; mimeType: string }[];
  parsed?: ParsedItem[];
  artifacts?: ArtifactPublic[];
  analysis?: JobAnalysis;
};

export type JobCreated = { jobId: string };
export type RunRecipeResponse = {
  artifacts?: ArtifactPublic[];
  decoded?: DecodedCsr;
  analysis?: JobAnalysis | null;
};

export async function createJob(files: File[]) {
  const fd = new FormData();
  for (const f of files) fd.append("files", f);
  return apiFetch<JobCreated>("/toolkit/jobs", { method: "POST", body: fd });
}

export async function getJob(jobId: string) {
  return apiFetch<JobPublic>(`/toolkit/jobs/${jobId}`);
}

export async function runRecipe(jobId: string, recipe: string, body?: Record<string, unknown>) {
  return apiFetch<RunRecipeResponse>(`/toolkit/jobs/${jobId}/recipes/${recipe}`, {
    method: "POST",
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(body ?? {}),
  });
}

export function downloadArtifact(jobId: string, artifactId: string) {
  const base = import.meta.env.VITE_API_BASE ?? "http://localhost:3000";
  const url = `${base}/toolkit/jobs/${jobId}/download/${artifactId}`;
  window.open(url, "_blank", "noopener,noreferrer");
}
