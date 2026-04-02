import path from "node:path";

const allowedExtensions = new Set([".pem", ".crt", ".cer", ".key", ".pfx", ".p12", ".csr", ".txt"]);
const asciiSafe = /[^a-zA-Z0-9._-]/g;

export function isAllowedUploadName(filename: string): boolean {
  const ext = path.extname(filename).toLowerCase();
  return allowedExtensions.has(ext);
}

export function sanitizeFilename(filename: string): string {
  const base = path.basename(filename).replace(asciiSafe, "_");
  return base.length > 0 ? base : "download.bin";
}

export function buildContentDisposition(filename: string): string {
  const safe = sanitizeFilename(filename);
  return `attachment; filename="${safe}"`;
}
