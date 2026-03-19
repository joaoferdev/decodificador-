export function splitPemBlocks(pemText: string): string[] {
  const re = /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g;
  return pemText.match(re) ?? [];
}