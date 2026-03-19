import { createHash } from "crypto";

export function sha1Hex(bytes: Buffer): string {
  return createHash("sha1").update(bytes).digest("hex");
}

export function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}