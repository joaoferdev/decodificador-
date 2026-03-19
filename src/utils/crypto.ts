import crypto from "node:crypto";

export function sha256Hex(data: Buffer | string): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export function randomId(prefix: string): string {
  return `${prefix}_${crypto.randomBytes(9).toString("hex")}`;
}