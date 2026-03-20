import type { InputFile, ParsedObject, Artifact } from "../domain/types.js";
import { sha256Hex, randomId } from "../utils/crypto.js";

export function recipeBuildBundle(files: InputFile[], parsed: ParsedObject[]): Artifact {
  const certInputIds = parsed
    .filter((p) => p.detectedType === "x509_certificate" && p.encoding === "pem")
    .map((p) => p.inputId);

  const pemBlocks: string[] = [];

  for (const id of certInputIds) {
    const f = files.find((x) => x.id === id);
    if (!f) continue;

    const text = f.bytes.toString("utf8");
    const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
    pemBlocks.push(...blocks);
  }

  const bundle = pemBlocks.join("\n") + "\n";
  const bytes = Buffer.from(bundle, "utf8");

  return {
    id: randomId("artifact"),
    filename: "chain.pem",
    mimeType: "application/x-pem-file",
    size: bytes.length,
    sha256: sha256Hex(bytes),
    bytes
  };
}
