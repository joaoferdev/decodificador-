import * as forgeNs from "node-forge";
import type { InputFile, ParsedObject, Artifact } from "../domain/types.js";
import { sha256Hex, randomId } from "../utils/crypto.js";
import { ToolkitException } from "../utils/errors.js";

const forge: any = (forgeNs as any).default ?? forgeNs;
const OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1";
const OID_PKCS8_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";
const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";

export function recipeExtractPkcs12(
  files: InputFile[],
  parsed: ParsedObject[],
  params: { password: string }
): Artifact[] {
  if (!params.password) {
    throw new ToolkitException("PASSWORD_REQUIRED", "Senha é obrigatória para extrair PFX.");
  }

  const pfxObj = parsed.find((p) => p.detectedType === "pkcs12");
  if (!pfxObj) {
    throw new ToolkitException("MISSING_PFX", "Envie um arquivo .pfx/.p12 para extrair.");
  }

  const pfxFile = files.find((f) => f.id === pfxObj.inputId);
  if (!pfxFile) {
    throw new ToolkitException("INPUT_NOT_FOUND", "Arquivo PFX não encontrado.");
  }

  
  const pfxDer = forge.util.createBuffer(pfxFile.bytes.toString("binary"));
  const asn1 = forge.asn1.fromDer(pfxDer);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, params.password);

  
  const bagsPkcs8 = p12.getBags({ bagType: OID_PKCS8_SHROUDED_KEY_BAG }) as any;
  const bagsKey = p12.getBags({ bagType: OID_KEY_BAG }) as any;

  const keyBags = (bagsPkcs8?.[OID_PKCS8_SHROUDED_KEY_BAG] ?? bagsKey?.[OID_KEY_BAG] ?? []) as any[];

  const key = keyBags[0]?.key;
  if (!key) {
    throw new ToolkitException("PFX_NO_KEY", "O PFX não contém chave privada.");
  }

  const keyPem = forge.pki.privateKeyToPem(key);
  const keyBytes = Buffer.from(keyPem, "utf8");

  
  const bagsCert = p12.getBags({ bagType: OID_CERT_BAG }) as any;
  const certBags = (bagsCert?.[OID_CERT_BAG] ?? []) as any[];

  const certPems = certBags.map((b) => forge.pki.certificateToPem(b.cert)).join("\n") + "\n";
  const certBytes = Buffer.from(certPems, "utf8");

  return [
    {
      id: randomId("artifact"),
      filename: "private.key.pem",
      mimeType: "application/x-pem-file",
      sha256: sha256Hex(keyBytes),
      bytes: keyBytes
    },
    {
      id: randomId("artifact"),
      filename: "certificates.pem",
      mimeType: "application/x-pem-file",
      sha256: sha256Hex(certBytes),
      bytes: certBytes
    }
  ];
}