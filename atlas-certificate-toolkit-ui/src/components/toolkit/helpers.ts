import type { JobPublic } from "../../api/toolkit";
import { formatExpiration } from "../../utils/jobExpiration";

export type ConversionKey =
  | "export_pem"
  | "export_crt"
  | "export_der"
  | "export_key"
  | "generate_pfx"
  | "generate_p12"
  | "extract_pkcs12"
  | "build_bundle";

export type ConversionOption = {
  key: ConversionKey;
  label: string;
  requirements: string;
  resultLabel: string;
  deploymentHint?: string;
  passwordHint?: string;
  validationHint?: string;
  unavailableReason?: string;
  passwordMode: "none" | "source" | "output" | "source-and-output";
  isEnabled: boolean;
  run: () => Promise<void>;
  buttonLabel: string;
  primary?: boolean;
};

export function bytes(n: number) {
  if (!Number.isFinite(n)) return "--";
  const units = ["B", "KB", "MB", "GB"];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function hasType(job: JobPublic | null, type: string) {
  const expected = String(type).trim().toLowerCase();
  return (job?.parsed ?? []).some((item) => String(item.detectedType).trim().toLowerCase() === expected);
}

export function errorMessage(error: unknown, fallback: string) {
  return error instanceof Error ? error.message : fallback;
}

export { formatExpiration };

export function artifactUsage(filename: string) {
  const name = filename.toLowerCase();
  if (name.endsWith("-fullchain.pem")) return "Use este arquivo como fullchain no Nginx, Apache e servidores Linux.";
  if (name.endsWith("-chain.pem")) return "Use este arquivo como cadeia intermediaria quando o servidor pedir a chain separada.";
  if (name.endsWith(".crt") || name.endsWith(".cer") || name.endsWith(".der") || name.endsWith(".pem")) {
    if (name.endsWith(".key")) return "Use este arquivo como chave privada correspondente ao certificado.";
    return "Use este arquivo como certificado principal do servidor.";
  }
  if (name.endsWith(".key")) return "Use este arquivo como chave privada correspondente ao certificado.";
  if (name.endsWith(".pfx") || name.endsWith(".p12")) return "Use este arquivo unico em IIS, Windows ou plataformas que importam PFX/P12.";
  return "Use este arquivo conforme o tipo de servidor que vai receber a instalacao.";
}
