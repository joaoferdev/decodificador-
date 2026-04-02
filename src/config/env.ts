import { z } from "zod";

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info"),
  TRUST_PROXY: z.union([z.literal("true"), z.literal("false")]).default("false"),
  CORS_ORIGINS: z.string().default("http://localhost:5173"),
  REQUIRE_AUTH_TOKEN: z.string().trim().optional(),
  JOB_STORAGE_ROOT: z.string().trim().optional(),
  JOB_TTL_MS: z.coerce.number().int().positive().default(30 * 60 * 1000),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(120),
  CSR_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(90),
  JOB_CREATE_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(20),
  JOB_ACTION_RATE_LIMIT_MAX: z.coerce.number().int().positive().default(40),
  REQUEST_TIMEOUT_MS: z.coerce.number().int().positive().default(30_000),
  JSON_BODY_LIMIT: z.string().default("2mb"),
  TEXT_BODY_LIMIT: z.string().default("2mb"),
  MAX_UPLOAD_FILE_SIZE_BYTES: z.coerce.number().int().positive().default(5 * 1024 * 1024),
  MAX_UPLOAD_FILES: z.coerce.number().int().positive().default(5)
});

const parsed = envSchema.parse(process.env);

function splitOrigins(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

export const env = {
  ...parsed,
  trustProxy: parsed.TRUST_PROXY === "true",
  corsOrigins: splitOrigins(parsed.CORS_ORIGINS)
};
