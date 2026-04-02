import { Router } from "express";
import multer from "multer";
import rateLimit from "express-rate-limit";

import { env } from "../config/env.js";
import {
  buildBundleSchema,
  exportFormatsSchema,
  extractPkcs12Schema,
  generatePkcs12Schema,
  pemPayloadSchema,
  recipeNameSchema
} from "./schemas.js";
import { logger } from "../lib/logger.js";
import { jobStore } from "../storage/jobStore.js";
import { randomId, sha256Hex } from "../utils/crypto.js";
import { createJobUseCase } from "../useCases/createJob.js";
import { decodeCsrUseCase } from "../useCases/decodeCsr.js";
import { downloadArtifactUseCase } from "../useCases/downloadArtifact.js";
import { getJobUseCase } from "../useCases/getJob.js";
import { runRecipeUseCase } from "../useCases/runRecipe.js";
import { buildContentDisposition, isAllowedUploadName, sanitizeFilename } from "../utils/http.js";

export const routes = Router();

function createRouteRateLimit(limit: number, message: string) {
  return rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: "RATE_LIMITED",
      message
    }
  });
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    files: env.MAX_UPLOAD_FILES,
    fileSize: env.MAX_UPLOAD_FILE_SIZE_BYTES
  },
  fileFilter(_req, file, callback) {
    if (!isAllowedUploadName(file.originalname)) {
      return callback(new multer.MulterError("LIMIT_UNEXPECTED_FILE", file.fieldname));
    }

    return callback(null, true);
  }
});

const decodeLimiter = createRouteRateLimit(
  env.CSR_RATE_LIMIT_MAX,
  "Muitas requisicoes de decodificacao em pouco tempo. Tente novamente em instantes."
);
const jobCreateLimiter = createRouteRateLimit(
  env.JOB_CREATE_RATE_LIMIT_MAX,
  "Muitos uploads em pouco tempo. Aguarde um pouco antes de enviar novos arquivos."
);
const jobActionLimiter = createRouteRateLimit(
  env.JOB_ACTION_RATE_LIMIT_MAX,
  "Muitas operacoes de conversao em pouco tempo. Tente novamente em instantes."
);

function toInputFiles(files: Express.Multer.File[]) {
  return files.map((file) => ({
    id: randomId("in"),
    originalName: sanitizeFilename(file.originalname),
    mimeType: file.mimetype,
    size: file.size,
    sha256: sha256Hex(file.buffer),
    bytes: file.buffer
  }));
}

function parseRecipePayload(recipe: string, body: unknown) {
  switch (recipe) {
    case "build_bundle":
      return buildBundleSchema.parse(body ?? {});
    case "extract_pkcs12":
      return extractPkcs12Schema.parse(body ?? {});
    case "generate_pkcs12":
      return generatePkcs12Schema.parse(body ?? {});
    case "export_formats":
      return exportFormatsSchema.parse(body ?? {});
    default:
      return body;
  }
}

routes.get("/toolkit/ping", (_req, res) => res.json({ pong: true }));

routes.post(
  "/toolkit/csr/decode",
  decodeLimiter,
  (req, res, next) => {
    const isMultipart = req.headers["content-type"]?.includes("multipart/form-data");
    if (isMultipart) return upload.array("files")(req as any, res as any, next);
    return next();
  },
  (req, res, next) => {
    try {
      const jsonPayload = typeof req.body === "object" && req.body ? pemPayloadSchema.safeParse(req.body) : null;
      const textPayload = typeof req.body === "string" ? req.body.trim() : "";
      const files = (req.files as Express.Multer.File[]) ?? [];
      const pem = jsonPayload?.success ? jsonPayload.data.pem : textPayload;

      const inputs =
        pem.length > 0
          ? [
              {
                id: randomId("in"),
                originalName: "pasted.csr.pem",
                mimeType: "application/x-pem-file",
                size: Buffer.byteLength(pem, "utf8"),
                sha256: sha256Hex(Buffer.from(pem, "utf8")),
                bytes: Buffer.from(pem, "utf8")
              }
            ]
          : toInputFiles(files);

      if (inputs.length === 0) {
        return res.status(400).json({
          error: "BAD_REQUEST",
          message: "Envie um arquivo ou cole um CSR em formato PEM."
        });
      }

      return res.json(decodeCsrUseCase(inputs));
    } catch (error) {
      return next(error);
    }
  }
);

routes.post("/toolkit/jobs", jobCreateLimiter, upload.array("files"), (req, res) => {
  const files = (req.files as Express.Multer.File[]) ?? [];
  if (files.length === 0) {
    return res.status(400).json({ error: "BAD_REQUEST", message: "Envie pelo menos um arquivo." });
  }

  const internal = createJobUseCase(jobStore, toInputFiles(files));
  return res.json({ jobId: internal.job.id });
});

routes.get("/toolkit/jobs/:jobId", (req, res) => {
  const internal = getJobUseCase(jobStore, String(req.params.jobId ?? ""));
  if (!internal) {
    return res.status(404).json({ error: "NOT_FOUND", message: "Esse processamento nao esta mais disponivel." });
  }

  return res.json(internal.job);
});

routes.post("/toolkit/jobs/:jobId/recipes/:recipe", jobActionLimiter, (req, res, next) => {
  const jobId = String(req.params.jobId ?? "");
  const parsedRecipe = recipeNameSchema.safeParse(String(req.params.recipe ?? "").trim().toLowerCase());

  if (!parsedRecipe.success) {
    return res.status(400).json({
      error: "BAD_REQUEST",
      message: "Tipo de conversao invalido."
    });
  }

  const internal = getJobUseCase(jobStore, jobId);
  if (!internal) {
    return res.status(404).json({ error: "NOT_FOUND", message: "Esse processamento nao esta mais disponivel." });
  }

  try {
    const payload = parseRecipePayload(parsedRecipe.data, req.body);
    return res.json(runRecipeUseCase(jobStore, jobId, internal, parsedRecipe.data, payload));
  } catch (error) {
    return next(error);
  }
});

routes.get("/toolkit/jobs/:jobId/download/:artifactId", (req, res) => {
  const artifact = downloadArtifactUseCase(
    jobStore,
    String(req.params.jobId ?? ""),
    String(req.params.artifactId ?? "")
  );

  if (!artifact) {
    return res.status(404).json({ error: "NOT_FOUND", message: "Arquivo gerado nao encontrado." });
  }

  res.setHeader("Content-Type", artifact.mimeType || "application/octet-stream");
  res.setHeader("Content-Disposition", buildContentDisposition(artifact.filename));
  res.setHeader("Content-Length", String(artifact.bytes.length));
  res.setHeader("Cache-Control", "no-store");

  return res.status(200).send(artifact.bytes);
});
