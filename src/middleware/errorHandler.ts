import type { NextFunction, Request, Response } from "express";
import multer from "multer";
import { ZodError } from "zod";

import { logger } from "../lib/logger.js";
import { incrementMetric } from "../lib/metrics.js";
import { ToolkitException } from "../utils/errors.js";

function isExpectedClientError(code: string) {
  return new Set([
    "PASSWORD_REQUIRED",
    "PASSWORD_INVALID",
    "BAD_REQUEST",
    "NOT_FOUND",
    "UNAUTHORIZED",
    "REQUEST_TIMEOUT",
    "FORMATS_REQUIRED",
    "UNSUPPORTED_FORMAT",
    "KEY_NOT_FOUND",
    "CERT_NOT_FOUND",
    "MISSING_INPUTS",
    "MISSING_PFX",
    "KEY_CERT_MISMATCH",
    "AMBIGUOUS_CERT_KEY_PAIR",
    "AMBIGUOUS_CERTIFICATES",
    "AMBIGUOUS_SERVER_CERTIFICATE",
    "INTERMEDIATE_CERT_REQUIRED",
    "SERVER_CERT_REQUIRED",
    "CHAIN_INVALID",
    "KEY_ENCRYPTED",
    "INPUT_NOT_FOUND",
    "CERT_PARSE_FAILED",
    "KEY_PARSE_FAILED",
    "PFX_BUILD_FAILED",
    "CSR_NOT_FOUND",
    "CSR_PARSE_FAILED",
    "PKCS12_INVALID",
    "PFX_NO_CERT",
    "PFX_NO_KEY"
  ]).has(code);
}

export function errorHandler(error: unknown, req: Request, res: Response, _next: NextFunction) {
  if (error instanceof multer.MulterError) {
    const message =
      error.code === "LIMIT_FILE_SIZE"
        ? "Um ou mais arquivos excedem o tamanho permitido."
        : error.code === "LIMIT_FILE_COUNT"
          ? "Voce enviou mais arquivos do que o permitido."
          : error.code === "LIMIT_UNEXPECTED_FILE"
            ? "Tipo de arquivo nao permitido."
            : "Nao foi possivel processar o upload.";

    logger.warn({ requestId: req.requestId, code: error.code }, "Upload validation failed");
    incrementMetric("clientErrors");
    return res.status(400).json({ error: "BAD_REQUEST", message });
  }

  if (error instanceof ToolkitException) {
    const log = isExpectedClientError(error.code) ? logger.info.bind(logger) : logger.warn.bind(logger);
    if (isExpectedClientError(error.code)) {
      incrementMetric("clientErrors");
    } else {
      incrementMetric("serverErrors");
    }
    log({ requestId: req.requestId, code: error.code }, "Handled toolkit error");
    return res.status(error.httpStatus).json({ error: error.code, message: error.message });
  }

  if (error instanceof ZodError) {
    logger.warn({ requestId: req.requestId, issues: error.issues }, "Payload validation failed");
    incrementMetric("clientErrors");
    return res.status(400).json({
      error: "BAD_REQUEST",
      message: error.issues[0]?.message ?? "Os dados enviados sao invalidos."
    });
  }

  logger.error({ requestId: req.requestId, error }, "Unhandled request failure");
  incrementMetric("serverErrors");
  return res.status(500).json({
    error: "INTERNAL_ERROR",
    message: "Nao foi possivel concluir a operacao. Tente novamente em instantes."
  });
}
