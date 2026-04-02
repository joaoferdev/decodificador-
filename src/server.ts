import cors from "cors";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

import { routes } from "./api/routes.js";
import { env } from "./config/env.js";
import { logger } from "./lib/logger.js";
import { getMetricsSnapshot } from "./lib/metrics.js";
import { errorHandler } from "./middleware/errorHandler.js";
import { requestContext } from "./middleware/requestContext.js";
import { requestTimeout } from "./middleware/requestTimeout.js";
import { requireAccessToken } from "./middleware/requireAccessToken.js";

export function createApp() {
  const app = express();

  app.disable("x-powered-by");
  app.set("trust proxy", env.trustProxy);

  app.use(requestContext);
  app.use(requestTimeout);
  app.use(
    cors({
      origin(origin, callback) {
        if (!origin) return callback(null, true);
        if (env.corsOrigins.includes(origin)) return callback(null, true);
        return callback(new Error("Origin nao permitida pelo CORS."));
      }
    })
  );
  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: "cross-origin" }
    })
  );
  app.use(express.json({ limit: env.JSON_BODY_LIMIT }));
  app.use(express.text({ type: ["text/plain"], limit: env.TEXT_BODY_LIMIT }));
  app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    logger.info(
      {
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        ip: req.ip,
        origin: req.headers.origin
      },
      "HTTP request"
    );
    next();
  });
  app.use(
    rateLimit({
      windowMs: env.RATE_LIMIT_WINDOW_MS,
      limit: env.RATE_LIMIT_MAX,
      standardHeaders: true,
      legacyHeaders: false,
      message: {
        error: "RATE_LIMITED",
        message: "Muitas requisicoes em pouco tempo. Tente novamente em instantes."
      }
    })
  );
  app.use(requireAccessToken);

  app.get("/health", (_req, res) =>
    res.json({
      ok: true,
      env: env.NODE_ENV,
      uptimeSeconds: Math.round(process.uptime()),
      jobTtlMs: env.JOB_TTL_MS,
      storageRoot: env.JOB_STORAGE_ROOT || null,
      metrics: getMetricsSnapshot()
    })
  );
  app.use(routes);
  app.use(errorHandler);

  return app;
}
