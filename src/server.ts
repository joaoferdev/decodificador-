import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { routes } from "./api/routes.js";

export function createApp() {
  const app = express();

  app.use(cors());
  app.use(helmet());
  app.use(express.json({ limit: "5mb" }));
  app.use(express.text({ type: ["text/plain"], limit: "5mb" }));

  app.use(
    rateLimit({
      windowMs: 60_000,
      limit: 120
    })
  );

  app.get("/health", (_req, res) => res.json({ ok: true }));
  app.use(routes);

  return app;
}
