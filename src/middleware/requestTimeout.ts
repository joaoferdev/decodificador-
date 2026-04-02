import type { Request, Response, NextFunction } from "express";

import { env } from "../config/env.js";

export function requestTimeout(req: Request, res: Response, next: NextFunction) {
  res.setTimeout(env.REQUEST_TIMEOUT_MS, () => {
    if (res.headersSent) return;
    res.status(408).json({
      error: "REQUEST_TIMEOUT",
      message: "A operacao demorou mais do que o esperado. Tente novamente."
    });
  });
  next();
}
