import type { Request, Response, NextFunction } from "express";

import { env } from "../config/env.js";

export function requireAccessToken(req: Request, res: Response, next: NextFunction) {
  if (!env.REQUIRE_AUTH_TOKEN) return next();

  const authHeader = req.header("authorization")?.trim();
  const bearer = authHeader?.startsWith("Bearer ") ? authHeader.slice("Bearer ".length).trim() : null;
  const fallbackHeader = req.header("x-access-token")?.trim();
  const token = bearer || fallbackHeader;

  if (token === env.REQUIRE_AUTH_TOKEN) {
    return next();
  }

  return res.status(401).json({
    error: "UNAUTHORIZED",
    message: "Acesso nao autorizado."
  });
}
