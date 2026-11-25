import crypto from "node:crypto";
import type { Request, Response, NextFunction } from "express";

declare module "express-session" {
  interface SessionData {
    csrfToken?: string;
  }
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function getOrCreateCsrfToken(req: Request): string {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }
  return req.session.csrfToken;
}

function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function requireCsrf(req: Request, res: Response, next: NextFunction) {
  if (SAFE_METHODS.has(req.method)) {
    return next();
  }

  const supplied = req.get("X-CSRF-Token");
  const expected = req.session.csrfToken;

  if (!supplied || !expected || !safeEqual(supplied, expected)) {
    return res.status(403).json({ message: "invalid or missing csrf token" });
  }

  return next();
}