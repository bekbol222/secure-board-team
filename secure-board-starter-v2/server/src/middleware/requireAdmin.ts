
import type { Request, Response, NextFunction } from "express";

export function requireAdmin(
  req: Request,
  res: Response,
  next: NextFunction
) {
  if (!req.session.user) {
    return res.status(401).json({
      message: "unauthorized"
    });
  }

  if (req.session.user.role !== "ADMIN") {
    return res.status(403).json({
      message: "admin only"
    });
  }

  next();
}
