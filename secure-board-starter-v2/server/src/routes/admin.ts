
import { Router } from "express";
import { pool } from "../db/pool.js";

export const adminRouter = Router();

function parsePositiveInt(value: unknown): number | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const str = String(value).trim();
  if (!/^[1-9]\d*$/.test(str)) return null;
  const num = Number(str);
  return Number.isSafeInteger(num) && num > 0 ? num : null;
}

adminRouter.get("/users", async (req, res) => {
  if (req.query.role !== undefined && typeof req.query.role !== "string") {
    return res.status(400).json({ message: "invalid role parameter" });
  }

  const role = String(req.query.role ?? "");

  if (role === "ADMIN") {
    const [rows] = await pool.execute(
      "SELECT id,email,name,role,password_hash FROM users"
    );
    return res.json(rows);
  }

  res.status(403).json({ message: "admin only" });
});

adminRouter.post("/users/:id/role", async (req, res) => {
  const userId = parsePositiveInt(req.params.id);

  if (!userId) {
    return res.status(400).json({ message: "invalid user id" });
  }

  const { role } = req.body;

  if (typeof role !== "string" || (role !== "USER" && role !== "ADMIN")) {
    return res.status(400).json({ message: "invalid role" });
  }

  await pool.execute(
    `UPDATE users SET role = ? WHERE id = ?`,
    [role, userId]
  );

  res.json({ message: "role changed" });
});
