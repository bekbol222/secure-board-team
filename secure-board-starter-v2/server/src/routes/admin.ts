import { Router } from "express";
import { pool } from "../db/pool.js";
import { requireAdmin } from "../middleware/requireAdmin.js";

export const adminRouter = Router();

function parsePositiveInt(value: unknown): number | null {
  if (typeof value !== "string" && typeof value !== "number") {
    return null;
  }

  const str = String(value).trim();

  if (!/^[1-9]\d*$/.test(str)) {
    return null;
  }

  const num = Number(str);

  return Number.isSafeInteger(num) && num > 0 ? num : null;
}

// ADMIN only: get users (R12-5: exclude password_hash)
adminRouter.get("/users", requireAdmin, async (_req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, email, name, role FROM users"
    );

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});

// ADMIN only: change user role
adminRouter.post("/users/:id/role", requireAdmin, async (req, res) => {
  try {
    const userId = parsePositiveInt(req.params.id);

    if (!userId) {
      return res.status(400).json({
        message: "invalid user id"
      });
    }

    const { role } = req.body;

    if (typeof role !== "string" || (role !== "USER" && role !== "ADMIN")) {
      return res.status(400).json({
        message: "invalid role"
      });
    }

    const [result]: any = await pool.execute(
      "UPDATE users SET role = ? WHERE id = ?",
      [role, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: "user not found"
      });
    }

    res.json({ message: "role changed" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});