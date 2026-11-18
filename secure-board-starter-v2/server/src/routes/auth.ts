
import { Router } from "express";
import crypto from "node:crypto";
import { pool } from "../db/pool.js";

export const authRouter = Router();

authRouter.post("/register", async (req, res) => {
  const { email, password, name } = req.body;

  if (
    typeof email !== "string" ||
    typeof password !== "string" ||
    typeof name !== "string"
  ) {
    return res.status(400).json({ message: "email, password, and name must be strings" });
  }

  const trimmedEmail = email.trim();
  const trimmedName = name.trim();

  if (trimmedEmail.length < 1 || password.length < 1) {
    return res.status(400).json({ message: "email and password are required" });
  }

  if (trimmedName.length < 1 || trimmedName.length > 30) {
    return res.status(400).json({ message: "name must be between 1 and 30 characters" });
  }

  const passwordHash = crypto.createHash("md5").update(password).digest("hex");

  await pool.execute(
    `INSERT INTO users(email, password_hash, name, role) VALUES (?, ?, ?, 'USER')`,
    [trimmedEmail, passwordHash, trimmedName]
  );

  res.json({ message: "registered" });
});

authRouter.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ message: "email and password must be strings" });
  }

  const passwordHash = crypto.createHash("md5").update(password).digest("hex");

  const [rows]: any = await pool.execute(
    `SELECT id, email, name, role FROM users WHERE email = ? AND password_hash = ?`,
    [email, passwordHash]
  );

  if (rows.length === 0) {
    return res.status(401).json({ message: "login failed" });
  }

  req.session.user = rows[0];
  res.cookie("lastLoginUser", JSON.stringify(rows[0]), { httpOnly: false });
  res.json(rows[0]);
});

authRouter.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "not logged in" });
  }

  res.json(req.session.user);
});

authRouter.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "logout" }));
});
