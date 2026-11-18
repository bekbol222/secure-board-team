import { Router, type Request } from "express";
import bcrypt from "bcrypt";
import { pool } from "../db/pool.js";

export const authRouter = Router();

const BCRYPT_ROUNDS = 12;

// Простой in-memory rate limiter для защиты от перебора паролей (R11-5)
const loginAttempts = new Map<string, { count: number; resetAt: number }>();
const MAX_LOGIN_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000;

function getAttemptKey(req: Request, email: string): string {
  const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
  return `${ip}:${email.toLowerCase()}`;
}

function isRateLimited(key: string): boolean {
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry) return false;
  if (now > entry.resetAt) {
    loginAttempts.delete(key);
    return false;
  }
  return entry.count >= MAX_LOGIN_ATTEMPTS;
}

function recordFailedAttempt(key: string): void {
  const now = Date.now();
  const entry = loginAttempts.get(key);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(key, { count: 1, resetAt: now + WINDOW_MS });
  } else {
    entry.count += 1;
  }
}

function clearAttempts(key: string): void {
  loginAttempts.delete(key);
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 255;
}

function isStrongPassword(password: string): boolean {
  // Минимум 8 символов, максимум 72 (ограничение bcrypt), хотя бы одна буква и одна цифра
  return (
    password.length >= 8 &&
    password.length <= 72 &&
    /[A-Za-z]/.test(password) &&
    /\d/.test(password)
  );
}

authRouter.post("/register", async (req, res) => {
  const { email, password, name } = req.body;

  if (typeof email !== "string" || typeof password !== "string" || typeof name !== "string") {
    return res.status(400).json({ message: "email, password, and name must be strings" });
  }

  const trimmedEmail = email.trim().toLowerCase();
  const trimmedName = name.trim();

  if (!isValidEmail(trimmedEmail)) {
    return res.status(400).json({ message: "invalid email format" });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      message: "password must be 8-72 characters and include both letters and numbers"
    });
  }

  if (trimmedName.length < 1 || trimmedName.length > 30) {
    return res.status(400).json({ message: "name must be between 1 and 30 characters" });
  }

  const [existing]: any = await pool.execute(
    `SELECT id FROM users WHERE email = ?`,
    [trimmedEmail]
  );
  if (existing.length > 0) {
    return res.status(409).json({ message: "email already registered" });
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

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

  const normalizedEmail = email.trim().toLowerCase();
  const attemptKey = getAttemptKey(req, normalizedEmail);

  if (isRateLimited(attemptKey)) {
    return res.status(429).json({ message: "too many login attempts, try again later" });
  }

  const [rows]: any = await pool.execute(
    `SELECT id, email, name, role, password_hash FROM users WHERE email = ?`,
    [normalizedEmail]
  );

  // Фиктивный bcrypt-хеш для защиты от timing attack, если пользователь не найден
  const dummyHash = "$2b$12$C6UzMDM.H6dfI/f/IKcEeO6H4rB1yS8F2N7H2Z8y7f6G5H4J3K2L.";
  const userRow = rows[0];
  const hashToCheck = userRow ? userRow.password_hash : dummyHash;
  const passwordValid = await bcrypt.compare(password, hashToCheck);

  if (!userRow || !passwordValid) {
    recordFailedAttempt(attemptKey);
    return res.status(401).json({ message: "invalid email or password" });
  }

  clearAttempts(attemptKey);

  const safeUser = {
    id: userRow.id,
    email: userRow.email,
    name: userRow.name,
    role: userRow.role
  };

  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).json({ message: "session error" });
    }
    req.session.user = safeUser;
    res.json(safeUser);
  });
});

authRouter.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "not logged in" });
  }
  res.json(req.session.user);
});

authRouter.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.json({ message: "logout" });
  });
});