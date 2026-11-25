import express from "express";
import session from "express-session";
import cookieParser from "cookie-parser";
import "dotenv/config";

import { authRouter } from "./routes/auth.js";
import { postRouter } from "./routes/posts.js";
import { commentRouter } from "./routes/comments.js";
import { adminRouter } from "./routes/admin.js";
import { fileRouter } from "./routes/files.js";
import { requireCsrf } from "./middleware/csrf.js";

const sessionSecret = process.env.SESSION_SECRET;
const dbPassword = process.env.DB_PASSWORD;

if (!sessionSecret || !dbPassword) {
  throw new Error("Required configuration missing: SESSION_SECRET and DB_PASSWORD");
}

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// R13-7: Do not log query strings, request body, cookies, passwords, or session IDs
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

app.use(
  session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 60 * 60 * 1000
    }
  })
);

// R13-8: Return strictly { ok: true }
app.get("/api/health", (_req, res) => {
  res.json({ ok: true });
});

// R13-5: Protect all state-changing API requests (POST, PUT, DELETE) with CSRF token
app.use("/api", requireCsrf);

app.use("/api/auth", authRouter);
app.use("/api/posts/:postId/comments", commentRouter);
app.use("/api/posts", postRouter);
app.use("/api/admin", adminRouter);
app.use("/api/files", fileRouter);

// R13-6 & R13-7: Never expose stack traces, file paths, or SQL/DB errors in response or sensitive logs
app.use((err: unknown, req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error(`[${new Date().toISOString()}] ERROR ${req.method} ${req.path}`);
  if (res.headersSent) return;
  res.status(500).json({
    message: "internal server error"
  });
});

app.listen(Number(process.env.PORT ?? 3001), () => {
  console.log(`server started: http://localhost:${process.env.PORT ?? 3001}`);
});