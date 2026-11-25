import mysql from "mysql2/promise";
import "dotenv/config";

const dbPassword = process.env.DB_PASSWORD;
if (!dbPassword) {
  throw new Error("Required configuration missing: DB_PASSWORD");
}

export const pool = mysql.createPool({
  host: process.env.DB_HOST ?? "localhost",
  port: Number(process.env.DB_PORT ?? 3306),
  user: process.env.DB_USER ?? "root",
  password: dbPassword,
  database: process.env.DB_NAME ?? "secure_board",
  connectionLimit: 10
});