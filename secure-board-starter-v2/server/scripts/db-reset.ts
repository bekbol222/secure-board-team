import fs from "node:fs";
import path from "node:path";
import bcrypt from "bcrypt";
import mysql from "mysql2/promise";
import "dotenv/config";

const schemaPath = path.join(process.cwd(), "..", "db", "schema.sql");
const uploadDir = path.join(process.cwd(), "uploads");

async function main() {
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST ?? "localhost",
    port: Number(process.env.DB_PORT ?? 3306),
    user: process.env.DB_USER ?? "root",
    password: process.env.DB_PASSWORD ?? "1234",
    multipleStatements: true
  });
  await conn.query(fs.readFileSync(schemaPath, "utf8"));

  const adminHash = await bcrypt.hash("admin1234", 12);
  const studentHash = await bcrypt.hash("student1234", 12);

  await conn.execute(`UPDATE users SET password_hash = ? WHERE email = ?`, [
    adminHash,
    "admin@school.test"
  ]);
  await conn.execute(`UPDATE users SET password_hash = ? WHERE email IN (?, ?)`, [
    studentHash,
    "student1@school.test",
    "student2@school.test"
  ]);

  await conn.end();

  fs.rmSync(uploadDir, { recursive: true, force: true });
  console.log("DB와 uploads 폴더를 처음 상태로 되돌렸습니다.");
}

main().catch(err => {
  console.error("초기화 실패:", err.message);
  process.exit(1);
});
