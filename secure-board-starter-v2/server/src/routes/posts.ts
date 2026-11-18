
import { Router } from "express";
import { pool } from "../db/pool.js";
import { requireAuth } from "../middleware/requireAuth.js";

export const postRouter = Router();

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

// Получение всех публикаций
postRouter.get("/", async (req, res) => {
  try {
    const rawQ = req.query.q;

    if (rawQ !== undefined && typeof rawQ !== "string") {
      return res.status(400).json({
        message: "invalid query parameter"
      });
    }

    const q = (rawQ ?? "").replace(/[\\%_]/g, "\\$&");

    const [rows] = await pool.execute(
      `SELECT p.id, p.user_id, p.title, p.content,
              p.created_at, u.name AS authorName
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.title LIKE ? ESCAPE '\\\\'
       ORDER BY p.id DESC`,
      ["%" + q + "%"]
    );

    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});

// Получение одной публикации
postRouter.get("/:id", async (req, res) => {
  try {
    const postId = parsePositiveInt(req.params.id);

    if (!postId) {
      return res.status(400).json({
        message: "invalid post id"
      });
    }

    const [rows]: any = await pool.execute(
      `SELECT p.*, u.name AS authorName
       FROM posts p
       JOIN users u ON p.user_id = u.id
       WHERE p.id = ?`,
      [postId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        message: "not found"
      });
    }

    const [attachments] = await pool.execute(
      `SELECT id, original_name, stored_name, size
       FROM attachments
       WHERE post_id = ?`,
      [postId]
    );

    res.json({
      ...rows[0],
      attachments
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});

// Создание публикации
postRouter.post("/", requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;

    if (typeof title !== "string" || typeof content !== "string") {
      return res.status(400).json({
        message: "title and content must be strings"
      });
    }

    const trimmedTitle = title.trim();

    if (trimmedTitle.length < 1 || trimmedTitle.length > 100) {
      return res.status(400).json({
        message: "title must be between 1 and 100 characters"
      });
    }

    if (content.trim().length < 1 || content.length > 5000) {
      return res.status(400).json({
        message: "content must be between 1 and 5000 characters"
      });
    }

    // 작성자는 요청 body가 아닌 로그인 세션에서 가져옴
    const userId = req.session.user!.id;

    const [result]: any = await pool.execute(
      `INSERT INTO posts(user_id, title, content)
       VALUES (?, ?, ?)`,
      [userId, trimmedTitle, content]
    );

    res.status(201).json({
      message: "created",
      id: result.insertId
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});

// Обновление публикации: автор или ADMIN
postRouter.put("/:id", requireAuth, async (req, res) => {
  try {
    const user = req.session.user!;

    const postId = parsePositiveInt(req.params.id);

    if (!postId) {
      return res.status(400).json({
        message: "invalid post id"
      });
    }

    const { title, content } = req.body;

    if (typeof title !== "string" || typeof content !== "string") {
      return res.status(400).json({
        message: "title and content must be strings"
      });
    }

    const trimmedTitle = title.trim();

    if (trimmedTitle.length < 1 || trimmedTitle.length > 100) {
      return res.status(400).json({
        message: "title must be between 1 and 100 characters"
      });
    }

    if (content.trim().length < 1 || content.length > 5000) {
      return res.status(400).json({
        message: "content must be between 1 and 5000 characters"
      });
    }

    const [result]: any = await pool.execute(
      `UPDATE posts
       SET title = ?, content = ?
       WHERE id = ?
       AND (user_id = ? OR ? = 'ADMIN')`,
      [trimmedTitle, content, postId, user.id, user.role]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: "post not found or access denied"
      });
    }

    res.json({
      message: "updated"
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});

// Удаление публикации: автор или ADMIN
postRouter.delete("/:id", requireAuth, async (req, res) => {
  try {
    const user = req.session.user!;

    const postId = parsePositiveInt(req.params.id);

    if (!postId) {
      return res.status(400).json({
        message: "invalid post id"
      });
    }

    const [result]: any = await pool.execute(
      `DELETE FROM posts
       WHERE id = ?
       AND (user_id = ? OR ? = 'ADMIN')`,
      [postId, user.id, user.role]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: "post not found or access denied"
      });
    }

    res.json({
      message: "deleted"
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "server error" });
  }
});
