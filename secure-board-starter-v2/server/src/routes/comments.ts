
import { Router } from "express";
import { pool } from "../db/pool.js";

export const commentRouter = Router({ mergeParams: true });

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

// Получение всех комментариев к публикации
commentRouter.get("/", async (req, res) => {
  try {
    const { postId } = req.params as Record<string, string>;

    const parsedPostId = parsePositiveInt(postId);

    if (!parsedPostId) {
      return res.status(400).json({
        message: "invalid post id"
      });
    }

    const [rows] = await pool.execute(
      `SELECT c.id, c.user_id, c.content, c.created_at,
              u.name AS authorName
       FROM comments c
       JOIN users u ON c.user_id = u.id
       WHERE c.post_id = ?
       ORDER BY c.id ASC`,
      [parsedPostId]
    );

    res.json(rows);
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "server error"
    });
  }
});

// Создание комментария
commentRouter.post("/", async (req, res) => {
  try {
    const { postId } = req.params as Record<string, string>;

    const parsedPostId = parsePositiveInt(postId);

    if (!parsedPostId) {
      return res.status(400).json({
        message: "invalid post id"
      });
    }

    const user = req.session.user as any;

    if (!user?.id) {
      return res.status(401).json({
        message: "unauthorized"
      });
    }

    const { content } = req.body;

    if (typeof content !== "string") {
      return res.status(400).json({
        message: "content must be a string"
      });
    }

    if (content.trim().length < 1 || content.length > 500) {
      return res.status(400).json({
        message: "comment must be between 1 and 500 characters"
      });
    }

    const userId = parsePositiveInt(user.id);

    if (!userId) {
      return res.status(400).json({
        message: "invalid user id"
      });
    }

    // Проверяем существование публикации
    const [posts]: any = await pool.execute(
      `SELECT id FROM posts WHERE id = ?`,
      [parsedPostId]
    );

    if (posts.length === 0) {
      return res.status(404).json({
        message: "post not found"
      });
    }

    const [result]: any = await pool.execute(
      `INSERT INTO comments(post_id, user_id, content)
       VALUES (?, ?, ?)`,
      [parsedPostId, userId, content]
    );

    res.status(201).json({
      message: "created",
      id: result.insertId
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "server error"
    });
  }
});

// Удаление комментария
commentRouter.delete("/:commentId", async (req, res) => {
  try {
    const { postId, commentId } = req.params as Record<string, string>;

    const parsedPostId = parsePositiveInt(postId);
    const parsedCommentId = parsePositiveInt(commentId);

    if (!parsedPostId || !parsedCommentId) {
      return res.status(400).json({
        message: "invalid id"
      });
    }

    const user = req.session.user as any;

    if (!user?.id) {
      return res.status(401).json({
        message: "unauthorized"
      });
    }

    const userId = parsePositiveInt(user.id);

    if (!userId) {
      return res.status(400).json({
        message: "invalid user id"
      });
    }

    const [result]: any = await pool.execute(
      `DELETE FROM comments
       WHERE id = ? AND post_id = ? AND user_id = ?`,
      [parsedCommentId, parsedPostId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        message: "comment not found or access denied"
      });
    }

    res.json({
      message: "deleted"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "server error"
    });
  }
});
