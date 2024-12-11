import { connectDb } from "./lib.js";
import jwt from "jsonwebtoken";

function validateData(schema) {
  return (req, res, next) => {
    try {
      schema.parse(req.body);
    } catch (error) {
      res.status(400);
      res.json({ error: error.errors });
      return;
    }

    next();
  };
}

function logger(req, res, next) {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
}

async function checkAuth(req, res, next) {
  const { authorization } = req.headers;

  try {
    const decoded = jwt.verify(authorization, process.env.JWT_KEY);
    const db = await connectDb();
    const [rows] = await db.query(
      "SELECT id, name, email , role FROM Utilisateur WHERE id = ?",
      [decoded.id]
    );

    if (rows.length === 0) {
      throw new Error("User not found");
    }

    req.user = rows[0];
    return next();
  } catch (error) {
    console.error(error);
  }

  res.status(401);
  res.send("Unauthorized");
  return;
}

export { validateData, logger, checkAuth };
