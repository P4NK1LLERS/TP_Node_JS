import mysql2 from "mysql2/promise";

function dayOfTheYear() {
  const now = new Date();
  const start = new Date(now.getFullYear(), 0, 0);
  const diff = now - start;
  const oneDay = 1000 * 60 * 60 * 24;
  const day = Math.floor(diff / oneDay);
  return day;
}

function listFiles() {
  return ["file1", "file2", "file3"];
}

async function connectDb() {
  let db = await mysql2.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
  });

  return db;
}

export { dayOfTheYear, listFiles, connectDb };
