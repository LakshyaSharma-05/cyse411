const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');

const app = express();

app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 5,
  message: 'Too many login attempts, please try again later'
});

const transferLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many requests, please try again later'
});

const csrfProtection = csrf({ cookie: true });

const db = new sqlite3.Database(":memory:");

db.serialize(async () => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const passwordHash = await bcrypt.hash("password123", 12);

  db.run(`INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)`,
    ['alice', passwordHash, 'alice@example.com']);

  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)`,
    [1, 25.50, 'Coffee shop']);
  db.run(`INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)`,
    [1, 100, 'Groceries']);
});

const sessions = {};


function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) return res.status(401).json({ error: "Not authenticated" });
  req.user = { id: sessions[sid].userId };
  next();
}

function generateSecureSessionId() {
  return crypto.randomBytes(32).toString('hex');
}


app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;


  const sql = `SELECT id, username, password_hash FROM users WHERE username = ?`;

  db.get(sql, [username], async (err, user) => {

    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    // FIXED: Use bcrypt.compare instead of fast hash
    const isValid = await bcrypt.compare(password, user.password_hash);
    
    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }


    const sid = generateSecureSessionId();
    sessions[sid] = { userId: user.id };


    res.cookie("sid", sid, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 3600000
    });

    res.json({ success: true });
  });
});


app.get("/me", auth, (req, res) => {
  db.get(`SELECT username, email FROM users WHERE id = ?`, [req.user.id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(row);
  });
});


app.get("/transactions", auth, transferLimiter, (req, res) => {
  const q = req.query.q || "";
  
  const sql = `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
  `;
  
  db.all(sql, [req.user.id, `%${q}%`], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post("/feedback", auth, csrfProtection, transferLimiter, (req, res) => {
  const comment = req.body.comment;
  const userId = req.user.id;

  db.get(`SELECT username FROM users WHERE id = ?`, [userId], (err, row) => {
    if (err || !row) return res.status(500).json({ error: 'Database error' });
    
    const username = row.username;

    const insert = `INSERT INTO feedback (user, comment) VALUES (?, ?)`;
    
    db.run(insert, [username, comment], (err) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    });
  });
});

app.get("/feedback", auth, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get("/feedback", auth, transferLimiter, (req, res) => {
  db.all("SELECT user, comment FROM feedback ORDER BY id DESC", (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.post("/change-email", auth, csrfProtection, transferLimiter, (req, res) => {
  const newEmail = req.body.email;

  if (!newEmail || !newEmail.includes("@")) {
    return res.status(400).json({ error: "Invalid email" });
  }

  const sql = `UPDATE users SET email = ? WHERE id = ?`;
  
  db.run(sql, [newEmail, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json({ success: true, email: newEmail });
  });
});

app.get("/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.listen(4000, () =>
  console.log("FastBank Version A backend running on http://localhost:4000")
);
