const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const rateLimit = require('express-rate-limit');
const csrf = require('csurf');

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 login attempts
  message: 'Too many login attempts, please try again later'
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: 'Too many requests, please try again later'
});

const csrfProtection = csrf({ cookie: true });

app.use(express.static("public"));

const users = [];

(async () => {
  const passwordHash = await bcrypt.hash("password123", 12);
  users.push({
    id: 1,
    username: "student",
    passwordHash: passwordHash
  });
})();

const sessions = {}; // token -> { userId, createdAt }

function generateSecureToken() {
  return crypto.randomBytes(32).toString('hex');
}

function findUser(username) {
  return users.find((u) => u.username === username);
}


setInterval(() => {
  const now = Date.now();
  const ONE_HOUR = 60 * 60 * 1000;
  Object.keys(sessions).forEach(token => {
    if (now - sessions[token].createdAt > ONE_HOUR) {
      delete sessions[token];
    }
  });
}, 5 * 60 * 1000); // Run every 5 minutes


app.get("/api/me", generalLimiter, (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

app.post("/api/login", loginLimiter, csrfProtection, async (req, res) => {
  const { username, password } = req.body;
  
  const user = findUser(username);
  
  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid credentials" });
  }
  
  const isValid = await bcrypt.compare(password, user.passwordHash);
  
  if (!isValid) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid credentials" });
  }
  
  const token = generateSecureToken();
  
  sessions[token] = { 
    userId: user.id,
    createdAt: Date.now()
  };
  
  res.cookie("session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000 // 1 hour
  });
  
  res.json({ success: true, token });
});

app.post("/api/logout", csrfProtection, (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
