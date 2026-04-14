const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'loop-secret-change-in-production';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');

// Ensure data dir exists (for Render persistent disk)
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ─── DATABASE ───
const db = new Database(path.join(DATA_DIR, 'loop.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id INTEGER REFERENCES conversations(id),
    user_id INTEGER REFERENCES users(id),
    PRIMARY KEY (conversation_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER REFERENCES conversations(id),
    sender_id INTEGER REFERENCES users(id),
    text TEXT NOT NULL,
    created_at INTEGER DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);
`);

// ─── EXPRESS ───
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Auth middleware
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(h.slice(7), JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ─── AUTH ROUTES ───
app.post('/api/register', (req, res) => {
  const { username, password, display_name } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
  if (username.length < 3) return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Логин: только буквы, цифры, _' });

  const hash = bcrypt.hashSync(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)');
    const result = stmt.run(username.toLowerCase(), hash, display_name || username);
    const token = jwt.sign({ id: result.lastInsertRowid, username: username.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: result.lastInsertRowid, username: username.toLowerCase(), display_name: display_name || username } });
  } catch (e) {
    if (e.message.includes('UNIQUE')) return res.status(409).json({ error: 'Логин уже занят' });
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, display_name: user.display_name } });
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, username, display_name, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(user);
});

// ─── USER SEARCH ───
app.get('/api/users/search', auth, (req, res) => {
  const q = (req.query.q || '').toLowerCase().trim();
  if (!q) return res.json([]);
  const users = db.prepare(
    'SELECT id, username, display_name FROM users WHERE username LIKE ? AND id != ? LIMIT 10'
  ).all(`%${q}%`, req.user.id);
  res.json(users);
});

// ─── CONVERSATIONS ───
app.get('/api/conversations', auth, (req, res) => {
  const convs = db.prepare(`
    SELECT c.id, c.created_at,
      u.id as other_id, u.username as other_username, u.display_name as other_name,
      (SELECT text FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_text,
      (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_at
    FROM conversations c
    JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = ?
    JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id != ?
    JOIN users u ON u.id = cm2.user_id
    ORDER BY COALESCE(last_at, c.created_at) DESC
  `).all(req.user.id, req.user.id);
  res.json(convs);
});

app.post('/api/conversations', auth, (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'Нужен user_id' });
  if (user_id === req.user.id) return res.status(400).json({ error: 'Нельзя написать себе' });

  const target = db.prepare('SELECT id, username, display_name FROM users WHERE id = ?').get(user_id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });

  // Check if conversation already exists
  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN conversation_members cm1 ON cm1.conversation_id = c.id AND cm1.user_id = ?
    JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id = ?
  `).get(req.user.id, user_id);

  if (existing) return res.json({ id: existing.id, other_id: target.id, other_username: target.username, other_name: target.display_name });

  const conv = db.prepare('INSERT INTO conversations DEFAULT VALUES').run();
  db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(conv.lastInsertRowid, req.user.id);
  db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(conv.lastInsertRowid, user_id);

  res.json({ id: conv.lastInsertRowid, other_id: target.id, other_username: target.username, other_name: target.display_name });
});

// ─── MESSAGES ───
app.get('/api/conversations/:id/messages', auth, (req, res) => {
  const convId = parseInt(req.params.id);
  // Check membership
  const member = db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(convId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Нет доступа' });

  const msgs = db.prepare(`
    SELECT m.id, m.text, m.created_at, m.sender_id, u.display_name as sender_name, u.username as sender_username
    FROM messages m JOIN users u ON u.id = m.sender_id
    WHERE m.conversation_id = ?
    ORDER BY m.created_at ASC
    LIMIT 100
  `).all(convId);
  res.json(msgs);
});

// ─── HTTP SERVER + WS ───
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Map userId -> Set of ws connections
const online = new Map();

function broadcast(userIds, data) {
  const msg = JSON.stringify(data);
  for (const uid of userIds) {
    const conns = online.get(uid);
    if (conns) conns.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(msg); });
  }
}

wss.on('connection', (ws) => {
  let userId = null;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    // ── AUTH ──
    if (msg.type === 'auth') {
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        userId = payload.id;
        if (!online.has(userId)) online.set(userId, new Set());
        online.get(userId).add(ws);
        ws.send(JSON.stringify({ type: 'auth_ok', userId }));
      } catch { ws.send(JSON.stringify({ type: 'auth_error' })); }
      return;
    }

    if (!userId) return;

    // ── SEND MESSAGE ──
    if (msg.type === 'send_message') {
      const { conversation_id, text } = msg;
      if (!text || !text.trim() || !conversation_id) return;

      const member = db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(conversation_id, userId);
      if (!member) return;

      const result = db.prepare('INSERT INTO messages (conversation_id, sender_id, text) VALUES (?, ?, ?)').run(conversation_id, userId, text.trim());
      const saved = db.prepare(`
        SELECT m.id, m.text, m.created_at, m.sender_id, u.display_name as sender_name, u.username as sender_username
        FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = ?
      `).get(result.lastInsertRowid);

      // Get all members of this conversation
      const members = db.prepare('SELECT user_id FROM conversation_members WHERE conversation_id = ?').all(conversation_id);
      const memberIds = members.map(m => m.user_id);

      broadcast(memberIds, { type: 'new_message', conversation_id, message: saved });
      return;
    }

    // ── TYPING ──
    if (msg.type === 'typing') {
      const { conversation_id } = msg;
      const members = db.prepare('SELECT user_id FROM conversation_members WHERE conversation_id = ?').all(conversation_id);
      const others = members.map(m => m.user_id).filter(id => id !== userId);
      broadcast(others, { type: 'typing', conversation_id, user_id: userId });
    }
  });

  ws.on('close', () => {
    if (userId) {
      const conns = online.get(userId);
      if (conns) { conns.delete(ws); if (conns.size === 0) online.delete(userId); }
    }
  });
});

server.listen(PORT, () => console.log(`LOOP running on :${PORT}`));
