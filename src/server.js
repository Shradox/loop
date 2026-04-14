const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'loop-secret-change-in-production';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

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
    conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    PRIMARY KEY (conversation_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id INTEGER REFERENCES users(id),
    text TEXT NOT NULL DEFAULT '',
    msg_type TEXT NOT NULL DEFAULT 'text',
    file_url TEXT,
    file_name TEXT,
    file_size INTEGER,
    created_at INTEGER DEFAULT (unixepoch())
  );
  CREATE TABLE IF NOT EXISTS reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    emoji TEXT NOT NULL,
    UNIQUE(message_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS deleted_conversations (
    conversation_id INTEGER,
    user_id INTEGER,
    deleted_at INTEGER DEFAULT (unixepoch()),
    PRIMARY KEY (conversation_id, user_id)
  );
  CREATE INDEX IF NOT EXISTS idx_messages_conv ON messages(conversation_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_members_user ON conversation_members(user_id);
  CREATE INDEX IF NOT EXISTS idx_reactions_msg ON reactions(message_id);
`);

// ─── EXPRESS ───
const app = express();
app.use(express.json({ limit: '70mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ─── AUTH ───
app.post('/api/register', (req, res) => {
  const { username, password, display_name } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Нужны логин и пароль' });
  if (username.length < 3) return res.status(400).json({ error: 'Логин минимум 3 символа' });
  if (password.length < 4) return res.status(400).json({ error: 'Пароль минимум 4 символа' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Логин: только буквы, цифры, _' });
  const hash = bcrypt.hashSync(password, 10);
  try {
    const r = db.prepare('INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)').run(username.toLowerCase(), hash, display_name || username);
    const token = jwt.sign({ id: r.lastInsertRowid, username: username.toLowerCase() }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, user: { id: r.lastInsertRowid, username: username.toLowerCase(), display_name: display_name || username } });
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
  res.json(db.prepare('SELECT id, username, display_name, created_at FROM users WHERE id = ?').get(req.user.id));
});

// ─── USERS ───
app.get('/api/users/search', auth, (req, res) => {
  const q = (req.query.q || '').toLowerCase().trim();
  if (!q) return res.json([]);
  res.json(db.prepare('SELECT id, username, display_name FROM users WHERE username LIKE ? AND id != ? LIMIT 10').all(`%${q}%`, req.user.id));
});

// ─── FILE UPLOAD ───
app.post('/api/upload', auth, (req, res) => {
  const { data, filename, mimetype } = req.body;
  if (!data || !filename) return res.status(400).json({ error: 'Нет файла' });
  if (data.length > 70 * 1024 * 1024) return res.status(413).json({ error: 'Файл слишком большой (макс ~50MB)' });
  const ext = path.extname(filename).toLowerCase() || '';
  const safeName = crypto.randomBytes(16).toString('hex') + ext;
  try {
    const buffer = Buffer.from(data, 'base64');
    fs.writeFileSync(path.join(UPLOADS_DIR, safeName), buffer);
    res.json({ url: `/uploads/${safeName}`, filename, size: buffer.length, mimetype: mimetype || 'application/octet-stream' });
  } catch { res.status(500).json({ error: 'Ошибка сохранения' }); }
});

// ─── CONVERSATIONS ───
app.get('/api/conversations', auth, (req, res) => {
  const convs = db.prepare(`
    SELECT c.id, c.created_at,
      u.id as other_id, u.username as other_username, u.display_name as other_name,
      (SELECT text FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_text,
      (SELECT msg_type FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_type,
      (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_at
    FROM conversations c
    JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = ?
    JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id != ?
    JOIN users u ON u.id = cm2.user_id
    WHERE c.id NOT IN (SELECT conversation_id FROM deleted_conversations WHERE user_id = ?)
    ORDER BY COALESCE(last_at, c.created_at) DESC
  `).all(req.user.id, req.user.id, req.user.id);
  res.json(convs);
});

app.post('/api/conversations', auth, (req, res) => {
  const { user_id } = req.body;
  if (!user_id) return res.status(400).json({ error: 'Нужен user_id' });
  if (user_id === req.user.id) return res.status(400).json({ error: 'Нельзя написать себе' });
  const target = db.prepare('SELECT id, username, display_name FROM users WHERE id = ?').get(user_id);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN conversation_members cm1 ON cm1.conversation_id = c.id AND cm1.user_id = ?
    JOIN conversation_members cm2 ON cm2.conversation_id = c.id AND cm2.user_id = ?
  `).get(req.user.id, user_id);
  if (existing) {
    db.prepare('DELETE FROM deleted_conversations WHERE conversation_id = ? AND user_id = ?').run(existing.id, req.user.id);
    return res.json({ id: existing.id, other_id: target.id, other_username: target.username, other_name: target.display_name });
  }
  const conv = db.prepare('INSERT INTO conversations DEFAULT VALUES').run();
  db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(conv.lastInsertRowid, req.user.id);
  db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(conv.lastInsertRowid, user_id);
  res.json({ id: conv.lastInsertRowid, other_id: target.id, other_username: target.username, other_name: target.display_name });
});

app.delete('/api/conversations/:id', auth, (req, res) => {
  const convId = parseInt(req.params.id);
  const member = db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(convId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Нет доступа' });
  db.prepare('INSERT OR REPLACE INTO deleted_conversations (conversation_id, user_id) VALUES (?, ?)').run(convId, req.user.id);
  res.json({ ok: true });
});

// ─── MESSAGES ───
app.get('/api/conversations/:id/messages', auth, (req, res) => {
  const convId = parseInt(req.params.id);
  const member = db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(convId, req.user.id);
  if (!member) return res.status(403).json({ error: 'Нет доступа' });
  const msgs = db.prepare(`
    SELECT m.id, m.text, m.msg_type, m.file_url, m.file_name, m.file_size,
           m.created_at, m.sender_id, u.display_name as sender_name, u.username as sender_username
    FROM messages m JOIN users u ON u.id = m.sender_id
    WHERE m.conversation_id = ? ORDER BY m.created_at ASC LIMIT 200
  `).all(convId);
  if (msgs.length) {
    const ids = msgs.map(m => m.id);
    const reactions = db.prepare(`SELECT r.message_id, r.emoji, r.user_id, u.display_name as user_name FROM reactions r JOIN users u ON u.id = r.user_id WHERE r.message_id IN (${ids.map(()=>'?').join(',')})`).all(...ids);
    const byMsg = {};
    reactions.forEach(r => { if (!byMsg[r.message_id]) byMsg[r.message_id] = []; byMsg[r.message_id].push(r); });
    msgs.forEach(m => { m.reactions = byMsg[m.id] || []; });
  } else msgs.forEach(m => { m.reactions = []; });
  res.json(msgs);
});

// ─── REACTIONS ───
app.post('/api/messages/:id/react', auth, (req, res) => {
  const msgId = parseInt(req.params.id);
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Нужен emoji' });
  const msg = db.prepare('SELECT * FROM messages WHERE id = ?').get(msgId);
  if (!msg) return res.status(404).json({ error: 'Не найдено' });
  const member = db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(msg.conversation_id, req.user.id);
  if (!member) return res.status(403).json({ error: 'Нет доступа' });
  const existing = db.prepare('SELECT * FROM reactions WHERE message_id = ? AND user_id = ?').get(msgId, req.user.id);
  if (existing && existing.emoji === emoji) {
    db.prepare('DELETE FROM reactions WHERE message_id = ? AND user_id = ?').run(msgId, req.user.id);
  } else {
    db.prepare('INSERT OR REPLACE INTO reactions (message_id, user_id, emoji) VALUES (?, ?, ?)').run(msgId, req.user.id, emoji);
  }
  const allReactions = db.prepare('SELECT r.emoji, r.user_id, u.display_name as user_name FROM reactions r JOIN users u ON u.id = r.user_id WHERE r.message_id = ?').all(msgId);
  const members = db.prepare('SELECT user_id FROM conversation_members WHERE conversation_id = ?').all(msg.conversation_id);
  broadcast(members.map(m => m.user_id), { type: 'reaction_update', message_id: msgId, conversation_id: msg.conversation_id, reactions: allReactions });
  res.json({ reactions: allReactions });
});

// ─── WEBSOCKET ───
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
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
    let msg; try { msg = JSON.parse(raw); } catch { return; }

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

    if (msg.type === 'send_message') {
      const { conversation_id, text, msg_type, file_url, file_name, file_size } = msg;
      if (!conversation_id) return;
      const type = msg_type || 'text';
      if (type === 'text' && (!text || !text.trim())) return;
      if (type !== 'text' && !file_url) return;
      const member = db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(conversation_id, userId);
      if (!member) return;
      const msgText = type === 'text' ? text.trim() : (text || '');
      const result = db.prepare('INSERT INTO messages (conversation_id, sender_id, text, msg_type, file_url, file_name, file_size) VALUES (?, ?, ?, ?, ?, ?, ?)').run(conversation_id, userId, msgText, type, file_url || null, file_name || null, file_size || null);
      const saved = db.prepare(`SELECT m.id, m.text, m.msg_type, m.file_url, m.file_name, m.file_size, m.created_at, m.sender_id, u.display_name as sender_name, u.username as sender_username FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = ?`).get(result.lastInsertRowid);
      saved.reactions = [];
      const members = db.prepare('SELECT user_id FROM conversation_members WHERE conversation_id = ?').all(conversation_id);
      broadcast(members.map(m => m.user_id), { type: 'new_message', conversation_id, message: saved });
      return;
    }

    if (msg.type === 'typing') {
      const members = db.prepare('SELECT user_id FROM conversation_members WHERE conversation_id = ?').all(msg.conversation_id);
      broadcast(members.map(m => m.user_id).filter(id => id !== userId), { type: 'typing', conversation_id: msg.conversation_id, user_id: userId });
    }
  });
  ws.on('close', () => {
    if (userId) { const c = online.get(userId); if (c) { c.delete(ws); if (!c.size) online.delete(userId); } }
  });
});

server.listen(PORT, () => console.log(`LOOP running on :${PORT}`));
