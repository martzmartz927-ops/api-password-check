const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DB_FILE = path.join(ROOT, 'db.json');

const MAX_BODY_BYTES = 16 * 1024;
const RATE_WINDOW_MS = 60 * 1000;
const MAX_REQ_PER_WINDOW = 30;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'iberia';
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

const rateByIp = new Map();
const sessions = new Map(); // token -> expiresAt

function now() {
  return Date.now();
}

function readText(file) {
  return fs.readFileSync(file, 'utf8');
}

function writeTextAtomic(file, content) {
  const tmp = `${file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, content, 'utf8');
  fs.renameSync(tmp, file);
}

function defaultDB() {
  return { keys: [] };
}

function loadDB() {
  try {
    const raw = readText(DB_FILE);
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.keys)) return defaultDB();
    parsed.keys = parsed.keys.filter(k => k && typeof k === 'object' && typeof k.key === 'string');
    return parsed;
  } catch {
    return defaultDB();
  }
}

function saveDB(db) {
  writeTextAtomic(DB_FILE, JSON.stringify(db, null, 2) + '\n');
}

function cleanupSessions() {
  const t = now();
  for (const [token, expiresAt] of sessions.entries()) {
    if (expiresAt <= t) sessions.delete(token);
  }
}

function getIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

function rateLimit(req) {
  const ip = getIp(req);
  const bucket = rateByIp.get(ip) || { count: 0, start: now() };

  if (now() - bucket.start > RATE_WINDOW_MS) {
    bucket.count = 0;
    bucket.start = now();
  }

  bucket.count += 1;
  rateByIp.set(ip, bucket);
  return bucket.count > MAX_REQ_PER_WINDOW;
}

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || '*');
}

function send(res, statusCode, payload, contentType = 'application/json; charset=utf-8', extraHeaders = {}) {
  setSecurityHeaders(res);
  res.writeHead(statusCode, { 'Content-Type': contentType, ...extraHeaders });
  if (typeof payload === 'string') {
    res.end(payload);
  } else {
    res.end(JSON.stringify(payload));
  }
}

function parseJsonBody(req, callback) {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) {
      req.destroy();
    }
  });
  req.on('end', () => {
    if (!body) return callback(null, {});
    try {
      callback(null, JSON.parse(body));
    } catch {
      callback(new Error('invalid_json'));
    }
  });
}

function getCookies(req) {
  const header = req.headers.cookie;
  const cookies = {};
  if (!header) return cookies;
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    cookies[key] = decodeURIComponent(value);
  });
  return cookies;
}

function getAdminToken(req) {
  const cookies = getCookies(req);
  return cookies.session || '';
}

function isAdmin(req) {
  cleanupSessions();
  const token = getAdminToken(req);
  if (!token) return false;
  const exp = sessions.get(token);
  return typeof exp === 'number' && exp > now();
}

function requireAdmin(req, res) {
  if (!isAdmin(req)) {
    send(res, 401, { ok: false });
    return false;
  }
  return true;
}

function issueSession(res) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, now() + SESSION_TTL_MS);
  const cookie = [
    `session=${encodeURIComponent(token)}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
  ].join('; ');
  return cookie;
}

function safeKey(key) {
  return String(key ?? '').trim();
}

function loadPage(name) {
  return readText(path.join(ROOT, name));
}

function serveFile(res, filePath, contentType) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      send(res, 404, { ok: false });
      return;
    }
    setSecurityHeaders(res);
    res.writeHead(200, { 'Content-Type': contentType || 'application/octet-stream' });
    res.end(data);
  });
}

function findKeyIndex(db, key) {
  return db.keys.findIndex(item => item.key === key);
}

function addKey(db, key) {
  if (db.keys.some(item => item.key === key)) return false;
  db.keys.push({
    key,
    script: null,
    createdAt: new Date().toISOString(),
    usedAt: null
  });
  return true;
}

function attachScript(db, key, script) {
  const idx = findKeyIndex(db, key);
  if (idx === -1) return false;
  db.keys[idx].script = String(script);
  return true;
}

function consumeKeyIfBound(db, key) {
  const idx = findKeyIndex(db, key);
  if (idx === -1) return { ok: false };
  const item = db.keys[idx];

  if (!item.script) {
    return { ok: true, script: null, consumed: false };
  }

  const script = item.script;
  db.keys.splice(idx, 1);
  return { ok: true, script, consumed: true };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'OPTIONS') {
    send(res, 204, '');
    return;
  }

  if (rateLimit(req)) {
    send(res, 429, { ok: false });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/') {
    send(res, 200, 'API is running', 'text/plain; charset=utf-8');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/health') {
    send(res, 200, { ok: true, service: 'api-key-script' });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin') {
    serveFile(res, path.join(ROOT, 'admin.html'), 'text/html; charset=utf-8');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin.css') {
    serveFile(res, path.join(ROOT, 'admin.css'), 'text/css; charset=utf-8');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/admin.js') {
    serveFile(res, path.join(ROOT, 'admin.js'), 'application/javascript; charset=utf-8');
    return;
  }

  if (req.method === 'POST' && url.pathname === '/admin/login') {
    parseJsonBody(req, (err, data) => {
      if (err) {
        send(res, 400, { ok: false });
        return;
      }
      const password = String(data.password ?? '').trim();
      if (password !== ADMIN_PASSWORD) {
        send(res, 200, { ok: false });
        return;
      }
      const cookie = issueSession(res);
      send(res, 200, { ok: true }, 'application/json; charset=utf-8', {
        'Set-Cookie': cookie
      });
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/admin/logout') {
    const token = getAdminToken(req);
    if (token) sessions.delete(token);
    send(res, 200, { ok: true }, 'application/json; charset=utf-8', {
      'Set-Cookie': 'session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/status') {
    send(res, 200, { ok: true, admin: isAdmin(req) });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/keys') {
    if (!requireAdmin(req, res)) return;
    const db = loadDB();
    send(res, 200, {
      ok: true,
      keys: db.keys.map(item => ({
        key: item.key,
        hasScript: Boolean(item.script),
        createdAt: item.createdAt,
        usedAt: item.usedAt
      }))
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/key/add') {
    if (!requireAdmin(req, res)) return;
    parseJsonBody(req, (err, data) => {
      if (err) {
        send(res, 400, { ok: false });
        return;
      }
      const key = safeKey(data.key);
      if (!key || key.length > 256) {
        send(res, 200, { ok: false });
        return;
      }
      const db = loadDB();
      const added = addKey(db, key);
      if (added) saveDB(db);
      send(res, 200, { ok: added });
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/key/attach') {
    if (!requireAdmin(req, res)) return;
    parseJsonBody(req, (err, data) => {
      if (err) {
        send(res, 400, { ok: false });
        return;
      }
      const key = safeKey(data.key);
      const script = String(data.script ?? '');
      if (!key || script.length > 50_000) {
        send(res, 200, { ok: false });
        return;
      }
      const db = loadDB();
      const attached = attachScript(db, key, script);
      if (attached) {
        const idx = findKeyIndex(db, key);
        if (idx !== -1) db.keys[idx].usedAt = null;
        saveDB(db);
      }
      send(res, 200, { ok: attached });
    });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/check') {
    parseJsonBody(req, (err, data) => {
      if (err) {
        send(res, 400, { ok: false });
        return;
      }

      const key = safeKey(data.key ?? data.pass);
      if (!key) {
        send(res, 200, { ok: false });
        return;
      }

      const db = loadDB();
      const idx = findKeyIndex(db, key);
      if (idx === -1) {
        send(res, 200, { ok: false });
        return;
      }

      const item = db.keys[idx];
      if (!item.script) {
        // Key stays in database until a script is attached.
        send(res, 200, { ok: true });
        return;
      }

      const script = item.script;
      db.keys.splice(idx, 1);
      saveDB(db);

      send(res, 200, { ok: true, script });
    });
    return;
  }

  send(res, 404, { ok: false });
});

server.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
