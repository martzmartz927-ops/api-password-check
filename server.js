const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PASS_FILE = path.join(ROOT, 'pass.txt');
const MAX_BODY_BYTES = 1024;
const WINDOW_MS = 60 * 1000;
const MAX_REQ_PER_WINDOW = 20;

// Simple in-memory rate limit by IP.
const requestsByIp = new Map();

function now() {
  return Date.now();
}

function getIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string' && xff.trim()) {
    return xff.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
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

function send(res, statusCode, payload, contentType = 'application/json; charset=utf-8') {
  setSecurityHeaders(res);
  res.writeHead(statusCode, { 'Content-Type': contentType });
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

function loadPasswords() {
  try {
    const raw = fs.readFileSync(PASS_FILE, 'utf8');
    return raw
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function savePasswords(lines) {
  const tmp = `${PASS_FILE}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, lines.join('\n') + (lines.length ? '\n' : ''), 'utf8');
  fs.renameSync(tmp, PASS_FILE);
}

function consumePassword(pass) {
  const current = loadPasswords();
  const idx = current.indexOf(pass);
  if (idx === -1) return false;

  current.splice(idx, 1);
  savePasswords(current);
  return true;
}

function rateLimit(req, res) {
  const ip = getIp(req);
  const bucket = requestsByIp.get(ip) || { count: 0, start: now() };

  if (now() - bucket.start > WINDOW_MS) {
    bucket.count = 0;
    bucket.start = now();
  }

  bucket.count += 1;
  requestsByIp.set(ip, bucket);

  if (bucket.count > MAX_REQ_PER_WINDOW) {
    send(res, 429, { ok: false });
    return true;
  }
  return false;
}

function isAllowedOrigin(req) {
  const allowed = process.env.ALLOWED_ORIGIN;
  if (!allowed) return true;
  const origin = req.headers.origin;
  if (!origin) return true; // allow non-browser clients
  return origin === allowed;
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    send(res, 204, '');
    return;
  }

  if (!isAllowedOrigin(req)) {
    send(res, 403, { ok: false });
    return;
  }

  if (rateLimit(req, res)) return;

  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/health') {
    send(res, 200, { ok: true, service: 'api-password-check' });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/') {
    send(res, 200, 'API is running', 'text/plain; charset=utf-8');
    return;
  }

  if (req.method === 'POST' && url.pathname === '/api/check') {
    parseJsonBody(req, (err, data) => {
      if (err) {
        send(res, 400, { ok: false });
        return;
      }

      const pass = String(data.pass ?? '').trim();
      if (!pass) {
        send(res, 200, { ok: false });
        return;
      }

      const ok = consumePassword(pass);
      send(res, 200, { ok });
    });
    return;
  }

  send(res, 404, { ok: false });
});

server.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
