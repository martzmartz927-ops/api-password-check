const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PASS_FILE = path.join(ROOT, 'pass.txt');

function readPasses() {
  try {
    const txt = fs.readFileSync(PASS_FILE, 'utf8');
    return txt
      .split(/\r?\n/)
      .map(s => s.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function serveStatic(req, res, pathname) {
  const safePath = pathname === '/' ? '/index.html' : pathname;
  const filePath = path.join(ROOT, safePath);

  if (!filePath.startsWith(ROOT)) {
    return send(res, 403, 'Forbidden');
  }

  fs.readFile(filePath, (err, data) => {
    if (err) return send(res, 404, 'Not found');

    const ext = path.extname(filePath).toLowerCase();
    const types = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.txt': 'text/plain; charset=utf-8'
    };

    send(res, 200, data, types[ext] || 'application/octet-stream');
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'POST' && url.pathname === '/api/check') {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) req.destroy();
    });

    req.on('end', () => {
      let pass = '';
      try {
        const json = body ? JSON.parse(body) : {};
        pass = String(json.pass ?? '').trim();
      } catch {
        pass = '';
      }

      const passes = readPasses();
      const ok = passes.includes(pass);
      send(res, 200, JSON.stringify({ ok }), 'application/json; charset=utf-8');
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/api/check') {
    const pass = String(url.searchParams.get('pass') || '').trim();
    const passes = readPasses();
    const ok = passes.includes(pass);
    send(res, 200, JSON.stringify({ ok }), 'application/json; charset=utf-8');
    return;
  }

  serveStatic(req, res, url.pathname);
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
