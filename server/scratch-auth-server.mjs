import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const PORT = Number(process.env.AUTH_PORT || 3901);
const HOST = process.env.AUTH_HOST || '127.0.0.1';
const USERS_FILE = process.env.USERS_FILE || '/var/lib/scratch-auth/users.json';
const GAME_FILE = process.env.GAME_FILE || '/var/www/escape-the-room/scratch/index.html';
const COOKIE_NAME = 'scratch_session';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const SECURE_COOKIE = process.env.COOKIE_SECURE !== 'false';
const MAX_BODY = 12 * 1024;

const sessions = new Map();
const loginHits = new Map();
const registerHits = new Map();

let users;
try {
  users = loadUsers();
} catch (err) {
  console.error('Failed to load users:', err.message);
  process.exit(1);
}

function loadUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (!data || typeof data !== 'object' || Array.isArray(data)) return {};
    return data;
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw err;
  }
}

function saveUsers() {
  fs.mkdirSync(path.dirname(USERS_FILE), { recursive: true, mode: 0o700 });
  const tmp = USERS_FILE + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, USERS_FILE);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, rec) {
  if (!rec || typeof rec.salt !== 'string' || typeof rec.hash !== 'string') return false;
  const actual = crypto.scryptSync(password, rec.salt, 64);
  const expected = Buffer.from(rec.hash, 'hex');
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

function createSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username, expiresAt: Date.now() + SESSION_TTL_MS });
  return token;
}

function getCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(i + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

function getSession(req) {
  const token = getCookie(req, COOKIE_NAME);
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, ...session };
}

function cookieAttrs() {
  return 'Path=/; HttpOnly; SameSite=Lax' + (SECURE_COOKIE ? '; Secure' : '');
}

function sessionCookie(token) {
  return COOKIE_NAME + '=' + token + '; ' + cookieAttrs() + '; Max-Age=' + Math.floor(SESSION_TTL_MS / 1000);
}

function clearSessionCookie() {
  return COOKIE_NAME + '=; ' + cookieAttrs() + '; Max-Age=0';
}

function clientIp(req) {
  const real = req.headers['x-real-ip'];
  if (real) return String(real);
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.socket.remoteAddress || 'unknown';
}

function isLimited(map, key, max, windowMs) {
  const now = Date.now();
  const entry = map.get(key);
  if (!entry || now > entry.resetAt) {
    map.set(key, { count: 1, resetAt: now + windowMs });
    return false;
  }
  entry.count++;
  return entry.count > max;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    let tooLarge = false;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        tooLarge = true;
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      if (tooLarge) reject(new Error('body too large'));
      else resolve(new URLSearchParams(body));
    });
    req.on('error', reject);
  });
}

function esc(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[ch]));
}

function pageShell(title, subtitle, content, error = '') {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${esc(title)} · 小确幸刮刮乐</title>
<style>
  :root {
    --ink: #66503f;
    --sub: #a08a74;
    --accent: #e8896a;
    --accent-dark: #c9664a;
    --line: rgba(196, 165, 127, .45);
    --paper: #fffdf8;
  }
  * { box-sizing: border-box; }
  html, body { min-height: 100%; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 24px 16px;
    font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
    color: var(--ink);
    background:
      radial-gradient(circle at 18% 18%, rgba(255, 207, 174, .55), transparent 34%),
      radial-gradient(circle at 82% 22%, rgba(214, 200, 255, .45), transparent 32%),
      radial-gradient(circle at 50% 95%, rgba(255, 226, 185, .5), transparent 40%),
      linear-gradient(145deg, #fdf4e8, #fbf3ea 50%, #f6eef8);
    overflow-x: hidden;
  }
  body::before, body::after {
    content: ""; position: fixed; border-radius: 50%; filter: blur(10px); pointer-events: none;
  }
  body::before { width: 240px; height: 240px; left: -80px; bottom: -90px; background: rgba(255, 200, 170, .3); }
  body::after { width: 200px; height: 200px; right: -70px; top: -80px; background: rgba(190, 175, 245, .22); }
  .wrap { position: relative; width: 100%; max-width: 400px; }
  .brand {
    text-align: center; font-size: 10px; letter-spacing: .28em; color: #a08a74;
    margin-bottom: 12px;
  }
  .card {
    position: relative;
    padding: 28px 26px 22px;
    border-radius: 24px;
    background: linear-gradient(160deg, rgba(255,255,255,.92), rgba(255,249,239,.92));
    border: 1px solid var(--line);
    box-shadow: 0 30px 60px -30px rgba(120, 82, 52, .55), inset 0 1px 0 rgba(255,255,255,.9);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
  }
  .eyebrow {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 9px; letter-spacing: .12em; color: var(--accent-dark);
    background: rgba(255, 240, 228, .9); border: 1px solid rgba(232, 137, 106, .22);
    border-radius: 999px; padding: 4px 9px;
  }
  .eyebrow::before { content: ""; width: 5px; height: 5px; border-radius: 50%; background: var(--accent); }
  h1 { margin: 14px 0 6px; font-size: 25px; line-height: 1.2; letter-spacing: .02em; }
  .sub { margin: 0 0 20px; font-size: 12px; line-height: 1.7; color: var(--sub); }
  .error {
    margin: 0 0 14px; padding: 9px 11px; border-radius: 11px;
    background: #fff1ee; border: 1px solid rgba(196, 94, 72, .22);
    color: #b2503a; font-size: 11.5px; line-height: 1.5;
  }
  form { display: grid; gap: 12px; }
  label { display: grid; gap: 6px; font-size: 11px; font-weight: 600; color: #7b6551; }
  input {
    width: 100%; padding: 11px 12px; border-radius: 12px;
    border: 1px solid rgba(190, 165, 135, .45);
    background: rgba(255, 253, 248, .95);
    color: var(--ink); font: inherit; font-size: 13px;
    outline: none; transition: border-color .18s ease, box-shadow .18s ease;
  }
  input::placeholder { color: #c3b2a0; }
  input:focus { border-color: rgba(232, 137, 106, .7); box-shadow: 0 0 0 3px rgba(232, 137, 106, .12); }
  button {
    margin-top: 4px; width: 100%; padding: 12px 14px;
    border: 0; border-radius: 13px; cursor: pointer;
    font: inherit; font-size: 14px; font-weight: 700; letter-spacing: .08em;
    color: #fffaf4;
    background: linear-gradient(135deg, #f0a07f, var(--accent));
    box-shadow: 0 10px 22px -12px rgba(201, 102, 74, .9), inset 0 1px 0 rgba(255,255,255,.35);
    transition: transform .15s ease, box-shadow .15s ease;
  }
  button:hover { transform: translateY(-1px); box-shadow: 0 14px 24px -12px rgba(201, 102, 74, .95); }
  button:active { transform: translateY(1px); }
  .switch { margin-top: 16px; text-align: center; font-size: 11.5px; color: var(--sub); }
  .switch a { color: var(--accent-dark); font-weight: 700; text-decoration: none; border-bottom: 1px dashed rgba(201, 102, 74, .45); }
  .switch a:hover { color: #a94f35; }
  .foot { margin-top: 14px; text-align: center; font-size: 9px; letter-spacing: .16em; color: #b3a18e; }
  .msg { font-size: 13px; line-height: 1.8; color: #7a6450; }
  .msg a { color: var(--accent-dark); }
  @media (max-width: 420px) {
    .card { padding: 24px 20px 20px; border-radius: 21px; }
    h1 { font-size: 23px; }
  }
</style>
</head>
<body>
  <main class="wrap">
    <div class="brand">XIAO QUE XING · SCRATCH</div>
    <section class="card">
      <div class="eyebrow">今日份 · 小确幸</div>
      <h1>${esc(title)}</h1>
      <p class="sub">${esc(subtitle)}</p>
      ${error ? `<div class="error">${esc(error)}</div>` : ''}
      ${content}
    </section>
    <div class="foot">轻轻刮开 · 慢慢生活</div>
  </main>
</body>
</html>`;
}

function loginPage(error = '') {
  return pageShell(
    '欢迎回来',
    '登录后继续刮开今天的小确幸。',
    `<form method="post" action="/auth/login">
      <label>用户名
        <input name="username" required maxlength="24" pattern="[A-Za-z0-9_]{3,24}" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="3-24 位字母、数字或下划线" autofocus>
      </label>
      <label>密码
        <input type="password" name="password" required minlength="8" maxlength="72" autocomplete="current-password" placeholder="至少 8 位">
      </label>
      <button type="submit">登录</button>
    </form>
    <div class="switch">还没有账号？<a href="/auth/register">注册一个</a></div>`,
    error
  );
}

function registerPage(error = '') {
  return pageShell(
    '创建账号',
    '注册后就能进入这台服务器上的刮刮乐。',
    `<form method="post" action="/auth/register">
      <label>用户名
        <input name="username" required maxlength="24" pattern="[A-Za-z0-9_]{3,24}" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="3-24 位字母、数字或下划线" autofocus>
      </label>
      <label>密码
        <input type="password" name="password" required minlength="8" maxlength="72" autocomplete="new-password" placeholder="至少 8 位">
      </label>
      <label>确认密码
        <input type="password" name="confirm" required minlength="8" maxlength="72" autocomplete="new-password" placeholder="再输入一次密码">
      </label>
      <button type="submit">注册并进入</button>
    </form>
    <div class="switch">已经有账号？<a href="/auth/login">去登录</a></div>`,
    error
  );
}

function messagePage(title, message) {
  return pageShell(
    title,
    ' ',
    `<p class="msg">${esc(message)}</p>
     <div class="switch"><a href="/auth/login">返回登录</a></div>`
  );
}

function sendHtml(req, res, status, html, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    ...extraHeaders
  });
  if (req.method === 'HEAD') res.end();
  else res.end(html);
}

function redirect(req, res, location, status = 303) {
  res.writeHead(status, {
    Location: location,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end();
}

function serveGame(req, res) {
  let html;
  try {
    html = fs.readFileSync(GAME_FILE, 'utf8');
  } catch (err) {
    console.error('Failed to read game file:', err.message);
    return sendHtml(req, res, 500, messagePage('暂时打不开', '游戏文件读取失败，请稍后再试。'));
  }
  const logout = '<a href="/auth/logout" style="position:fixed;top:12px;right:14px;z-index:7;padding:7px 12px;border-radius:999px;background:rgba(255,252,246,.9);border:1px solid rgba(196,165,127,.6);box-shadow:0 6px 16px -10px rgba(105,78,52,.6);color:#7a6652;font:600 11px -apple-system,BlinkMacSystemFont,\'PingFang SC\',\'Microsoft YaHei\',sans-serif;text-decoration:none;letter-spacing:.04em;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);">退出登录</a>';
  const withLogout = html.includes('</body>')
    ? html.replace('</body>', logout + '\n</body>')
    : html + logout;
  sendHtml(req, res, 200, withLogout);
}

function isGamePath(pathname) {
  return pathname === '/scratch' || pathname === '/scratch/' || pathname === '/scratch/index.html';
}

const server = http.createServer(async (req, res) => {
  const method = req.method === 'HEAD' ? 'GET' : req.method;
  try {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;

    if (method === 'GET' && isGamePath(pathname)) {
      const session = getSession(req);
      if (!session) return redirect(req, res, '/auth/login');
      return serveGame(req, res);
    }

    if (method === 'GET' && pathname === '/auth/login') {
      if (getSession(req)) return redirect(req, res, '/scratch/');
      return sendHtml(req, res, 200, loginPage());
    }

    if (req.method === 'POST' && pathname === '/auth/login') {
      if (isLimited(loginHits, clientIp(req), 10, 10 * 60 * 1000)) {
        return sendHtml(req, res, 429, loginPage('尝试次数过多，请稍后再试。'));
      }
      let form;
      try {
        form = await readBody(req);
      } catch {
        return sendHtml(req, res, 400, loginPage('提交内容有误，请重试。'));
      }
      const username = String(form.get('username') || '').trim();
      const password = String(form.get('password') || '');
      const key = username.toLowerCase();
      const rec = users[key];
      if (!rec || !verifyPassword(password, rec)) {
        return sendHtml(req, res, 401, loginPage('用户名或密码不正确。'));
      }
      loginHits.delete(clientIp(req));
      const token = createSession(key);
      res.setHeader('Set-Cookie', sessionCookie(token));
      return redirect(req, res, '/scratch/');
    }

    if (method === 'GET' && pathname === '/auth/register') {
      if (getSession(req)) return redirect(req, res, '/scratch/');
      return sendHtml(req, res, 200, registerPage());
    }

    if (req.method === 'POST' && pathname === '/auth/register') {
      if (isLimited(registerHits, clientIp(req), 5, 60 * 60 * 1000)) {
        return sendHtml(req, res, 429, registerPage('注册次数过多，请稍后再试。'));
      }
      let form;
      try {
        form = await readBody(req);
      } catch {
        return sendHtml(req, res, 400, registerPage('提交内容有误，请重试。'));
      }
      const username = String(form.get('username') || '').trim();
      const password = String(form.get('password') || '');
      const confirm = String(form.get('confirm') || '');
      const key = username.toLowerCase();

      if (!/^[A-Za-z0-9_]{3,24}$/.test(username)) {
        return sendHtml(req, res, 400, registerPage('用户名需为 3-24 位字母、数字或下划线。'));
      }
      if (password.length < 8 || password.length > 72) {
        return sendHtml(req, res, 400, registerPage('密码长度需在 8-72 位之间。'));
      }
      if (password !== confirm) {
        return sendHtml(req, res, 400, registerPage('两次输入的密码不一致。'));
      }
      if (users[key]) {
        return sendHtml(req, res, 409, registerPage('这个用户名已经被注册了。'));
      }

      const record = {
        ...hashPassword(password),
        createdAt: new Date().toISOString()
      };
      users[key] = record;
      try {
        saveUsers();
      } catch (err) {
        delete users[key];
        throw err;
      }
      const token = createSession(key);
      res.setHeader('Set-Cookie', sessionCookie(token));
      return redirect(req, res, '/scratch/');
    }

    if (method === 'GET' && pathname === '/auth/logout') {
      const session = getSession(req);
      if (session) sessions.delete(session.token);
      res.setHeader('Set-Cookie', clearSessionCookie());
      return redirect(req, res, '/auth/login');
    }

    if (method === 'GET' && (pathname === '/auth' || pathname === '/auth/')) {
      return redirect(req, res, '/auth/login');
    }

    if (method === 'GET' && pathname === '/auth/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(req.method === 'HEAD' ? undefined : 'ok');
    }

    if (method === 'GET' && pathname === '/') {
      return redirect(req, res, '/auth/login');
    }

    sendHtml(req, res, 404, messagePage('页面不存在', '这个地址没有内容。'));
  } catch (err) {
    console.error('Request failed:', err.message);
    if (!res.headersSent) {
      sendHtml(req, res, 500, messagePage('服务器开小差了', '请稍后再试。'));
    } else {
      res.end();
    }
  }
});

server.requestTimeout = 15000;
server.headersTimeout = 20000;
server.keepAliveTimeout = 5000;

server.listen(PORT, HOST, () => {
  console.log('scratch-auth listening on ' + HOST + ':' + PORT);
});

setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(token);
  }
  for (const map of [loginHits, registerHits]) {
    for (const [key, entry] of map) {
      if (entry.resetAt <= now) map.delete(key);
    }
  }
}, 10 * 60 * 1000).unref();

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});
