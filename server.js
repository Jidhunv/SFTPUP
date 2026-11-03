'use strict';
// SFileUp - password-protected internal uploader for .zip / .rar files.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const { verifyPassword } = require('./password');
const views = require('./views');

const env = process.env;
const UPLOAD_DIR = path.resolve(env.SFILEUP_UPLOAD_DIR || path.join(__dirname, 'uploads'));
const ALLOWED_EXT = new Set(['.zip', '.rar']);
// Magic bytes: ZIP ("PK\x03\x04", empty "PK\x05\x06"), RAR4 and RAR5
const MAGIC = {
  '.zip': [Buffer.from('PK\x03\x04', 'latin1'), Buffer.from('PK\x05\x06', 'latin1')],
  '.rar': [Buffer.from('Rar!\x1a\x07\x00', 'latin1'), Buffer.from('Rar!\x1a\x07\x01\x00', 'latin1')],
};
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_BYTES = Number(env.SFILEUP_MAX_MB || 500) * 1024 * 1024;

let passwordHash = (env.SFILEUP_PASSWORD_HASH || '').trim();
const hashFile = path.join(__dirname, 'password.hash');
if (!passwordHash && fs.existsSync(hashFile)) passwordHash = fs.readFileSync(hashFile, 'utf8').trim();
if (!passwordHash) { console.error('No password set. Run: npm run set-password'); process.exit(1); }

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
app.disable('x-powered-by');
if (env.SFILEUP_TRUST_PROXY) app.set('trust proxy', Number(env.SFILEUP_TRUST_PROXY) || env.SFILEUP_TRUST_PROXY);

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'self'",
  });
  next();
});

app.use('/static', express.static(path.join(__dirname, 'public'), { index: false }));

app.use(session({
  name: 'sfileup.sid',
  secret: env.SFILEUP_SECRET_KEY || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: env.SFILEUP_HTTPS === '1',
    maxAge: 30 * 60 * 1000,
  },
}));

app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Per-session CSRF token; multipart bodies are checked after multer parses them.
app.use((req, res, next) => {
  req.session.csrf = req.session.csrf || crypto.randomBytes(16).toString('hex');
  next();
});
function checkCsrf(req) {
  const sent = Buffer.from(String((req.body && req.body.csrf) || ''));
  const want = Buffer.from(req.session.csrf);
  return sent.length === want.length && crypto.timingSafeEqual(sent, want);
}
function csrfGuard(req, res, next) {
  if (checkCsrf(req)) return next();
  res.status(400).send('Invalid CSRF token');
}

const flash = (req, cat, text) => { (req.session.flash = req.session.flash || []).push({ cat, text }); };
const takeFlash = (req) => { const f = req.session.flash || []; req.session.flash = []; return f; };
const requireAuth = (req, res, next) => (req.session.auth ? next() : res.redirect('/login'));

// ---- login rate limiting (in memory, per IP) ----
const failures = new Map(); // ip -> { count, first }
function lockedFor(ip) {
  const f = failures.get(ip);
  if (!f || f.count < MAX_ATTEMPTS) return 0;
  const left = f.first + LOCKOUT_MS - Date.now();
  if (left > 0) return left;
  failures.delete(ip);
  return 0;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.get('/login', (req, res) => res.send(views.login(takeFlash(req), req.session.csrf)));

app.post('/login', csrfGuard, async (req, res, next) => {
  try {
    const ip = req.ip;
    const wait = lockedFor(ip);
    if (wait) {
      flash(req, 'error', `Too many attempts. Try again in ${Math.ceil(wait / 60000)} min.`);
      return res.redirect('/login');
    }
    if (await verifyPassword(String(req.body.password || ''), passwordHash)) {
      failures.delete(ip);
      const csrf = req.session.csrf;
      return req.session.regenerate((err) => {   // new session id on login
        if (err) return next(err);
        req.session.csrf = csrf;
        req.session.auth = true;
        res.redirect('/');
      });
    }
    const f = failures.get(ip);
    failures.set(ip, f ? { count: f.count + 1, first: f.first } : { count: 1, first: Date.now() });
    await sleep(1000);
    flash(req, 'error', 'Incorrect password.');
    res.redirect('/login');
  } catch (e) { next(e); }
});

app.post('/logout', csrfGuard, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/', requireAuth, (req, res) => {
  const files = fs.readdirSync(UPLOAD_DIR, { withFileTypes: true })
    .filter((d) => d.isFile() && !d.name.startsWith('.upload-'))
    .map((d) => { const s = fs.statSync(path.join(UPLOAD_DIR, d.name)); return { name: d.name, size: s.size, mtime: s.mtimeMs }; })
    .sort((a, b) => b.mtime - a.mtime);
  res.send(views.upload(takeFlash(req), req.session.csrf, files));
});

const uploader = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, `.upload-${crypto.randomBytes(8).toString('hex')}`),
  }),
  limits: { fileSize: MAX_BYTES, files: 1 },
  fileFilter: (req, file, cb) => cb(null, ALLOWED_EXT.has(path.extname(file.originalname).toLowerCase())),
}).single('file');

// Auth is checked before multer so unauthenticated clients can't write anything to disk.
app.post('/upload', requireAuth, (req, res, next) => {
  uploader(req, res, (err) => {
    const tmp = req.file && req.file.path;
    const cleanup = () => { if (tmp) fs.rmSync(tmp, { force: true }); };
    const done = (cat, text) => { flash(req, cat, text); res.redirect('/'); };

    if (err) {
      cleanup();
      return done('error', err.code === 'LIMIT_FILE_SIZE' ? 'File too large.' : 'Upload failed.');
    }
    if (!checkCsrf(req)) { cleanup(); return res.status(400).send('Invalid CSRF token'); }
    if (!req.file) return done('error', 'Only .zip and .rar files are allowed.');

    // Keep only the base name, strip anything outside a safe character set.
    const raw = path.basename(req.file.originalname.replace(/\\/g, '/'));
    const ext = path.extname(raw).toLowerCase();
    let stem = path.basename(raw, path.extname(raw)).replace(/[^\w.\- ]+/g, '_').replace(/^\.+/, '').trim();
    if (!stem) stem = 'file';

    const head = Buffer.alloc(8);
    const fd = fs.openSync(tmp, 'r');
    const n = fs.readSync(fd, head, 0, 8, 0);
    fs.closeSync(fd);
    if (!MAGIC[ext].some((m) => n >= m.length && head.subarray(0, m.length).equals(m))) {
      cleanup();
      return done('error', `File content is not a valid ${ext} archive.`);
    }

    let name = stem + ext;
    if (fs.existsSync(path.join(UPLOAD_DIR, name))) name = `${stem}_${Math.floor(Date.now() / 1000)}${ext}`;
    fs.renameSync(tmp, path.join(UPLOAD_DIR, name));
    done('ok', `Uploaded ${name}`);
  });
});

app.use((err, req, res, next) => { console.error(err); res.status(500).send('Server error'); });

const port = Number(env.SFILEUP_PORT || 5000);
const host = env.SFILEUP_HOST || '127.0.0.1';
if (require.main === module) {
  app.listen(port, host, () => console.log(`SFileUp listening on http://${host}:${port}`));
}
module.exports = app;
