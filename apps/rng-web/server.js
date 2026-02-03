import express from 'express';
import crypto from 'crypto';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import QRCode from 'qrcode';

const app = express();
app.set('trust proxy', 1);

// Basic hardening headers (OWASP baseline)
app.disable('x-powered-by');
app.use(
  helmet({
    // We serve only inline scripts/styles right now; keep CSP off for now to avoid breaking UI.
    contentSecurityPolicy: false
  })
);

app.use(express.json({ limit: '64kb' }));

// --- Passphrase gate (24h sessions) ---
// Stored secret is a SHA-256 hex digest (64 chars) in env PASSPHRASE_SHA256.
const PASSPHRASE_SHA256 = (process.env.PASSPHRASE_SHA256 || '').trim().toLowerCase();
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const sessions = new Map();

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i === -1) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!k) return;
    out[k] = decodeURIComponent(v);
  });
  return out;
}

function setCookie(res, name, value, { maxAgeMs } = {}) {
  const secure = (process.env.NODE_ENV === 'production');
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax'
  ];
  if (secure) parts.push('Secure');
  if (maxAgeMs != null) parts.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`);
}

function cleanupSessions() {
  const now = Date.now();
  for (const [k, v] of sessions.entries()) {
    if (!v || (now - v.createdAt) > SESSION_TTL_MS) sessions.delete(k);
  }
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function timingSafeEqHex(a, b) {
  try {
    const ba = Buffer.from(String(a).toLowerCase(), 'hex');
    const bb = Buffer.from(String(b).toLowerCase(), 'hex');
    if (ba.length !== bb.length) return False;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

function isAuthed(req) {
  cleanupSessions();
  const cookies = parseCookies(req);
  const sid = cookies.rng_sid;
  if (!sid) return false;
  const s = sessions.get(sid);
  if (!s) return false;
  if ((Date.now() - s.createdAt) > SESSION_TTL_MS) {
    sessions.delete(sid);
    return false;
  }
  return true;
}

// Login page (GET)
app.get('/login', (req, res) => {
  const err = String(req.query.err || '');
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Login</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:520px}
    .card{border:1px solid #ddd;border-radius:10px;padding:18px}
    input{padding:10px;font-size:16px;width:100%}
    button{padding:10px 14px;font-size:16px;cursor:pointer;margin-top:12px}
    .err{color:#b00020;margin-top:10px}
  </style>
</head>
<body>
  <h1>Enter passphrase</h1>
  <div class="card">
    <form method="post" action="/login">
      <input type="password" name="passphrase" placeholder="Passphrase" autofocus required />
      <button type="submit">Unlock</button>
      ${err ? `<div class="err">${err.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</div>` : ''}
    </form>
  </div>
</body>
</html>`);
});

// Login handler (POST)
app.use(express.urlencoded({ extended: false, limit: '4kb' }));

// Rate-limit login attempts (OWASP brute-force mitigation)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: 'Too many login attempts. Try again later.'
});

app.post('/login', loginLimiter, (req, res) => {
  if (!PASSPHRASE_SHA256 || !/^[0-9a-f]{64}$/.test(PASSPHRASE_SHA256)) {
    return res.status(500).type('html').send('<h1>Server misconfigured</h1>');
  }
  const passphrase = String(req.body?.passphrase || '');
  const digest = sha256Hex(passphrase);
  const ok = crypto.timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(PASSPHRASE_SHA256, 'hex'));

  if (!ok) {
    // Non-blocking delay to slow brute force without burning CPU.
    return setTimeout(() => {
      res.redirect('/login?err=Wrong%20passphrase');
    }, 450);
  }

  const sid = crypto.randomUUID();
  sessions.set(sid, { createdAt: Date.now() });
  setCookie(res, 'rng_sid', sid, { maxAgeMs: SESSION_TTL_MS });
  res.redirect('/');
});

app.get('/logout', (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.rng_sid) sessions.delete(cookies.rng_sid);
  clearCookie(res, 'rng_sid');
  res.redirect('/login');
});

function requireAuth(req, res, next) {
  if (isAuthed(req)) return next();
  // Allow health checks through.
  if (req.path === '/health') return next();
  // Allow login/logout.
  if (req.path === '/login' || req.path === '/logout') return next();
  return res.redirect('/login');
}

// Gate everything by default.
app.use(requireAuth);

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'rng-web' });
});

// Simple UI
app.get('/', (req, res) => {
  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>RNG</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:720px}
    label{display:block;margin:12px 0 6px}
    input{padding:10px;font-size:16px;width:220px}
    button{padding:10px 14px;font-size:16px;cursor:pointer}
    .row{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-end}
    .card{border:1px solid #ddd;border-radius:10px;padding:18px}
    code{background:#f6f6f6;padding:2px 6px;border-radius:6px}
    #out{font-size:28px;font-weight:700;margin-top:10px}
  </style>
</head>
<body>
  <h1>Random Number Generator</h1>
  <p><a href="/logout">Logout</a></p>
  <p>Backend uses <code>random.org</code> via their JSON-RPC API.</p>

  <div class="card">
    <div class="row">
      <div>
        <label for="min">Min (inclusive)</label>
        <input id="min" type="number" value="1" />
      </div>
      <div>
        <label for="max">Max (inclusive)</label>
        <input id="max" type="number" value="100" />
      </div>
      <div>
        <button id="go">Generate</button>
      </div>
    </div>
    <div id="out"></div>
    <div id="verify" style="margin-top:10px"></div>
    <div id="err" style="color:#b00020;margin-top:8px"></div>
  </div>

<script>
  const $ = (id) => document.getElementById(id);
  $('go').addEventListener('click', async () => {
    $('err').textContent = '';
    $('out').textContent = '';
    const min = Number($('min').value);
    const max = Number($('max').value);
    try {
      const r = await fetch('/api/rng?min=' + encodeURIComponent(min) + '&max=' + encodeURIComponent(max));
      const j = await r.json();
      if (!r.ok) throw new Error(j?.error || 'Request failed');
      $('out').textContent = String(j.value);
      if (j.verifyUrl) {
        $('verify').innerHTML = '<a href="' + j.verifyUrl + '">Verify on random.org</a>';
      } else {
        $('verify').textContent = '';
      }
    } catch (e) {
      $('err').textContent = e.message || String(e);
    }
  });
</script>
</body>
</html>`);
});

// In-memory store of signed results for verification links.
// Not durable; intended for short-lived “verify” UX.
const signedStore = new Map();
const SIGNED_TTL_MS = 6 * 60 * 60 * 1000; // 6h

function storeSignedResult(obj) {
  const id = crypto.randomUUID();
  signedStore.set(id, { ...obj, storedAt: Date.now() });
  return id;
}

function getSignedResult(id) {
  const v = signedStore.get(id);
  if (!v) return null;
  if (Date.now() - v.storedAt > SIGNED_TTL_MS) {
    signedStore.delete(id);
    return null;
  }
  return v;
}

app.get('/api/rng', async (req, res) => {
  const min = Number(req.query.min);
  const max = Number(req.query.max);

  if (!Number.isFinite(min) || !Number.isFinite(max)) {
    return res.status(400).json({ ok: false, error: 'min and max must be numbers' });
  }
  if (!Number.isInteger(min) || !Number.isInteger(max)) {
    return res.status(400).json({ ok: false, error: 'min and max must be integers' });
  }
  if (max < min) {
    return res.status(400).json({ ok: false, error: 'max must be >= min' });
  }

  try {
    const payload = {
      jsonrpc: '2.0',
      method: 'generateSignedIntegers',
      params: {
        apiKey: process.env.RANDOM_ORG_API_KEY,
        n: 1,
        min,
        max,
        replacement: true,
        base: 10
      },
      id: Date.now()
    };

    const r = await fetch('https://api.random.org/json-rpc/4/invoke', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const j = await r.json().catch(() => null);
    if (!r.ok) {
      return res.status(502).json({ ok: false, error: 'random.org request failed', status: r.status, detail: j });
    }

    if (!j || j.error) {
      return res.status(502).json({ ok: false, error: 'random.org error', detail: j && (j.error || j) });
    }

    const value = j?.result?.random?.data?.[0];
    const random = j?.result?.random;
    const signature = j?.result?.signature;

    if (!Number.isInteger(value) || !random || typeof signature !== 'string') {
      return res.status(502).json({ ok: false, error: 'random.org returned unexpected payload', detail: j });
    }

    const storeId = storeSignedResult({ random, signature });
    const verifyUrl = `/verify/${encodeURIComponent(storeId)}`;

    res.json({
      ok: true,
      value,
      min,
      max,
      source: 'random.org',
      completionTime: random?.completionTime,
      serialNumber: random?.serialNumber,
      verifyUrl
    });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'random.org call failed', message: String(e?.message || e) });
  }
});

// NOTE: We intentionally do NOT self-verify on behalf of users.
// Users can verify independently on random.org using the payload shown on /verify/:id.

app.get('/verify/:id', async (req, res) => {
  const id = String(req.params.id || '');
  const stored = getSignedResult(id);
  if (!stored) {
    return res.status(404).type('html').send('<h1>Expired</h1><p>This verification link is unknown or has expired.</p>');
  }

  const verifyPageUrl = `${req.protocol}://${req.get('host')}/verify/${encodeURIComponent(id)}`;
  const qr = await QRCode.toDataURL(verifyPageUrl, { margin: 1, width: 240 });

  // Keep the payload copy/paste friendly.
  const randomJson = JSON.stringify(stored.random, null, 2);
  const signature = String(stored.signature);

  res.type('html').send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Verify RNG (random.org)</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:40px;max-width:860px}
    .card{border:1px solid #ddd;border-radius:10px;padding:18px}
    .ok{color:#0b7a0b;font-weight:700}
    .bad{color:#b00020;font-weight:700}
    code{background:#f6f6f6;padding:2px 6px;border-radius:6px}
    textarea{width:100%;min-height:160px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;padding:10px;border-radius:8px;border:1px solid #ddd}
    .row{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start}
    .qr{border:1px solid #ddd;border-radius:10px;padding:10px;display:inline-block;background:#fff}
    button{padding:8px 12px;font-size:14px;cursor:pointer}
    a{word-break:break-word}
  </style>
</head>
<body>
  <h1>Verification</h1>

  <p>This page is a proof bundle: it contains the <code>random</code> object and <code>signature</code> you can verify directly on random.org.</p>

  <div class="card">
    <div style="font-weight:700">Verify on random.org</div>
    <ol style="margin:10px 0 0 18px">
      <li>Open: <a href="https://api.random.org/signatures/form" target="_blank" rel="noreferrer">https://api.random.org/signatures/form</a></li>
      <li>Paste <b>random (JSON)</b> and <b>signature</b> from below</li>
      <li>Submit — random.org should confirm the signature is valid</li>
    </ol>
  </div>

  <div class="card">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
      <div style="font-weight:700">random (JSON)</div>
      <button type="button" onclick="copyText('random')">Copy random</button>
    </div>
    <textarea id="random" readonly>${randomJson.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</textarea>
  </div>

  <div class="card" style="margin-top:14px">
    <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">
      <div style="font-weight:700">signature</div>
      <button type="button" onclick="copyText('signature')">Copy signature</button>
    </div>
    <textarea id="signature" readonly>${signature.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</textarea>
  </div>

  <div class="card" style="margin-top:14px">
    <div style="font-weight:700;margin-bottom:8px">QR code (proof link)</div>
    <div class="qr">
      <img alt="QR" src="${qr}" width="240" height="240" />
    </div>
    <div style="margin-top:8px;font-size:12px"><a href="${verifyPageUrl}">${verifyPageUrl}</a></div>
  </div>

  <p style="margin-top:18px"><a href="/">Back</a></p>

<script>
  async function copyText(id) {
    const el = document.getElementById(id);
    try {
      await navigator.clipboard.writeText(el.value);
    } catch {
      el.select();
      document.execCommand('copy');
      window.getSelection().removeAllRanges();
    }
  }

  // No self-verification here; this page only shows proof data for manual verification on random.org.
</script>
</body>
</html>`);
});

const port = Number(process.env.PORT || 8080);
app.listen(port, '0.0.0.0', () => {
  console.log(`rng-web listening on :${port}`);
});
