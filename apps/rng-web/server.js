import express from 'express';
import crypto from 'crypto';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

const BUILD_ID = String(Date.now());

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: []
      }
    }
  })
);

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: false, limit: '4kb' }));

// -------------------- auth (passphrase) --------------------
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
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Secure'
  ];
  if (maxAgeMs != null) parts.push(`Max-Age=${Math.floor(maxAgeMs / 1000)}`);
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearCookie(res, name) {
  res.setHeader('Set-Cookie', `${name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`);
}

function cleanupSessions() {
  const now = Date.now();
  for (const [k, v] of sessions.entries()) {
    if (!v || (now - v.createdAt) > SESSION_TTL_MS) sessions.delete(k);
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

function topbarHtml({ showLogout }) {
  return `
  <div class="topbar">
    <div class="topbarInner">
      <div class="brand">Random Number Generator</div>
      ${showLogout ? '<a class="logout" href="/logout">Logout</a>' : '<div style="width:80px"></div>'}
    </div>
  </div>`;
}

function pageHtml({ title, showLogout, body, scripts = [] }) {
  const scriptTags = scripts
    .map(s => `<script src="${s}?v=${BUILD_ID}" defer></script>`)
    .join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <link rel="stylesheet" href="/assets/site.css?v=${BUILD_ID}">
</head>
<body>
  ${topbarHtml({ showLogout })}
  <main>
    ${body}
  </main>
  ${scriptTags}
</body>
</html>`;
}

function requireAuth(req, res, next) {
  if (req.path === '/health') return next();
  if (req.path === '/login' || req.path === '/logout') return next();
  if (req.path.startsWith('/assets/')) return next();
  if (isAuthed(req)) return next();
  return res.redirect('/login');
}

app.use(requireAuth);

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false
});

app.get('/login', (req, res) => {
  const err = String(req.query.err || '');
  res.type('html').send(
    pageHtml({
      title: 'Login',
      showLogout: false,
      body: `
        <div class="pageCenter">
          <div class="h1">Enter passphrase</div>
          <div class="card">
            <form method="post" action="/login" class="formStack">
              <label for="pass">Passphrase</label>
              <input id="pass" type="password" name="passphrase" placeholder="Passphrase" autofocus required />
              <button type="submit">Unlock</button>
              ${err ? `<div class="err">${err.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</div>` : ''}
            </form>
          </div>
        </div>
      `
    })
  );
});

app.post('/login', loginLimiter, (req, res) => {
  if (!PASSPHRASE_SHA256 || !/^[0-9a-f]{64}$/.test(PASSPHRASE_SHA256)) {
    return res.status(500).type('html').send('Server misconfigured');
  }

  const passphrase = String(req.body?.passphrase || '');
  const digest = crypto.createHash('sha256').update(passphrase, 'utf8').digest('hex');
  const ok = crypto.timingSafeEqual(Buffer.from(digest, 'hex'), Buffer.from(PASSPHRASE_SHA256, 'hex'));

  if (!ok) {
    return setTimeout(() => res.redirect('/login?err=Wrong%20passphrase'), 350);
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

// -------------------- assets (no-store to avoid Safari caching issues) --------------------
function noStore(res) {
  res.setHeader('Cache-Control', 'no-store');
}

app.get('/assets/site.css', (req, res) => {
  noStore(res);
  res.type('text/css').send(`
:root{--pad:40px;--maxw:860px;--topbar-h:56px;--radius:18px;--shadow:0 16px 50px rgba(0,0,0,0.10)}
@media (max-width:420px){:root{--pad:20px;--topbar-h:52px}}
*{box-sizing:border-box}
body{margin:0;color:#111;font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background:
  radial-gradient(900px 280px at 20% 0%, rgba(106,90,205,0.12), transparent 60%),
  radial-gradient(900px 280px at 80% 20%, rgba(0,188,212,0.10), transparent 60%),
  #ffffff;
}
.topbar{position:fixed;top:0;left:0;right:0;height:var(--topbar-h);display:flex;align-items:center;z-index:1000;
  background:rgba(255,255,255,0.88);backdrop-filter:blur(10px);border-bottom:1px solid rgba(0,0,0,0.06);
}
.topbarInner{max-width:var(--maxw);width:100%;margin:0 auto;padding:0 var(--pad);display:flex;align-items:center;justify-content:space-between;gap:12px}
.brand{font-weight:700;letter-spacing:0.2px;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
@media (max-width:420px){.brand{font-size:15px}}
.logout{font-weight:800;text-decoration:none;color:#111;border:1px solid rgba(0,0,0,0.12);padding:8px 12px;border-radius:12px;background:#fff;white-space:nowrap;font-size:14px}
@media (max-width:420px){.logout{padding:7px 10px;font-size:13px}}
main{padding-top:calc(var(--topbar-h) + 18px);padding-left:var(--pad);padding-right:var(--pad);padding-bottom:40px}
.pageCenter{max-width:720px;margin:0 auto}

.container{max-width:720px;margin:0 auto}
.card{background:rgba(255,255,255,0.92);border:1px solid rgba(0,0,0,0.10);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px}
.h1{font-size:40px;line-height:1.05;margin:12px 0 14px;font-weight:800}
@media (max-width:420px){.h1{font-size:34px}}
.p{margin:8px 0;color:#333}
.small{color:#666;font-size:13px}
.err{color:#b00020;margin-top:10px}
.row{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-end}
label{display:block;margin:0 0 6px;font-weight:600}
.formStack{display:flex;flex-direction:column;gap:12px}

input[type=number],input[type=password]{padding:10px;font-size:16px;width:220px;max-width:100%;border:1px solid rgba(0,0,0,0.12);border-radius:12px;background:#fff}
button{padding:12px 16px;font-size:16px;cursor:pointer;border-radius:14px;border:1px solid rgba(0,0,0,0.10);background:#1565ff;color:#fff;font-weight:800;box-shadow:0 10px 24px rgba(21,101,255,0.18)}
button:disabled{opacity:0.55;cursor:not-allowed}
button.secondary{background:#fff;color:#1565ff;border-color:rgba(21,101,255,0.30);box-shadow:none}

.progressWrap{margin-top:14px}
.progressBar{height:10px;background:#eee;border-radius:999px;overflow:hidden}
.progressFill{height:100%;width:0%;background:linear-gradient(90deg,#6a5acd,#00bcd4);border-radius:999px}
.status{margin-top:8px;color:#666;font-size:13px;min-height:18px}
.centerWrap{max-width:760px;margin:0 auto;display:flex;align-items:center;justify-content:center;min-height:calc(100dvh - var(--topbar-h) - 18px - 40px)}
.resultCard{text-align:center;padding:26px}
.numBox{display:inline-flex;align-items:center;justify-content:center;min-width:160px;min-height:160px;padding:18px 26px;border-radius:22px;
  background:linear-gradient(135deg, rgba(106,90,205,0.18), rgba(0,188,212,0.16));border:1px solid rgba(0,0,0,0.06)}
.num{font-size:84px;font-weight:800;letter-spacing:1px;line-height:1}
.btnRow{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-top:16px}
.btn{display:inline-block;padding:12px 16px;border-radius:12px;text-decoration:none;font-weight:800;border:1px solid rgba(0,0,0,0.12)}
.btnPrimary{background:#1565ff;color:#fff;border-color:#1565ff;box-shadow:0 10px 24px rgba(21,101,255,0.18)}
.btnGhost{background:#fff;color:#1565ff;border-color:rgba(21,101,255,0.30)}
textarea{width:100%;min-height:160px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;font-size:12px;padding:10px;border-radius:12px;border:1px solid rgba(0,0,0,0.12);background:#fff}
.copyRow{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
.qr{border:1px solid rgba(0,0,0,0.12);border-radius:14px;padding:10px;display:inline-block;background:#fff}
canvas.confetti{position:fixed;inset:0;pointer-events:none;z-index:500}
`);
});

app.get('/assets/app.js', (req, res) => {
  noStore(res);
  res.type('application/javascript').send(`
  const $ = (id) => document.getElementById(id);
  function sleep(ms){ return new Promise(r => setTimeout(r, ms)); }

  async function runGenerate(){
    const btn = $('go');
    const bar = $('bar');
    const status = $('status');
    const wrap = $('progressWrap');
    const err = $('err');

    err.textContent = '';
    wrap.style.display = 'block';
    status.textContent = 'Generating…';
    bar.style.width = '0%';

    const min = Number($('min').value);
    const max = Number($('max').value);

    btn.disabled = true;

    const fetchPromise = fetch('/api/rng?min=' + encodeURIComponent(min) + '&max=' + encodeURIComponent(max))
      .then(async r => {
        const j = await r.json().catch(() => null);
        if (!r.ok) throw new Error(j?.error || 'Request failed');
        return j;
      });

    const start = performance.now();
    const duration = 3000;
    function tick(){
      const t = Math.min(1, (performance.now() - start) / duration);
      bar.style.width = Math.floor(t * 100) + '%';
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);

    try {
      const [j] = await Promise.all([fetchPromise, sleep(duration)]);
      status.textContent = 'Done';
      if (j.resultUrl) {
        window.location.href = j.resultUrl;
        return;
      }
      err.textContent = 'Missing resultUrl from server.';
    } catch (e) {
      err.textContent = e.message || String(e);
      status.textContent = '';
    } finally {
      btn.disabled = false;
      setTimeout(() => {
        wrap.style.display = 'none';
        bar.style.width = '0%';
      }, 800);
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    const btn = $('go');
    if (btn) btn.addEventListener('click', runGenerate);
  });
`);
});

app.get('/assets/verify.js', (req, res) => {
  noStore(res);
  res.type('application/javascript').send(`
  async function copyText(id) {
    const el = document.getElementById(id);
    if (!el) return;
    try {
      await navigator.clipboard.writeText(el.value);
    } catch {
      el.select();
      document.execCommand('copy');
      window.getSelection().removeAllRanges();
    }
  }
  window.copyText = copyText;
`);
});

app.get('/assets/result.js', (req, res) => {
  noStore(res);
  res.type('application/javascript').send(`
  (function(){
    function confettiBurst(){
      const canvas = document.createElement('canvas');
      canvas.className = 'confetti';
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      document.body.appendChild(canvas);
      const ctx = canvas.getContext('2d');
      const colors = ['#6a5acd','#00bcd4','#ff9800','#e91e63','#4caf50','#ffc107'];
      const parts = Array.from({length: 160}).map(() => ({
        x: canvas.width * 0.5,
        y: canvas.height * 0.25,
        vx: (Math.random() - 0.5) * 12,
        vy: Math.random() * -9 - 7,
        g: 0.28 + Math.random() * 0.14,
        size: 4 + Math.random() * 6,
        color: colors[(Math.random() * colors.length) | 0],
        rot: Math.random() * Math.PI,
        vr: (Math.random() - 0.5) * 0.35
      }));
      const start = performance.now();
      function frame(t){
        const dt = (t - start);
        ctx.clearRect(0,0,canvas.width,canvas.height);
        for (const p of parts) {
          p.vy += p.g;
          p.x += p.vx;
          p.y += p.vy;
          p.rot += p.vr;
          ctx.save();
          ctx.translate(p.x, p.y);
          ctx.rotate(p.rot);
          ctx.fillStyle = p.color;
          ctx.fillRect(-p.size/2, -p.size/2, p.size, p.size);
          ctx.restore();
        }
        if (dt < 1600) requestAnimationFrame(frame);
        else canvas.remove();
      }
      requestAnimationFrame(frame);
    }
    window.addEventListener('load', () => setTimeout(confettiBurst, 120));
  })();
`);
});

// -------------------- app routes --------------------
app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'rng-web' });
});

app.get('/', (req, res) => {
  res.type('html').send(
    pageHtml({
      title: 'RNG',
      showLogout: true,
      body: `
        <div class="pageCenter">
          <div class="h1">Random Number Generator</div>
          <div class="p">Backend uses <code>random.org</code> via their JSON-RPC API.</div>
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

            <div class="progressWrap" id="progressWrap" style="display:none">
              <div class="progressBar"><div class="progressFill" id="bar"></div></div>
              <div class="status" id="status"></div>
            </div>

            <div id="err" class="err"></div>
          </div>
        </div>
      `,
      scripts: ['/assets/app.js']
    })
  );
});

// -------------------- random.org signed RNG --------------------
const signedStore = new Map();
const SIGNED_TTL_MS = 6 * 60 * 60 * 1000;

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

  if (!Number.isInteger(min) || !Number.isInteger(max) || max < min) {
    return res.status(400).json({ ok: false, error: 'Invalid min/max' });
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
    if (!r.ok || !j || j.error) {
      return res.status(502).json({ ok: false, error: 'random.org error', detail: j });
    }

    const value = j?.result?.random?.data?.[0];
    const random = j?.result?.random;
    const signature = j?.result?.signature;
    if (!Number.isInteger(value) || !random || typeof signature !== 'string') {
      return res.status(502).json({ ok: false, error: 'Unexpected random.org payload' });
    }

    const storeId = storeSignedResult({ random, signature });

    res.json({
      ok: true,
      value,
      min,
      max,
      source: 'random.org',
      completionTime: random?.completionTime,
      serialNumber: random?.serialNumber,
      verifyUrl: `/verify/${encodeURIComponent(storeId)}`,
      resultUrl: `/result/${encodeURIComponent(storeId)}`
    });
  } catch (e) {
    res.status(502).json({ ok: false, error: 'random.org call failed', message: String(e?.message || e) });
  }
});

app.get('/result/:id', (req, res) => {
  const id = String(req.params.id || '');
  const stored = getSignedResult(id);
  if (!stored) {
    return res.status(404).type('html').send(pageHtml({ title:'Expired', showLogout:true, body:`<div class="container"><div class="h1">Expired</div><div class="p">This result link is unknown or has expired.</div></div>` }));
  }

  const value = stored?.random?.data?.[0];

  res.type('html').send(
    pageHtml({
      title: 'Result',
      showLogout: true,
      body: `
        <div class="centerWrap">
          <div class="wrap" style="width:100%;max-width:760px">
            <div class="card resultCard">
              <div style="font-weight:800;font-size:18px">Result</div>
              <div class="numBox" style="margin:18px auto 6px auto"><div class="num">${String(value).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</div></div>
              <div class="small">Generated by random.org (signed)</div>
              <div class="btnRow">
                <a class="btn btnPrimary" href="/verify/${encodeURIComponent(id)}">Verify</a>
                <a class="btn btnGhost" href="/">Generate another</a>
              </div>
            </div>
          </div>
        </div>
      `,
      scripts: ['/assets/result.js']
    })
  );
});

app.get('/verify/:id', async (req, res) => {
  const id = String(req.params.id || '');
  const stored = getSignedResult(id);
  if (!stored) {
    return res.status(404).type('html').send(pageHtml({ title:'Expired', showLogout:true, body:`<div class="container"><div class="h1">Expired</div><div class="p">This verification link is unknown or has expired.</div></div>` }));
  }

  const verifyPageUrl = `${req.protocol}://${req.get('host')}/verify/${encodeURIComponent(id)}`;
  // Simple QR via inline SVG (avoid dependencies)
  // (For now: show just the URL; QR optional to re-add later.)
  const randomJson = JSON.stringify(stored.random, null, 2);
  const signature = String(stored.signature);

  res.type('html').send(
    pageHtml({
      title: 'Verification',
      showLogout: true,
      body: `
        <div class="pageCenter">
          <div class="h1">Verification</div>
          <div class="card">
            <div style="font-weight:800">Verify on random.org</div>
            <ol style="margin:10px 0 0 18px">
              <li>Open: <a href="https://api.random.org/signatures/form" target="_blank" rel="noreferrer">https://api.random.org/signatures/form</a></li>
              <li>Paste <b>random (JSON)</b> and <b>signature</b> from below</li>
              <li>Submit — random.org should confirm the signature is valid</li>
            </ol>
          </div>

          <div class="card" style="margin-top:14px">
            <div class="copyRow">
              <div style="font-weight:700">random (JSON)</div>
              <button type="button" onclick="copyText('random')">Copy random</button>
            </div>
            <textarea id="random" readonly>${randomJson.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</textarea>
          </div>

          <div class="card" style="margin-top:14px">
            <div class="copyRow">
              <div style="font-weight:700">signature</div>
              <button type="button" onclick="copyText('signature')">Copy signature</button>
            </div>
            <textarea id="signature" readonly>${signature.replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;')}</textarea>
          </div>

          <div class="card" style="margin-top:14px">
            <div style="font-weight:700;margin-bottom:8px">Proof link</div>
            <div class="small"><a href="${verifyPageUrl}">${verifyPageUrl}</a></div>
          </div>
        </div>
      `,
      scripts: ['/assets/verify.js']
    })
  );
});

const port = Number(process.env.PORT || 8080);
app.listen(port, '0.0.0.0', () => {
  console.log(`rng-web listening on :${port}`);
});
